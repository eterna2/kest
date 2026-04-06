#!/bin/bash
set -e

# Configuration
SPIRE_SERVER_CONTAINER="kest-lab-spire-server-1"
TRUST_BUNDLE_PATH="spire/agent/trust-bundle.pem"
PUBLIC_DIR="spire/agent/public"

# Ensure directories exist
mkdir -p spire/agent
mkdir -p "$PUBLIC_DIR"

echo "Waiting for Spire Server to be ready..."
# Simple health check loop
FOR_COUNT=0
max_retries=30
until docker compose exec spire-server bin/spire-server bundle show > /dev/null 2>&1 || [ $FOR_COUNT -eq $max_retries ]; do
  sleep 1
  FOR_COUNT=$((FOR_COUNT + 1))
done

if [ $FOR_COUNT -eq $max_retries ]; then
  echo "Error: Spire Server failed to start."
  exit 1
fi

echo "--- 2. Bootstrapping SPIRE Agent ---"
# Export trust bundle
docker compose exec spire-server bin/spire-server bundle show -format pem > "$TRUST_BUNDLE_PATH"

# Generate Join Token
TOKEN=$(docker compose exec spire-server bin/spire-server token generate -spiffeID spiffe://kest.internal/agent/my-node | cut -d' ' -f2)
echo "Generated Join Token: $TOKEN"

echo "--- 3. Registering Workload Entries ---"
CURRENT_UID=$(id -u)
for hop in hop1 hop2 hop3 kest-agent; do
  docker compose exec spire-server bin/spire-server entry create \
    -parentID spiffe://kest.internal/agent/my-node \
    -spiffeID spiffe://kest.internal/workload/$hop \
    -selector unix:uid:0 || echo "Entry for $hop (root) already exists."
done

# Also register for the host user to allow test-live to pass
docker compose exec spire-server bin/spire-server entry create \
  -parentID spiffe://kest.internal/agent/my-node \
  -spiffeID spiffe://kest.internal/workload/host-test \
  -selector unix:uid:$CURRENT_UID || echo "Entry for host-test already exists."

echo "--- 4. Saving Join Token to .env ---"
echo "JOIN_TOKEN=$TOKEN" > .env

echo "--- 5. Waiting for Cedar Agent to be ready ---"
CEDAR_URL="http://localhost:8180"
FOR_COUNT=0
max_retries=30
until curl -sf "${CEDAR_URL}/v1/policies" > /dev/null 2>&1 || [ $FOR_COUNT -eq $max_retries ]; do
  sleep 1
  FOR_COUNT=$((FOR_COUNT + 1))
done
if [ $FOR_COUNT -eq $max_retries ]; then
  echo "Warning: Cedar Agent not reachable at ${CEDAR_URL}, skipping policy upload."
else
  echo "--- 5a. Uploading Cedar Policies ---"
  for policy_file in cedar/policies/*.cedar; do
    policy_id=$(basename "${policy_file}" .cedar)
    policy_content=$(cat "${policy_file}")
    http_status=$(curl -s -o /tmp/cedar_resp.txt -w "%{http_code}" \
      -X PUT "${CEDAR_URL}/v1/policies/${policy_id}" \
      -H "Content-Type: application/json" \
      -d "{\"content\": $(echo "$policy_content" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))')}")
    if [ "$http_status" -ge 200 ] && [ "$http_status" -lt 300 ]; then
      echo "  ✓ Uploaded policy: ${policy_id}"
    else
      echo "  ✗ Failed to upload ${policy_id} (HTTP ${http_status}): $(cat /tmp/cedar_resp.txt)"
    fi
  done
fi

echo "--- 6. Waiting for Keycloak to be ready ---"
KC_URL="http://localhost:8080/realms/kest-lab"
FOR_COUNT=0
max_retries=60
until curl -sf "${KC_URL}" > /dev/null 2>&1 || [ $FOR_COUNT -eq $max_retries ]; do
  sleep 2
  FOR_COUNT=$((FOR_COUNT + 1))
done
if [ $FOR_COUNT -eq $max_retries ]; then
  echo "Warning: Keycloak not ready at ${KC_URL} — OBO tests may fail."
else
  echo "  ✓ Keycloak realm kest-lab is ready."
  echo "--- 6a. Enabling Keycloak token-exchange feature ---"
  # Check if token-exchange feature is already enabled at realm level
  # (Keycloak 24 requires the realm config attribute to allow token exchange)
  ADMIN_TOKEN=$(curl -sf -X POST "http://localhost:8080/realms/master/protocol/openid-connect/token" \
    -d "grant_type=password&client_id=admin-cli&username=admin&password=admin" | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])' 2>/dev/null || echo "")
  if [ -n "$ADMIN_TOKEN" ]; then
    # Enable the standard token exchange capability on the realm
    curl -sf -X PUT "http://localhost:8080/admin/realms/kest-lab" \
      -H "Authorization: Bearer ${ADMIN_TOKEN}" \
      -H "Content-Type: application/json" \
      -d '{"attributes": {"token-exchange.standard-token-exchange.enabled": "true"}}' > /dev/null 2>&1 && echo "  ✓ Token exchange feature enabled on kest-lab realm." || echo "  ✗ Failed to enable token exchange (may already be enabled)."
    # Grant kest-agent permission to exchange tokens
    # This may require additional permission setup depending on Keycloak 24 config
    echo "  ℹ Token exchange permission is configured in realm-export.json (kest-agent client attributes)."
  else
    echo "  ✗ Could not obtain Keycloak admin token; token exchange will depend on default realm settings."
  fi
fi

echo "--- Bootstrap Complete ---"

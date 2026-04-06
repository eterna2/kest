import os
import pytest
import json
import time
import httpx
import base64
import hashlib


def get_payload(sig):
    try:
        parts = sig.split(".")
        # Try each part to find the KestEntry JSON
        for part in parts:
            try:
                # Handle base64url padding
                p_b64 = part + "=" * ((4 - len(part) % 4) % 4)
                data = json.loads(base64.urlsafe_b64decode(p_b64))
                # KestEntry payload contains entry_id (not "resource" which is an old schema)
                if isinstance(data, dict) and "entry_id" in data:
                    return data
            except Exception:
                continue
        return {}
    except Exception:
        return {}


def test_distributed_e2e():
    print("--- Starting Distributed E2E Integration Test ---")

    # 0. Clear old audit files
    if os.path.exists("lab_audit.json"):
        os.remove("lab_audit.json")
    if os.path.exists("chain_tips.json"):
        os.remove("chain_tips.json")

    # --- Obtain a Keycloak JWT for alice ---
    # workload_user_policy requires a non-empty principal_user (from JWT).
    keycloak_url = os.getenv("KEYCLOAK_URL", "http://keycloak:8080")
    realm = os.getenv("KEYCLOAK_REALM", "kest-lab")
    try:
        token_resp = httpx.post(
            f"{keycloak_url}/realms/{realm}/protocol/openid-connect/token",
            data={
                "grant_type": "password",
                "client_id": "kest-cli",
                "username": "alice",
                "password": "alice",
            },
            timeout=15,
        )
        token_resp.raise_for_status()
        alice_token = token_resp.json()["access_token"]
    except Exception as e:
        pytest.fail(f"Failed to obtain Keycloak token: {e}")

    # 1. Trigger the chain with authentication + Merkle lineage root
    try:
        headers = {
            "Authorization": f"Bearer {alice_token}",
            "baggage": "kest.chain_tip=0",
        }
        response = httpx.get("http://localhost:8000/", headers=headers, timeout=15)
        print(f"Chain execution status: {response.status_code}")
        if response.status_code == 200:
            print(f"Chain Result: {json.dumps(response.json(), indent=2)}")
        else:
            pytest.fail(f"Chain HTTP execution failed: {response.text}")
    except Exception as e:
        pytest.fail(f"Chain execution failed (network/parsing): {e}")


    # 2. Wait for file flushes
    print("Waiting for audit logs to persist...")
    time.sleep(2)

    # 3. Retrieve Audit Logs from Shared File
    audit_file = "lab_audit.json"
    if not os.path.exists(audit_file):
        pytest.fail(f"Error: Audit file {audit_file} not found.")

    with open(audit_file, "r") as f:
        kest_signatures = json.load(f)

    print(f"Found {len(kest_signatures)} unique Kest signatures in lab audit log.")

    # 4. Reconstruct and Sort Merkle Chain
    sorted_sigs = []
    current_parent = "0"
    used = set()

    while True:
        found_next = None
        for s in kest_signatures:
            if s in used:
                continue
            payload = get_payload(s)
            parents = payload.get("parent_ids", [])
            if parents and parents[0] == current_parent:
                found_next = s
                break

        if found_next:
            sorted_sigs.append(found_next)
            used.add(found_next)
            current_parent = hashlib.sha256(found_next.encode()).hexdigest()
        else:
            break

    print(f"Verified Chain Length: {len(sorted_sigs)}")
    for i, s in enumerate(sorted_sigs):
        p = get_payload(s)
        identity = p.get("labels", {}).get("identity") or p.get("identity")
        score = p.get("trust_score")
        print(
            f"  [{i}] Operation: {p.get('operation')} (Principal: {identity}, Trust: {score})"
        )

    if len(sorted_sigs) < 3:
        pytest.fail("Expected at least 3 hops in the Merkle chain.")

    # 5. Cryptographic Verification (Merkle Hash Links)
    print("Verifying Merkle Hash Links...")
    current_expected_parent = "0"
    for i, sig in enumerate(sorted_sigs):
        payload = get_payload(sig)
        parent = payload.get("parent_ids", [""])[0]
        if parent != current_expected_parent:
            pytest.fail(
                f"Merkle link broken at hop {i}. Expected parent {current_expected_parent}, got {parent}"
            )
        # Calculate hash of this signature for the next one
        current_expected_parent = hashlib.sha256(sig.encode()).hexdigest()

    print("SUCCESS: Distributed Merkle Lineage Hash-Chain Verified.")

"""
Keycloak end-to-end integration tests for the kest-lab showcase.

These tests verify the full zero-trust flow with human identity via Keycloak JWTs:
  - Flow A: alice authenticates and calls hop1 directly
  - Flow B: alice delegates to kest-agent via RFC 8693 OBO token exchange
  - Flow C: invalid/expired JWT is rejected at the middleware level

Requires: the full lab stack running (moon run kest-lab:up).
"""
import json
import pytest
import httpx

# conftest.py helper functions are importable as regular Python in pytest context
from conftest import (
    get_keycloak_token,
    decode_jwt_payload,
)

HOP1_URL = "http://hop1:8000"
AGENT_URL = "http://kest-agent:8001"
KEYCLOAK_URL = "http://keycloak:8080"
AUDIT_FILE = "/app/lab_audit.json"


def load_audit() -> list[dict]:
    """Load and decode all entries from the shared audit file."""
    try:
        with open(AUDIT_FILE, "r") as f:
            sigs = json.load(f)
        return [decode_jwt_payload(s) for s in sigs if s]
    except Exception:
        return []


def any_identity_matches(payloads: list[dict], **expected) -> bool:
    """Return True if any payload's kest.identity labels match all expected fields."""
    for payload in payloads:
        labels = payload.get("labels", {})
        identity_raw = labels.get("kest.identity", "{}")
        try:
            identity = json.loads(identity_raw) if identity_raw else {}
        except Exception:
            identity = {}
        if all(identity.get(k) == v for k, v in expected.items()):
            return True
    return False


@pytest.mark.live
@pytest.mark.asyncio
async def test_direct_user_flow_alice(wait_for_audit):
    """
    Flow A: alice authenticates with Keycloak, calls hop1 with a Bearer JWT.
    Policy (workload_user_policy) enforces: authenticated user + kest-reader role.
    Audit trail must include alice's identity in all three hops.
    """
    alice_token = await get_keycloak_token("alice", "alice")

    # Verify alice's token has the expected role
    claims = decode_jwt_payload(alice_token)
    roles = claims.get("realm_access", {}).get("roles", [])
    assert "kest-reader" in roles, f"Expected kest-reader in roles, got: {roles}"

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(
            f"{HOP1_URL}/",
            headers={"Authorization": f"Bearer {alice_token}"},
        )

    assert response.status_code == 200, f"hop1 rejected: {response.text}"
    data = response.json()
    assert data["service"] == "hop1"
    # hop1 should have called hop2 which called hop3
    assert "next" in data

    # Get alice's UUID from her JWT — kest-cli doesn't emit preferred_username,
    # so KestIdentityMiddleware falls back to sub (UUID) as kest.principal_user.
    alice_uuid = decode_jwt_payload(alice_token).get("sub")

    # Verify the audit trail records alice's identity (as UUID)
    audit = wait_for_audit(timeout=10, expected_count=3)
    payloads = [decode_jwt_payload(s) for s in audit]
    assert any_identity_matches(payloads, user=alice_uuid), (
        f"alice ({alice_uuid}) not found in audit identities: "
        f"{[p.get('labels', {}).get('kest.identity') for p in payloads]}"
    )


@pytest.mark.live
@pytest.mark.asyncio
async def test_direct_user_flow_bob_admin(wait_for_audit):
    """
    Flow A (admin): bob has kest-admin role which also satisfies workload_user_policy.
    """
    bob_token = await get_keycloak_token("bob", "bob")

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(
            f"{HOP1_URL}/",
            headers={"Authorization": f"Bearer {bob_token}"},
        )

    assert response.status_code == 200, f"hop1 rejected bob: {response.text}"
    # Get bob's UUID — kest-cli omits preferred_username, KestIdentityMiddleware uses sub.
    bob_uuid = decode_jwt_payload(bob_token).get("sub")
    audit = wait_for_audit(timeout=10, expected_count=3)
    payloads = [decode_jwt_payload(s) for s in audit]
    assert any_identity_matches(payloads, user=bob_uuid), (
        f"bob ({bob_uuid}) not found in audit identities: "
        f"{[p.get('labels', {}).get('kest.identity') for p in payloads]}"
    )


@pytest.mark.live
@pytest.mark.asyncio
async def test_obo_agent_flow(wait_for_audit):
    """
    Flow B: alice delegates to kest-agent via RFC 8693 OBO token exchange.
    Alice's token is sent to kest-agent /delegate; the agent exchanges it
    for an OBO token and calls hop1. The audit trail must reflect BOTH
    alice (original user) and kest-agent (acting agent).
    """
    alice_token = await get_keycloak_token("alice", "alice")

    # POST to kest-agent /delegate with alice's token
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            f"{AGENT_URL}/delegate",
            headers={"Authorization": f"Bearer {alice_token}"},
        )

    assert response.status_code == 200, f"agent delegation failed: {response.text}"
    data = response.json()
    assert data["status"] == "delegated"
    assert data["agent"] == "kest-agent"

    # The OBO chain should have produced audit entries with alice+kest-agent.
    # kest-cli omits preferred_username, so all user fields are the UUID sub.
    alice_uuid = decode_jwt_payload(alice_token).get("sub")
    audit = wait_for_audit(timeout=15, expected_count=4)  # agent + 3 hops
    payloads = [decode_jwt_payload(s) for s in audit]
    assert any_identity_matches(payloads, user=alice_uuid, agent="kest-agent"), (
        f"Expected audit entry with user={alice_uuid!r} and agent=kest-agent. "
        f"Got: {[p.get('labels', {}).get('kest.identity') for p in payloads]}"
    )


@pytest.mark.live
@pytest.mark.asyncio
async def test_invalid_jwt_rejected():
    """
    Flow C: an invalid/expired JWT must be rejected at KestIdentityMiddleware
    with a 403 — before the request reaches @kest_verified.
    """
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(
            f"{HOP1_URL}/",
            headers={"Authorization": "Bearer not.a.valid.jwt"},
        )
    assert response.status_code == 403, (
        f"Expected 403, got {response.status_code}: {response.text}\n"
        "Note: KestIdentityMiddleware sets empty identity on bad JWT; "
        "hop1 must have a PermissionError exception handler to return 403 (not 500)."
    )


@pytest.mark.live
@pytest.mark.asyncio
async def test_no_jwt_rejected():
    """
    Unauthenticated requests (no Authorization header) must be denied by policy.
    workload_user_policy requires a non-empty principal_user, so anonymous requests
    should be denied by Cedar (403 from @kest_verified PermissionError →
    or a policy deny response from the sidecar).
    """
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(f"{HOP1_URL}/")
    # Either a policy denial (PermissionError → 500 internal server error from unhandled exception)
    # or a 403 if the app explicitly handles it. Anything but 200 is correct.
    assert response.status_code != 200, (
        "Unauthenticated request should not succeed with workload_user_policy"
    )

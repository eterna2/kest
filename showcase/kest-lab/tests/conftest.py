import os
import json
import base64
import pytest
import httpx
import time


@pytest.fixture(autouse=True)
def auto_clean():
    """Ensure audit artifacts are wiped before each test."""
    files_to_clean = ["lab_audit.json", "chain_tips.json"]
    for f in files_to_clean:
        if os.path.exists(f):
            os.remove(f)
    yield


@pytest.fixture
async def lab_client():
    """Returns an async HTTP client configured to hit hop1 natively."""
    async with httpx.AsyncClient(base_url="http://localhost:8000") as client:
        yield client


@pytest.fixture
def wait_for_audit():
    """Utility to poll lab_audit.json until it has at least 'expected_count' signatures."""

    def _wait(timeout: int = 5, expected_count: int = 1):
        start = time.time()
        while time.time() - start < timeout:
            if os.path.exists("lab_audit.json"):
                try:
                    with open("lab_audit.json", "r") as f:
                        content = f.read()
                        if content.strip():
                            data = json.loads(content)
                            if len(data) >= expected_count:
                                return data
                except json.JSONDecodeError:
                    pass
            time.sleep(0.5)
        return []

    return _wait


# ---------------------------------------------------------------------------
# Keycloak helpers
# ---------------------------------------------------------------------------

KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://keycloak:8080")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "kest-lab")
_TOKEN_URL = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"


async def get_keycloak_token(
    username: str,
    password: str,
    client_id: str = "kest-cli",
    scope: str = "openid profile roles email",
) -> str:
    """
    Obtain a Keycloak access token via Resource Owner Password Credentials grant.
    Only suitable for test automation — never use ROPC in production.

    Args:
        scope: OAuth2 scope string. Include optional scopes (e.g. "read:data write:data")
               to request delegatable data scopes for gateway flow tests.
    """
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(
            _TOKEN_URL,
            data={
                "grant_type": "password",
                "client_id": client_id,
                "username": username,
                "password": password,
                "scope": scope,
            },
        )
        resp.raise_for_status()
        return resp.json()["access_token"]


async def exchange_token_obo(
    subject_token: str,
    client_id: str = "kest-agent",
    client_secret: str = "kest-agent-secret",
) -> str:
    """
    Perform RFC 8693 token exchange: swap `subject_token` for an OBO token
    where `client_id` acts on behalf of the original user.

    The resulting token has:
      sub     = client_id  (the agent)
      act.sub = original `sub` from subject_token  (the delegating user)
    """
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(
            _TOKEN_URL,
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token": subject_token,
                "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "client_id": client_id,
                "client_secret": client_secret,
            },
        )
        resp.raise_for_status()
        return resp.json()["access_token"]


def decode_jwt_payload(token: str) -> dict:
    """Decode JWT payload without verification (for test assertions only)."""
    try:
        parts = token.split(".")
        if len(parts) >= 2:
            payload_b64 = parts[1]
            payload_b64 += "=" * ((4 - len(payload_b64) % 4) % 4)
            return json.loads(base64.urlsafe_b64decode(payload_b64))
    except Exception:
        pass
    return {}

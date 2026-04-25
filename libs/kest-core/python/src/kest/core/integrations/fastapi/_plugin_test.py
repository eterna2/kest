"""
Tests for kest.core.integrations.fastapi — RED phase (TDD).

Tests are written against the public API *before* the implementation exists.
Run with: moon run kest-core-python:test

All tests use httpx.AsyncClient with ASGITransport — no live server.
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from kest.core import HandleVault, VaultCodec, ZlibCompressor
from kest.core.integrations.fastapi import (
    HandleResponse,
    HeaderPrincipalExtractor,
    JWTPrincipalExtractor,
    PrincipalExtractor,
    VaultDependency,
    VaultRouter,
    vault_seal_response,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

GATEWAY_PRINCIPAL = "spiffe://test.local/services/gateway"
AGENT_PRINCIPAL = "spiffe://test.local/services/agent"
OWNER_PRINCIPAL = "spiffe://test.local/services/owner"

JWT_SECRET = "test-secret-1234"
JWT_ALGORITHM = "HS256"

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def vault() -> HandleVault:
    return HandleVault(codec=VaultCodec(compressor=ZlibCompressor()))


@pytest.fixture()
def jwt_extractor() -> JWTPrincipalExtractor:
    return JWTPrincipalExtractor(secret=JWT_SECRET, algorithm=JWT_ALGORITHM)


def _make_jwt(principal: str) -> str:
    """Helper: issue a minimal HS256 JWT with a 'principal' claim."""
    from datetime import UTC, datetime, timedelta

    from jose import jwt

    now = datetime.now(UTC)
    payload = {
        "sub": "test",
        "principal": principal,
        "iat": now,
        "exp": now + timedelta(minutes=10),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


@pytest.fixture()
def gateway_token() -> str:
    return _make_jwt(GATEWAY_PRINCIPAL)


@pytest.fixture()
def agent_token() -> str:
    return _make_jwt(AGENT_PRINCIPAL)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_app(vault: HandleVault, extractor: PrincipalExtractor) -> object:
    """Build a minimal FastAPI app with VaultRouter mounted at /vault."""
    from fastapi import FastAPI

    app = FastAPI()
    router = VaultRouter(
        vault=vault,
        extractor=extractor,
        gateway_principals=[GATEWAY_PRINCIPAL],
    )
    app.include_router(router, prefix="/vault")
    return app


def _seal_patient(vault: HandleVault) -> str:
    """Seal a test payload and return the handle_id."""
    handle = vault.seal(
        data={"name": "Alice", "ssn": "123-45-6789"},
        owner_principal=OWNER_PRINCIPAL,
        safe_view="Patient record: Diagnosis: Diabetes.",
        granted_principals=[GATEWAY_PRINCIPAL],
    )
    return handle.id


# ---------------------------------------------------------------------------
# Tests: PrincipalExtractor Protocol
# ---------------------------------------------------------------------------


def test_jwt_extractor_is_protocol_compliant() -> None:
    """JWTPrincipalExtractor must satisfy PrincipalExtractor protocol."""
    extractor = JWTPrincipalExtractor(secret=JWT_SECRET)
    assert isinstance(extractor, PrincipalExtractor)


def test_header_extractor_is_protocol_compliant() -> None:
    """HeaderPrincipalExtractor must satisfy PrincipalExtractor protocol."""
    extractor = HeaderPrincipalExtractor(header_name="X-Principal")
    assert isinstance(extractor, PrincipalExtractor)


# ---------------------------------------------------------------------------
# Tests: HandleResponse + vault_seal_response helper
# ---------------------------------------------------------------------------


def test_vault_seal_response_returns_handle_response(vault: HandleVault) -> None:
    resp: HandleResponse = vault_seal_response(
        vault=vault,
        data={"secret": "value"},
        safe_view="A safe description.",
        owner_principal=OWNER_PRINCIPAL,
        granted_principals=[GATEWAY_PRINCIPAL],
    )
    assert resp["handle_id"].startswith("hdl_")
    assert resp["safe_view"] == "A safe description."


# ---------------------------------------------------------------------------
# Tests: VaultRouter — /safe-view endpoint (no auth)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_safe_view_no_auth(
    vault: HandleVault, jwt_extractor: JWTPrincipalExtractor
) -> None:
    """/safe-view/{handle_id} must return 200 with no Authorization header."""
    app = _build_app(vault, jwt_extractor)
    handle_id = _seal_patient(vault)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get(f"/vault/safe-view/{handle_id}")

    assert resp.status_code == 200
    body = resp.json()
    assert body["handle_id"] == handle_id
    assert "Diabetes" in body["safe_view"]


@pytest.mark.asyncio
async def test_safe_view_unknown_handle_is_404(
    vault: HandleVault, jwt_extractor: JWTPrincipalExtractor
) -> None:
    """/safe-view/{handle_id} for an unknown handle returns 404."""
    app = _build_app(vault, jwt_extractor)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get("/vault/safe-view/hdl_doesnotexist")

    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Tests: VaultRouter — /resolve endpoint (gateway only)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_resolve_gateway_principal_succeeds(
    vault: HandleVault, jwt_extractor: JWTPrincipalExtractor, gateway_token: str
) -> None:
    """/resolve with gateway JWT returns 200 with raw data."""
    app = _build_app(vault, jwt_extractor)
    handle_id = _seal_patient(vault)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get(
            f"/vault/resolve/{handle_id}",
            headers={"Authorization": f"Bearer {gateway_token}"},
        )

    assert resp.status_code == 200
    body = resp.json()
    assert body["handle_id"] == handle_id
    # raw data should contain PII
    assert "Alice" in str(body["data"])
    assert body["resolved_by"] == GATEWAY_PRINCIPAL


@pytest.mark.asyncio
async def test_resolve_agent_principal_denied(
    vault: HandleVault, jwt_extractor: JWTPrincipalExtractor, agent_token: str
) -> None:
    """/resolve with non-gateway JWT returns 403."""
    app = _build_app(vault, jwt_extractor)
    handle_id = _seal_patient(vault)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get(
            f"/vault/resolve/{handle_id}",
            headers={"Authorization": f"Bearer {agent_token}"},
        )

    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_resolve_no_auth_is_401(
    vault: HandleVault, jwt_extractor: JWTPrincipalExtractor
) -> None:
    """/resolve with no auth header returns 401."""
    app = _build_app(vault, jwt_extractor)
    handle_id = _seal_patient(vault)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get(f"/vault/resolve/{handle_id}")

    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_resolve_bad_token_is_401(
    vault: HandleVault, jwt_extractor: JWTPrincipalExtractor
) -> None:
    """/resolve with a malformed JWT returns 401."""
    app = _build_app(vault, jwt_extractor)
    handle_id = _seal_patient(vault)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get(
            f"/vault/resolve/{handle_id}",
            headers={"Authorization": "Bearer not-a-valid-jwt"},
        )

    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_resolve_unknown_handle_is_404(
    vault: HandleVault, jwt_extractor: JWTPrincipalExtractor, gateway_token: str
) -> None:
    """/resolve for an unknown handle_id returns 404."""
    app = _build_app(vault, jwt_extractor)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get(
            "/vault/resolve/hdl_doesnotexist",
            headers={"Authorization": f"Bearer {gateway_token}"},
        )

    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Tests: VaultDependency — use in a custom route
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_vault_dependency_in_custom_route(
    vault: HandleVault, jwt_extractor: JWTPrincipalExtractor, gateway_token: str
) -> None:
    """VaultDependency can be used as a Depends() in user-defined routes."""
    from fastapi import Depends, FastAPI

    handle_id = _seal_patient(vault)
    get_unsealed = VaultDependency(vault=vault, extractor=jwt_extractor)

    app = FastAPI()

    @app.get("/custom/{handle_id}")
    async def custom_route(data=Depends(get_unsealed)):  # noqa: ANN001
        return {"payload": str(data)}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get(
            f"/custom/{handle_id}",
            headers={"Authorization": f"Bearer {gateway_token}"},
        )

    assert resp.status_code == 200
    assert "Alice" in resp.json()["payload"]


# ---------------------------------------------------------------------------
# Tests: HeaderPrincipalExtractor
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_header_extractor_resolves(vault: HandleVault) -> None:
    """HeaderPrincipalExtractor reads principal from a custom header."""
    extractor = HeaderPrincipalExtractor(header_name="X-Principal")
    app = _build_app(vault, extractor)
    handle_id = _seal_patient(vault)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get(
            f"/vault/resolve/{handle_id}",
            headers={"X-Principal": GATEWAY_PRINCIPAL},
        )

    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_header_extractor_missing_header_is_401(vault: HandleVault) -> None:
    """HeaderPrincipalExtractor with missing header returns 401."""
    extractor = HeaderPrincipalExtractor(header_name="X-Principal")
    app = _build_app(vault, extractor)
    handle_id = _seal_patient(vault)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get(f"/vault/resolve/{handle_id}")

    assert resp.status_code == 401

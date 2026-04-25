"""
gateway_api.py — FastAPI HTTP Gateway with Kest HandleVault Integration

This module shows how to integrate Kest's HandleVault into a real
FastAPI-based API gateway.  It is the "real-world" layer that external
HTTP clients (e.g. a clinical dashboard or a BI tool) would call.

Architecture
============

    External client (HTTP)
        │
        ▼
    ┌─────────────────────────────────────────────────────────┐
    │  FastAPI Gateway  (gateway_api.py)                      │
    │                                                         │
    │  • JWT authentication (Bearer token)                    │
    │  • JWT claim  → SPIFFE-style principal                  │
    │  • /safe-view/{handle_id}   — public, no auth          │
    │  • /resolve/{handle_id}     — privileged, gateway-only │
    │  • /patient/{id}            — agent summary endpoint   │
    │  • /patient/{id}/rx         — prescription summary     │
    │                                                         │
    │  HandleVault sealed INSIDE the MCP server sub-process  │
    └────────────────┬────────────────────────────────────────┘
                     │  MCP stdio (subprocess)
                     ▼
    ┌────────────────────────────────────┐
    │  server_patient_records.py (MCP)  │
    │  HandleVault (AES-256-GCM)        │
    └────────────────────────────────────┘

Running
=======

    # Install deps (already in pyproject.toml):
    uv sync

    # Start the gateway:
    uv run python gateway_api.py

    # The Swagger UI is available at:
    #   http://localhost:8765/docs

    # Example requests (see README for full curl examples):
    #
    # 1. Get a patient summary (returns handle + safe_view):
    #    curl -H "Authorization: Bearer <gateway_token>" \\
    #         http://localhost:8765/patient/P-001
    #
    # 2. Resolve a handle (gateway-tier only):
    #    curl -H "Authorization: Bearer <gateway_token>" \\
    #         http://localhost:8765/resolve/<handle_id>
    #
    # 3. Read the safe_view with NO auth:
    #    curl http://localhost:8765/safe-view/<handle_id>

Demo tokens
===========

For the showcase we issue two hard-coded HS256 JWTs.
In production, replace with your identity provider (SPIRE, Auth0, Okta, …).

    GATEWAY_TOKEN — maps to spiffe://hospital.internal/services/gateway
    AGENT_TOKEN   — maps to spiffe://hospital.internal/services/agent

Run this file once with --print-tokens to see them:

    uv run python gateway_api.py --print-tokens
"""

from __future__ import annotations

import contextlib
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Path as FPath, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from rich.console import Console

# ---------------------------------------------------------------------------
# Config — in production, load from env / secrets manager
# ---------------------------------------------------------------------------

JWT_SECRET = "kest-showcase-secret-DO-NOT-USE-IN-PRODUCTION"
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = 60

# Map JWT "sub" claim → SPIFFE-style principal identity
_PRINCIPAL_MAP: dict[str, str] = {
    "gateway": "spiffe://hospital.internal/services/gateway",
    "agent": "spiffe://hospital.internal/services/agent",
    "admin": "spiffe://hospital.internal/services/admin",
}

GATEWAY_PRINCIPAL = "spiffe://hospital.internal/services/gateway"

# ---------------------------------------------------------------------------
# MCP server connection params
# ---------------------------------------------------------------------------

_HERE = Path(__file__).parent
_PYTHON = sys.executable

PATIENT_RECORDS_PARAMS = StdioServerParameters(
    command=_PYTHON,
    args=[str(_HERE / "server_patient_records.py")],
)

# ---------------------------------------------------------------------------
# Token helpers
# ---------------------------------------------------------------------------


def _make_token(sub: str, role: str) -> str:
    now = datetime.now(UTC)
    payload = {
        "sub": sub,
        "role": role,
        "principal": _PRINCIPAL_MAP.get(sub, f"spiffe://unknown/{sub}"),
        "iat": now,
        "exp": now + timedelta(minutes=JWT_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def _decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired token: {exc}",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


# ---------------------------------------------------------------------------
# FastAPI app + lifespan (MCP session management)
# ---------------------------------------------------------------------------

_mcp_session: ClientSession | None = None
_mcp_context: Any = None

console = Console()


@contextlib.asynccontextmanager
async def _lifespan(app: FastAPI):
    """Open a single long-lived MCP stdio connection for the gateway's lifetime."""
    global _mcp_session, _mcp_context  # noqa: PLW0603

    console.print("[cyan]Gateway starting — connecting to patient-records MCP server…")
    async with stdio_client(PATIENT_RECORDS_PARAMS) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            _mcp_session = session
            console.print("[green]✓ MCP session established.")
            console.print("[green]✓ FastAPI gateway ready at http://localhost:8765")
            console.print("[dim]  Swagger UI: http://localhost:8765/docs")
            yield
            console.print("[yellow]Gateway shutting down.")

    _mcp_session = None


app = FastAPI(
    title="Kest Vault Gateway",
    description=(
        "FastAPI API gateway that integrates with Kest's HandleVault. "
        "Sensitive PII is sealed inside the MCP server's vault — "
        "only the privileged gateway token can resolve opaque handles."
    ),
    version="0.1.0",
    lifespan=_lifespan,
)


# ---------------------------------------------------------------------------
# Auth dependencies
# ---------------------------------------------------------------------------

_bearer_scheme = HTTPBearer(auto_error=True)


async def _get_principal(
    credentials: Annotated[HTTPAuthorizationCredentials, Security(_bearer_scheme)],
) -> str:
    """Decode the JWT and return the caller's SPIFFE-style principal string."""
    payload = _decode_token(credentials.credentials)
    principal = payload.get("principal", "")
    if not principal:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token missing 'principal' claim.",
        )
    return principal


async def _require_gateway(principal: Annotated[str, Depends(_get_principal)]) -> str:
    """Dependency that enforces gateway-only access."""
    if principal != GATEWAY_PRINCIPAL:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Access denied. Endpoint requires principal "
                f"'{GATEWAY_PRINCIPAL}', got '{principal}'."
            ),
        )
    return principal


# ---------------------------------------------------------------------------
# MCP call helper
# ---------------------------------------------------------------------------


async def _mcp_call(tool: str, **kwargs: Any) -> str:
    if _mcp_session is None:
        raise HTTPException(status_code=503, detail="MCP session not available.")
    result = await _mcp_session.call_tool(tool, arguments=kwargs)
    return "\n".join(c.text for c in result.content if hasattr(c, "text"))


def _parse_field(text: str, field: str) -> str:
    for line in text.splitlines():
        if line.startswith(f"{field}:"):
            return line[len(field) + 1 :].strip()
    return ""


# ---------------------------------------------------------------------------
# Response models (plain dicts — keep the showcase dependency-light)
# ---------------------------------------------------------------------------

# GET /patient/{patient_id}
# Returns: { patient_id, handle_id, safe_view }
#
# GET /patient/{patient_id}/rx
# Returns: [ { handle_id, safe_view }, ... ]
#
# GET /safe-view/{handle_id}
# Returns: { handle_id, safe_view }
#
# GET /resolve/{handle_id}
# Returns: { handle_id, data: <raw dict> }   [gateway-only]
#
# GET /tokens
# Returns: { gateway_token, agent_token }    [demo only]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.get(
    "/tokens",
    summary="[Demo] Get example JWT tokens",
    description=(
        "Returns two hard-coded demo tokens for testing the API. "
        "**Do not use this endpoint in production.**"
    ),
    tags=["Demo"],
)
async def get_demo_tokens() -> dict:
    return {
        "gateway_token": _make_token("gateway", "gateway"),
        "agent_token": _make_token("agent", "agent"),
        "note": "Paste a token into the Authorize button above to use protected endpoints.",
    }


@app.get(
    "/patient/{patient_id}",
    summary="Get patient summary (agent-tier)",
    description=(
        "Returns an opaque handle ID and a non-sensitive safe_view for the patient record. "
        "Raw PII is sealed in the vault — this endpoint is safe to expose to agents and "
        "downstream services."
    ),
    tags=["Patient Records"],
)
async def get_patient(
    patient_id: Annotated[str, FPath(description="Patient ID, e.g. P-001")],
    principal: Annotated[str, Depends(_get_principal)],
) -> dict:
    raw = await _mcp_call("lookup_patient", patient_id=patient_id)
    if raw.startswith("ERROR"):
        raise HTTPException(status_code=404, detail=raw)
    return {
        "patient_id": patient_id,
        "handle_id": _parse_field(raw, "handle_id"),
        "safe_view": _parse_field(raw, "safe_view"),
        "requesting_principal": principal,
        "_note": "PII sealed in vault — handle_id is an opaque pointer only.",
    }


@app.get(
    "/patient/{patient_id}/rx",
    summary="List prescriptions (agent-tier)",
    description=(
        "Returns opaque handles + safe_views for each active prescription. "
        "Drug, dose, prescriber details are sealed; safe_views are safe for LLM context."
    ),
    tags=["Patient Records"],
)
async def list_prescriptions(
    patient_id: Annotated[str, FPath(description="Patient ID, e.g. P-001")],
    principal: Annotated[str, Depends(_get_principal)],
) -> dict:
    raw = await _mcp_call("list_patient_prescriptions", patient_id=patient_id)
    if raw.startswith("ERROR") or raw.startswith("No prescription"):
        raise HTTPException(status_code=404, detail=raw)

    blocks = [b.strip() for b in raw.split("---") if b.strip()]
    prescriptions = [
        {
            "handle_id": _parse_field(block, "handle_id"),
            "safe_view": _parse_field(block, "safe_view"),
        }
        for block in blocks
    ]
    return {
        "patient_id": patient_id,
        "prescription_count": len(prescriptions),
        "prescriptions": prescriptions,
        "requesting_principal": principal,
    }


@app.get(
    "/safe-view/{handle_id}",
    summary="Read safe_view (public, no auth)",
    description=(
        "Returns the non-sensitive safe_view string for any handle. "
        "No authentication required — safe_views are intentionally non-sensitive "
        "and safe to cache, log, and share."
    ),
    tags=["Vault"],
)
async def get_safe_view(
    handle_id: Annotated[str, FPath(description="Opaque handle ID (hdl_...)")],
) -> dict:
    raw = await _mcp_call("get_safe_view", handle_id=handle_id)
    if raw.startswith("ERROR"):
        raise HTTPException(status_code=404, detail=raw)
    return {"handle_id": handle_id, "safe_view": raw}


@app.get(
    "/resolve/{handle_id}",
    summary="Resolve handle → raw PII (GATEWAY ONLY)",
    description=(
        "**Privileged endpoint.** Unseals the vault handle and returns the raw data "
        "(including PII). Only accessible with a JWT whose principal maps to "
        "`spiffe://hospital.internal/services/gateway`.\n\n"
        "Any other principal receives HTTP 403. This mirrors the vault's "
        "`HandleAccessDeniedError` at the HTTP layer."
    ),
    tags=["Vault"],
)
async def resolve_handle(
    handle_id: Annotated[str, FPath(description="Opaque handle ID (hdl_...)")],
    principal: Annotated[str, Depends(_require_gateway)],  # enforces gateway-only
) -> dict:
    raw = await _mcp_call(
        "resolve_handle",
        handle_id=handle_id,
        requesting_principal=principal,
    )
    if raw.startswith("ERROR (access denied)"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=raw)
    if raw.startswith("ERROR (not found)") or raw.startswith("ERROR (expired)"):
        raise HTTPException(status_code=404, detail=raw)
    if raw.startswith("ERROR"):
        raise HTTPException(status_code=500, detail=raw)
    return {
        "handle_id": handle_id,
        "data": raw,
        "resolved_by": principal,
        "audit": "This resolution has been logged.",
    }


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------


@app.get("/health", tags=["Meta"])
async def health() -> dict:
    return {"status": "ok", "mcp_connected": _mcp_session is not None}


# ---------------------------------------------------------------------------
# CLI entrypoints
# ---------------------------------------------------------------------------


def _print_tokens() -> None:
    gateway_tok = _make_token("gateway", "gateway")
    agent_tok = _make_token("agent", "agent")
    console = Console()
    console.print("\n[bold cyan]Demo JWT tokens for Kest Vault Gateway showcase[/bold cyan]\n")
    console.print(f"[bold]GATEWAY_TOKEN[/bold] (can resolve handles):\n  {gateway_tok}\n")
    console.print(f"[bold]AGENT_TOKEN[/bold]   (agent-tier only, cannot resolve):\n  {agent_tok}\n")
    console.print(
        "[dim]Use these with:\n"
        "  curl -H 'Authorization: Bearer <token>' http://localhost:8765/patient/P-001\n"
        "  curl -H 'Authorization: Bearer <gateway_token>' http://localhost:8765/resolve/<hdl>\n"
    )


if __name__ == "__main__":
    if "--print-tokens" in sys.argv:
        _print_tokens()
        sys.exit(0)

    uvicorn.run(
        "gateway_api:app",
        host="0.0.0.0",
        port=8765,
        reload=False,
        log_level="info",
    )

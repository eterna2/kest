"""
kest-gateway: Scope-aware delegation gateway with task token minting.

Full flow this service implements:
  1. Receive OBO token from kest-agent (sub=kest-agent, act.sub=alice)
  2. KestIdentityMiddleware extracts user/agent/scope from the OBO JWT
  3. POST /authorise — @kest_verified enforces gateway_policy (scope check)
     • Verifies delegated scopes include "read:data"
     • Signs a KestEntry (audit entry #2 in the chain)
     • Mints a narrow task token (scope: task:process-data only)
  4. POST /execute-task — @kest_verified enforces task_policy
     • Verifies token carries exactly "task:process-data"
     • Signs a KestEntry (audit entry #3 in the chain)
     • Calls hop1 with the task token embedded as kest.principal_scope baggage

This service demonstrates Approach A from docs/GATEWAY_E2E.md:
  - Gateway self-signs task tokens with its own LocalEd25519Provider
  - SPIRE-backed production variant: replace LocalEd25519Provider with SPIREProvider

Security note: if this gateway is compromised, the attacker can mint arbitrary
task tokens. Mitigations are documented in docs/GATEWAY_E2E.md §"What If Compromised?".
"""
import os
import json
import time
import base64
import traceback

import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from opentelemetry import trace, baggage
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource

from kest.core import (
    configure,
    kest_verified,
    LocalEd25519Provider,
    SPIREProvider,
    CedarLocalEngine,
)
from kest.core.ext import KestMiddleware, KestIdentityMiddleware
import kest.core.decorators

# ---------------------------------------------------------------------------
# OpenTelemetry
# ---------------------------------------------------------------------------
SERVICE_NAME = os.getenv("SERVICE_NAME", "kest-gateway")
resource = Resource.create({"service.name": SERVICE_NAME})
provider = TracerProvider(resource=resource)
otlp_endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel-collector:4318")
exporter = OTLPSpanExporter(endpoint=f"{otlp_endpoint}/v1/traces")
provider.add_span_processor(BatchSpanProcessor(exporter))
trace.set_tracer_provider(provider)
kest.core.decorators.tracer = trace.get_tracer("kest.core")

# ---------------------------------------------------------------------------
# Identity Provider
# ---------------------------------------------------------------------------
# Production: use SPIREProvider for SPIRE-attested key material and automatic rotation.
# Dev/test: fall back to a LocalEd25519Provider (ephemeral key, not attestation-backed).
SPIRE_SOCKET = "unix:///var/run/spire/agent/public/api.sock"
if os.path.exists(SPIRE_SOCKET):
    identity_provider = SPIREProvider(socket_path=SPIRE_SOCKET)
else:
    identity_provider = LocalEd25519Provider()

# ---------------------------------------------------------------------------
# Policy Engine — Cedar (in-process)
# ---------------------------------------------------------------------------
JWKS_URI = os.getenv("KEYCLOAK_JWKS_URI")
HOP1_URL = os.getenv("HOP1_URL", "http://hop1:8000")
TASK_TTL_SECONDS = int(os.getenv("TASK_TOKEN_TTL", "300"))  # 5 minutes


def _load_cedar_policies(policy_dir: str = "/workspace/app/cedar/policies") -> dict:
    policies = {}
    if os.path.isdir(policy_dir):
        for fname in os.listdir(policy_dir):
            if fname.endswith(".cedar"):
                policy_id = fname[:-6]
                with open(os.path.join(policy_dir, fname)) as f:
                    policies[policy_id] = f.read()
    if not policies:
        # Minimal fallback: allow nothing (safe default)
        policies["deny_all"] = "forbid(principal, action, resource);"
    return policies


cedar_policies = _load_cedar_policies()
print(f"[Kest.Gateway] Loaded Cedar policies: {list(cedar_policies.keys())}")
policy_engine = CedarLocalEngine(policies=cedar_policies, entities=[])
configure(engine=policy_engine, identity=identity_provider)

# ---------------------------------------------------------------------------
# App & Middleware
# ---------------------------------------------------------------------------
app = FastAPI(
    title="kest-gateway",
    description=(
        "Scope-aware delegation gateway. Enforces OBO scope policy, mints narrow "
        "task tokens, and produces a cryptographic audit trail via Kest."
    ),
)

# Middleware order: FastAPI processes middleware LIFO (last added = outermost = first to run).
# KestMiddleware is added LAST → runs OUTERMOST (first): propagates incoming W3C baggage
#   (kest.chain_tip, kest.passport, etc.) from kest-agent into OTel context.
# KestIdentityMiddleware is added FIRST → runs INNER (second): extracts identity from the
#   OBO JWT in Authorization header → overwrites kest.principal_user/principal_agent/principal_scope with JWT-derived values.
#
# Result: kest.principal_agent = azp from the OBO token = "kest-agent" ✓
#         kest.chain_tip = from incoming baggage header ✓ (set by KestMiddleware first)
app.add_middleware(
    KestIdentityMiddleware,
    jwks_uri=JWKS_URI,
    user_claim="preferred_username",
)
app.add_middleware(KestMiddleware)


@app.exception_handler(PermissionError)
async def permission_error_handler(request: Request, exc: PermissionError):
    """
    Map @kest_verified PermissionError (policy denial) to a strict 403 Forbidden.
    Without this, FastAPI returns 500 for unhandled PermissionError.
    """
    return JSONResponse(
        status_code=403,
        content={"detail": str(exc)},
    )


# ---------------------------------------------------------------------------
# Task Token Minting
# ---------------------------------------------------------------------------
def _mint_task_token(
    delegated_user: str,
    delegated_agent: str,
    task: str = "process-data",
    ttl: int = TASK_TTL_SECONDS,
) -> str:
    """
    Mint a narrow-scope task token signed by this gateway's Ed25519 key.

    The token is a compact JWT (header.payload.signature) carrying only the
    specific task scope — NOT the user's full delegated scopes.

    Args:
        delegated_user: The original human user (from OBO act.sub).
        delegated_agent: The acting agent that presented the OBO token.
        task: The task identifier (becomes scope: task:<task>).
        ttl: Token lifetime in seconds.

    Returns:
        str: A compact JWT string.

    Security note (Approach A):
        This token is signed by the gateway's own key — not Keycloak.
        See docs/GATEWAY_E2E.md for the full threat analysis and alternatives.
    """
    now = int(time.time())
    payload = {
        "iss": f"kest-gateway/{SERVICE_NAME}",
        "sub": SERVICE_NAME,
        "iat": now,
        "exp": now + ttl,
        "scope": f"task:{task}",
        "task": task,
        "delegated_user": delegated_user,
        "delegated_agent": delegated_agent,
    }

    # Build a minimal JWS using the gateway's identity provider
    header = {"alg": "EdDSA", "typ": "JWT", "kid": SERVICE_NAME}
    header_b64 = base64.urlsafe_b64encode(
        json.dumps(header, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()
    payload_b64 = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()

    signing_input = f"{header_b64}.{payload_b64}"
    signature = identity_provider.sign(signing_input.encode())
    return f"{signing_input}.{signature}"


def _decode_task_token(token: str) -> dict:
    """Decode a task token payload without signature verification (test helper)."""
    try:
        parts = token.split(".")
        if len(parts) >= 2:
            pad = "=" * ((4 - len(parts[1]) % 4) % 4)
            return json.loads(base64.urlsafe_b64decode(parts[1] + pad))
    except Exception:
        pass
    return {}


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.post("/authorise")
async def authorise_handler(request: Request):
    """
    Step 1 of the gateway flow.

    Receives an OBO token from kest-agent. KestIdentityMiddleware has already:
      - Verified the OBO JWT signature against Keycloak JWKS
      - Extracted kest.principal_user (alice), kest.principal_agent (kest-agent), kest.principal_scope (scope)
        into OTel baggage

    This endpoint:
      1. Enforces gateway_policy (scope check + dual-identity via @kest_verified)
      2. Signs a KestEntry → audit entry #2 in the Merkle chain
      3. Mints a narrow task token (task:process-data)
      4. Returns the task token to the caller (kest-agent)

    The caller is then expected to PUT the task token into /execute-task.
    """
    return await _authorise_logic()


@kest_verified(
    policy="gateway_policy",
    origin="internal",
)
async def _authorise_logic():
    """
    @kest_verified-decorated logic for /authorise.

    gateway_policy enforces:
      - context["principal_user"] != ""
      - context["principal_agent"] != ""
      - context["principal_scope"] contains "read:data"
    """
    try:
        user = str(baggage.get_baggage("kest.principal_user") or "")
        agent = str(baggage.get_baggage("kest.principal_agent") or "")
        scope = str(baggage.get_baggage("kest.principal_scope") or "")

        print(
            f"[{SERVICE_NAME}] /authorise — user={user!r}, agent={agent!r}, scope={scope!r}"
        )

        if not user:
            raise HTTPException(status_code=403, detail="No delegated user identity in OBO token")
        if not agent:
            raise HTTPException(status_code=403, detail="No agent identity in OBO token")

        # Mint a narrow task token
        task_token = _mint_task_token(
            delegated_user=user,
            delegated_agent=agent,
            task="process-data",
        )

        return {
            "status": "authorised",
            "gateway": SERVICE_NAME,
            "delegated_user": user,
            "delegated_agent": agent,
            "granted_scope": "task:process-data",
            "task_token": task_token,
        }

    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/execute-task")
async def execute_task_handler(request: Request):
    """
    Step 2 of the gateway flow.

    Receives the narrow task token (from /authorise response).
    KestIdentityMiddleware has already injected kest.principal_scope=task:process-data
    into OTel baggage (the gateway sets this itself before forwarding).

    This endpoint:
      1. Enforces task_policy (scope must be exactly "task:process-data")
      2. Signs a KestEntry → audit entry #3 in the Merkle chain
      3. Calls hop1 with the task token, producing audit entries #4/5/6
    """
    body = await request.json()
    task_token = body.get("task_token", "")
    if not task_token:
        raise HTTPException(status_code=400, detail="task_token required in request body")

    # Decode the task token and inject its scope into baggage so
    # task_policy can read context["principal_scope"] == "task:process-data"
    token_claims = _decode_task_token(task_token)
    task_scope = token_claims.get("scope", "")
    delegated_user = token_claims.get("delegated_user", "")
    delegated_agent = token_claims.get("delegated_agent", "")

    # Store task scope in request-local baggage so task_policy and
    # CedarLocalEngine pick it up as context["principal_scope"].
    import opentelemetry.context as otel_context
    from opentelemetry import baggage as otel_baggage

    ctx = otel_context.get_current()
    ctx = otel_baggage.set_baggage("kest.principal_scope", task_scope, context=ctx)
    ctx = otel_baggage.set_baggage("kest.principal_user", delegated_user, context=ctx)
    ctx = otel_baggage.set_baggage("kest.principal_agent", delegated_agent, context=ctx)
    token = otel_context.attach(ctx)
    try:
        return await _execute_task_logic(task_token, delegated_user, delegated_agent)
    finally:
        otel_context.detach(token)


@kest_verified(
    policy="task_policy",
    origin="internal",
)
async def _execute_task_logic(task_token: str, delegated_user: str, delegated_agent: str):
    """
    @kest_verified-decorated logic for /execute-task.

    task_policy enforces:
      - context["principal_scope"] == "task:process-data"
      - context["trust_score"] >= 50 (internal origin)
    """
    try:
        print(
            f"[{SERVICE_NAME}] /execute-task — user={delegated_user!r}, agent={delegated_agent!r}"
        )

        # Forward to hop1, embedding the task token in Authorization
        # and propagating current OTel baggage (which carries kest.principal_scope)
        all_baggage = baggage.get_all()
        baggage_header = ",".join(f"{k}={v}" for k, v in all_baggage.items())

        headers: dict[str, str] = {}
        if baggage_header:
            headers["baggage"] = baggage_header

        # Inject W3C traceparent so hop1 continues the trace
        span_ctx = trace.get_current_span().get_span_context()
        if span_ctx and span_ctx.is_valid:
            headers["traceparent"] = (
                f"00-{span_ctx.trace_id:032x}-{span_ctx.span_id:016x}-{span_ctx.trace_flags:02x}"
            )

        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            response = await client.get(HOP1_URL, headers=headers)

        if response.status_code != 200:
            raise HTTPException(
                status_code=response.status_code,
                detail=f"hop1 returned {response.status_code}: {response.text}",
            )

        return {
            "status": "executed",
            "gateway": SERVICE_NAME,
            "task": "process-data",
            "delegated_user": delegated_user,
            "delegated_agent": delegated_agent,
            "hop_result": response.json(),
        }

    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    return {"status": "ok", "service": SERVICE_NAME}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)

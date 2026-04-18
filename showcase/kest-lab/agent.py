"""
kest-agent: Mocked OBO (On-Behalf-Of) agent service.

Demonstrates RFC 8693 token exchange: alice's token is exchanged for an OBO
token where the agent acts on alice's behalf. The agent then calls hop1 with
its own SPIFFE identity + the OBO JWT, which propagates alice's identity
through the entire hop chain via KestIdentityMiddleware + OTel baggage.
"""
import os
import traceback
import httpx
from fastapi import FastAPI, Request, HTTPException
from opentelemetry import trace, baggage
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from kest.core import (
    configure,
    kest_verified,
    SPIREProvider,
    MockIdentityProvider,
    CedarLocalEngine,
    KestMiddleware,
    KestIdentityMiddleware,
)
import kest.core.framework.decorators as kest_decorators

# --- OTel ---
SERVICE_NAME = os.getenv("SERVICE_NAME", "kest-agent")
resource = Resource.create({"service.name": SERVICE_NAME})
provider = TracerProvider(resource=resource)
otlp_endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel-collector:4318")
exporter = OTLPSpanExporter(endpoint=f"{otlp_endpoint}/v1/traces")
provider.add_span_processor(BatchSpanProcessor(exporter))
trace.set_tracer_provider(provider)
kest_decorators.tracer = trace.get_tracer("kest.core")

# --- Identity & Engine ---
SPIRE_SOCKET = "unix:///var/run/spire/agent/public/api.sock"
if os.path.exists(SPIRE_SOCKET):
    identity_provider = SPIREProvider(socket_path=SPIRE_SOCKET)
else:
    identity_provider = MockIdentityProvider(
        principal=f"spiffe://kest.internal/workload/{SERVICE_NAME}"
    )

# --- Load Cedar policies from /app/cedar/policies/*.cedar ---
JWKS_URI = os.getenv("KEYCLOAK_JWKS_URI")


def _load_cedar_policies(policy_dir: str = "/workspace/app/cedar/policies") -> dict:
    policies = {}
    if os.path.isdir(policy_dir):
        for fname in os.listdir(policy_dir):
            if fname.endswith(".cedar"):
                policy_id = fname[:-6]
                with open(os.path.join(policy_dir, fname)) as f:
                    policies[policy_id] = f.read()
    if not policies:
        policies["fallback"] = 'permit(principal, action, resource) when { context["trust_score"] >= 10 };'
    return policies


cedar_policies = _load_cedar_policies()
print(f"[Kest.Agent] Loaded Cedar policies: {list(cedar_policies.keys())}")
policy_engine = CedarLocalEngine(policies=cedar_policies, entities=[])
configure(engine=policy_engine, identity=identity_provider)

# --- Keycloak token exchange config ---
KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://keycloak:8080")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "kest-lab")
KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "kest-agent")
KEYCLOAK_CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET", "kest-agent-secret")
HOP1_URL = os.getenv("HOP1_URL", "http://hop1:8000")
GATEWAY_URL = os.getenv("GATEWAY_URL", "http://kest-gateway:8002")

TOKEN_URL = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"

app = FastAPI()

# Middleware order: FastAPI processes middleware LIFO (last added = outermost = first to run).
# KestMiddleware is added LAST → runs OUTERMOST (first): propagates incoming W3C baggage
#   (kest.chain_tip, kest.passport, etc.) from kest-agent into OTel context.
# KestIdentityMiddleware is added FIRST → runs INNER (second): extracts identity from the
# KestIdentityMiddleware is added FIRST → runs INNER (second): extracts identity from the
#   JWT in Authorization header → writes kest.user/kest.agent/kest.task baggage with JWT-derived
#   values, which take precedence over whatever the caller forwarded in the baggage header.
#
# Result: kest.agent = azp from the OBO token = "kest-agent" ✓
app.add_middleware(
    KestIdentityMiddleware,
    jwks_uri=JWKS_URI,
    user_claim="preferred_username",
)
app.add_middleware(KestMiddleware)


async def exchange_token_obo(subject_token: str) -> str:
    """
    Performs an RFC 8693 token exchange: swaps alice's token for an OBO
    token where this agent is the actor (sub=kest-agent, act.sub=alice).

    Returns:
        str: The OBO access token.

    Raises:
        HTTPException: If Keycloak rejects the exchange.
    """
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(
            TOKEN_URL,
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token": subject_token,
                "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "client_id": KEYCLOAK_CLIENT_ID,
                "client_secret": KEYCLOAK_CLIENT_SECRET,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if response.status_code != 200:
            print(f"[{SERVICE_NAME}] Token exchange failed: {response.text}")
            raise HTTPException(
                status_code=502,
                detail=f"Token exchange failed: {response.status_code}",
            )
        return response.json()["access_token"]


@app.post("/delegate")
async def delegate_handler(request: Request):
    """
    Receives alice's Bearer token, performs OBO token exchange,
    then calls hop1 with the resulting delegated token.

    The OBO JWT contains:
      sub  = kest-agent  (this agent is now the acting principal)
      act.sub = alice    (original delegating user)

    KestIdentityMiddleware on hop1 will extract:
      kest.user   = alice        (from act.sub)
      kest.agent  = kest-agent   (from sub)
    """
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")

    subject_token = auth.split(" ", 1)[1]

    try:
        obo_token = await exchange_token_obo(subject_token)
    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

    return await call_hop1_as_agent(obo_token)


@kest_verified(
    policy="delegation_policy",
    origin="internal",
)
async def call_hop1_as_agent(obo_token: str):
    """
    The agent's protected call to hop1. @kest_verified enforces the
    delegation_policy using the agent's own SPIFFE identity before
    forwarding with the OBO JWT.
    """
    # Read kest.user from OTel baggage (set by KestIdentityMiddleware from OBO JWT)
    # Spec-compliant key: SPEC-v0.3.0 §8.4
    resolved_user = baggage.get_baggage("kest.user")
    print(f"[{SERVICE_NAME}] Calling hop1 as agent, delegating for user={resolved_user}.")
    async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
        response = await client.get(
            HOP1_URL,
            headers={"Authorization": f"Bearer {obo_token}"},
        )
        if response.status_code != 200:
            raise HTTPException(
                status_code=response.status_code,
                detail=response.text,
            )
        return {
            "status": "delegated",
            "agent": SERVICE_NAME,
            "user": resolved_user,
            "hop1_response": response.json(),
        }


@app.post("/delegate-to-gateway")
async def delegate_to_gateway_handler(request: Request):
    """
    Full delegation chain: Alice → OBO → kest-gateway → task token → hop1/2/3.

    This endpoint demonstrates the complete three-tier delegation flow:
      1. Receives alice's Bearer token
      2. Performs RFC 8693 OBO exchange (alice → kest-agent)
      3. Calls kest-gateway /authorise with the OBO token (scope check)
         kest-gateway enforces gateway_policy and mints a task token
      4. Calls kest-gateway /execute-task with the narrowly scoped task token
         kest-gateway enforces task_policy then calls hop1 → hop2 → hop3

    The result carries the full chain output for E2E audit verification.
    """
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")

    subject_token = auth.split(" ", 1)[1]

    try:
        obo_token = await exchange_token_obo(subject_token)
    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

    return await _delegate_to_gateway_logic(obo_token)


@kest_verified(
    policy="delegation_policy",
    origin="internal",
)
async def _delegate_to_gateway_logic(obo_token: str):
    """
    @kest_verified-decorated gateway delegation logic.

    Enforces delegation_policy (user + agent both present), then:
      1. Calls kest-gateway /authorise with the OBO token
      2. Extracts the task token from the response
      3. Calls kest-gateway /execute-task with the task token
    """
    resolved_user = baggage.get_baggage("kest.user")  # spec-compliant (SPEC-v0.3.0 §8.4)
    print(f"[{SERVICE_NAME}] /delegate-to-gateway — delegating for user={resolved_user!r}")

    # Inject W3C traceparent and baggage so gateway continues the trace
    span_ctx = trace.get_current_span().get_span_context()
    traceparent = ""
    if span_ctx and span_ctx.is_valid:
        traceparent = f"00-{span_ctx.trace_id:032x}-{span_ctx.span_id:016x}-{span_ctx.trace_flags:02x}"
        
    all_baggage = baggage.get_all()
    baggage_header = ",".join(f"{k}={v}" for k, v in all_baggage.items())
    
    base_headers = {}
    if traceparent:
        base_headers["traceparent"] = traceparent
    if baggage_header:
        base_headers["baggage"] = baggage_header

    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        # Step 1: Present OBO token to kest-gateway /authorise for scope check + token mint
        auth_headers = dict(base_headers)
        auth_headers["Authorization"] = f"Bearer {obo_token}"
        auth_resp = await client.post(
            f"{GATEWAY_URL}/authorise",
            headers=auth_headers,
        )
        if auth_resp.status_code != 200:
            raise HTTPException(
                status_code=auth_resp.status_code,
                detail=f"kest-gateway /authorise failed: {auth_resp.text}",
            )
        auth_data = auth_resp.json()
        task_token = auth_data.get("task_token", "")
        if not task_token:
            raise HTTPException(status_code=500, detail="kest-gateway did not return a task_token")

        # Step 2: Submit the narrow task token to /execute-task
        exec_headers = dict(base_headers)
        exec_headers["Content-Type"] = "application/json"
        
        exec_resp = await client.post(
            f"{GATEWAY_URL}/execute-task",
            headers=exec_headers,
            json={"task_token": task_token},
        )
        if exec_resp.status_code != 200:
            raise HTTPException(
                status_code=exec_resp.status_code,
                detail=f"kest-gateway /execute-task failed: {exec_resp.text}",
            )

    return {
        "status": "delegated_via_gateway",
        "agent": SERVICE_NAME,
        "user": resolved_user,
        "authorise_response": auth_data,
        "execute_response": exec_resp.json(),
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8001)

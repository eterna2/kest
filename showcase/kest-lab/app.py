import os
import httpx
import traceback
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from opentelemetry import trace
import opentelemetry.context as otel_context
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator
from kest.core import (
    configure,
    kest_verified,
    OPAPolicyEngine,
    CedarLocalEngine,
    SPIREProvider,
    MockIdentityProvider,
    KestMiddleware,
    KestIdentityMiddleware,
)
import kest.core.framework.decorators as kest_decorators

_propagator = TraceContextTextMapPropagator()

# --- Initialize OpenTelemetry SDK ---
SERVICE_NAME = os.getenv("SERVICE_NAME", "unknown")
resource = Resource.create({"service.name": SERVICE_NAME})
provider = TracerProvider(resource=resource)
otlp_endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel-collector:4318")
exporter = OTLPSpanExporter(endpoint=f"{otlp_endpoint}/v1/traces")
processor = BatchSpanProcessor(exporter)
provider.add_span_processor(processor)
trace.set_tracer_provider(provider)

# Patch the Kest tracer to use our global provider
kest_decorators.tracer = trace.get_tracer("kest.core")

# --- JWKS URI for JWT signature verification ---
JWKS_URI = os.getenv("KEYCLOAK_JWKS_URI")  # None in dev/mock mode → unverified decode

app = FastAPI()

# Middleware registration order: last added = outermost (first to run on request).
# KestIdentityMiddleware must be outermost so JWT → baggage happens before
# KestMiddleware propagates baggage into the OTel context.
app.add_middleware(KestMiddleware)
app.add_middleware(
    KestIdentityMiddleware,
    jwks_uri=JWKS_URI,
    user_claim="preferred_username",  # Use username, not UUID, for policy/audit matching
    audience="account",
)


@app.exception_handler(PermissionError)
async def permission_error_handler(request: Request, exc: PermissionError):
    """
    Map @kest_verified PermissionError (policy denial or missing identity) to 403.
    This includes requests with invalid JWTs where kest.user is empty.
    """
    return JSONResponse(status_code=403, content={"detail": str(exc)})


# --- Configure Kest ---
NEXT_HOP = os.getenv("NEXT_HOP_URL", "none")

os.environ["SPIFFE_ENDPOINT_SOCKET"] = "unix:///var/run/spire/agent/public/api.sock"
SPIRE_SOCKET = "unix:///var/run/spire/agent/public/api.sock"
if os.path.exists("/var/run/spire/agent/public/api.sock"):
    identity_provider = SPIREProvider(socket_path=SPIRE_SOCKET)
else:
    identity_provider = MockIdentityProvider(
        principal=f"spiffe://kest.internal/workload/{SERVICE_NAME}"
    )


# --- Load Cedar policies from /app/cedar/policies/*.cedar ---
# CedarLocalEngine evaluates in-process using cedarpy (Rust-backed).
# This avoids the sidecar's entity-UID API format requirements.
def _load_cedar_policies(policy_dir: str = "/workspace/app/cedar/policies") -> dict:
    policies = {}
    if os.path.isdir(policy_dir):
        for fname in os.listdir(policy_dir):
            if fname.endswith(".cedar"):
                policy_id = fname[:-6]  # strip .cedar
                with open(os.path.join(policy_dir, fname)) as f:
                    policies[policy_id] = f.read()
    if not policies:
        # Minimal fallback policy for environments without the policy dir
        policies["fallback"] = (
            'permit(principal, action, resource) when { context["trust_score"] >= 50 };'
        )
    return policies


engine_type = os.getenv("AUTHORIZATION_ENGINE", "cedar").lower()
if engine_type == "opa":
    policy_engine = OPAPolicyEngine(url="http://opa:8181")
else:
    cedar_policies = _load_cedar_policies()
    print(f"[Kest.App] Loaded Cedar policies: {list(cedar_policies.keys())}")
    policy_engine = CedarLocalEngine(policies=cedar_policies, entities=[])

configure(engine=policy_engine, identity=identity_provider)


@app.get("/")
async def root_handler(request: Request):
    """
    Entry point. KestIdentityMiddleware and KestMiddleware have already
    extracted all JWT claims and W3C baggage (kest.user/agent/task)
    into the OTel context. We anchor the trace from the remote parent, then hand off.
    """
    # Only use the trace context (traceparent) for remote parent continuation;
    # baggage is already in the current context from KestIdentityMiddleware.
    current_ctx = otel_context.get_current()
    remote_ctx = _propagator.extract(request.headers, context=current_ctx)

    with trace.get_tracer("kest.core").start_as_current_span(
        "kest.gateway.extract", context=remote_ctx
    ):
        return await handle_request_logic()


@kest_verified(
    policy="allow",
    origin="internet" if os.getenv("SERVICE_NAME") == "hop1" else "internal",
)
async def handle_request_logic():
    try:
        print(f"[{SERVICE_NAME}] Handling request with context attached.")

        if NEXT_HOP != "none":
            print(f"[{SERVICE_NAME}] Calling next hop: {NEXT_HOP}")
            from opentelemetry import baggage

            all_baggage = baggage.get_all(context=otel_context.get_current())
            header_val = ",".join([f"{k}={v}" for k, v in all_baggage.items()])

            headers = {"baggage": header_val}

            span_ctx = trace.get_current_span().get_span_context()
            if span_ctx and span_ctx.is_valid:
                headers["traceparent"] = (
                    f"00-{span_ctx.trace_id:032x}-{span_ctx.span_id:016x}-{span_ctx.trace_flags:02x}"
                )
                if span_ctx.trace_state:
                    headers["tracestate"] = span_ctx.trace_state.to_header()

            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                print(f"[{SERVICE_NAME}] Injecting headers: {list(headers.keys())}")
                response = await client.get(NEXT_HOP, headers=headers)

                if response.status_code != 200:
                    print(
                        f"[{SERVICE_NAME}] Next hop returned {response.status_code}: {response.text}"
                    )
                    return {
                        "service": SERVICE_NAME,
                        "error_from_next": response.status_code,
                        "detail": response.text,
                    }

                return {"service": SERVICE_NAME, "next": response.json()}

        return {"service": SERVICE_NAME, "status": "end_of_chain"}
    except Exception as e:
        print(f"[{SERVICE_NAME}] Error in handle_request: {e}")
        traceback.print_exc()
        raise


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)

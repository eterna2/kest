import json
import base64
import threading
from opentelemetry import baggage, trace
import opentelemetry.context as otel_context
import httpx

# A global, thread-safe store for the lab to ensure propagation
# In a real system, this would be handled by a proper OTel Propagator
_LAB_BAGGAGE_STORE = {}
_LAB_LOCK = threading.Lock()


class KestMiddleware:
    """
    FastAPI (ASGI) Middleware for automatic Kest lineage propagation.

    This middleware extracts Kest-related baggage from incoming HTTP headers
    and injects it into the OpenTelemetry context. This ensures that
    downstream `@kest_verified` functions can continue the Merkle lineage.
    """

    def __init__(self, app):
        """
        Initializes the Kest middleware.

        Args:
            app: The ASGI application.
        """
        self.app = app

    async def __call__(self, scope, receive, send):
        """
        ASGI middleware call implementation.

        Extracts 'baggage' headers and maps them to the current trace context.
        """
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        # 1. Extract Baggage from Headers
        headers = dict(scope.get("headers", []))
        baggage_header = headers.get(b"baggage", b"").decode()

        extracted_baggage = {}
        if baggage_header:
            parts = baggage_header.split(",")
            for part in parts:
                if "=" in part:
                    k, v = part.split("=", 1)
                    extracted_baggage[k.strip()] = v.strip()

        # 2. Store in OTel context
        ctx = otel_context.get_current()
        for k, v in extracted_baggage.items():
            ctx = baggage.set_baggage(k, v, context=ctx)

        # 3. For the lab, we'll also store it in a global map linked to the trace_id
        with trace.get_tracer("kest.core").start_as_current_span(
            "kest.middleware.extract", context=ctx
        ) as span:
            trace_id = span.get_span_context().trace_id
            if trace_id:
                with _LAB_LOCK:
                    _LAB_BAGGAGE_STORE[trace_id] = extracted_baggage
                    print(
                        f"[Kest.Middleware] Mapped trace {trace_id} to baggage: {extracted_baggage}"
                    )

        token = otel_context.attach(ctx)
        try:
            return await self.app(scope, receive, send)
        finally:
            otel_context.detach(token)


class KestHttpxInterceptor:
    """
    HTTPX Interceptor for automatic Kest lineage injection into outgoing requests.

    This interceptor automatically injects the current Kest lineage (Passport)
    into the 'baggage' header of outgoing HTTP requests, allowing lineage
    to propagate across microservice boundaries.
    """

    def __call__(self, request: httpx.Request) -> httpx.Request:
        """
        Intercepts an outgoing request and injects baggage headers.

        Args:
            request: The httpx.Request object to modify.

        Returns:
            httpx.Request: The modified request with Kest baggage headers.
        """
        # 1. Get trace_id to lookup baggage
        ctx = otel_context.get_current()
        current_span = trace.get_current_span(ctx)

        all_baggage = {}
        if current_span:
            trace_id = current_span.get_span_context().trace_id
            with _LAB_LOCK:
                all_baggage = _LAB_BAGGAGE_STORE.get(trace_id, {}).copy()

        # Merge with OTel baggage
        all_baggage.update(baggage.get_all(context=ctx))

        if all_baggage:
            print(f"[Kest.Interceptor] Injecting baggage: {list(all_baggage.keys())}")
            header_val = ",".join([f"{k}={v}" for k, v in all_baggage.items()])
            request.headers["baggage"] = header_val

        return request


class KestIdentityMiddleware:
    """
    FastAPI (ASGI) Middleware that extracts principal identity from incoming JWT tokens.

    For standard tokens:
        - kest.principal_user  = <user_claim> (default: preferred_username or sub)
        - kest.principal_agent = azp or client_id (the application presenting the token)

    For OBO tokens (RFC 8693 — 'act' claim present):
        - kest.principal_user  = act.sub (the original delegating user)
        - kest.principal_agent = sub     (the service that performed the OBO exchange)

    Also populates:
        - kest.principal_scope  = scope  (full scope string, used for policy enforcement)
        - kest.principal_roles  = JSON-encoded realm_access.roles list

    Verification mode:
        - If jwks_uri is provided, JWTs are verified with PyJWT (pyjwt[crypto] required).
        - If jwks_uri is None, tokens are decoded without signature verification (dev mode).
    """

    def __init__(
        self, app, jwks_uri: str | None = None, user_claim: str = "preferred_username"
    ):
        self.app = app
        self.user_claim = user_claim
        self._jwks_client = None
        if jwks_uri:
            try:
                from jwt import PyJWKClient  # type: ignore[import-not-found]

                self._jwks_client = PyJWKClient(jwks_uri, cache_keys=True)
            except ImportError:
                print(
                    "[Kest.IdentityMiddleware] WARNING: pyjwt[crypto] not installed. "
                    "Falling back to unverified JWT decoding. Do not use in production."
                )

    def _decode_token(self, token: str) -> dict:
        """Decode and optionally verify a JWT, returning its claims as a dict."""
        if self._jwks_client is not None:
            try:
                from jwt import decode as jwt_decode  # type: ignore[import-not-found]

                signing_key = self._jwks_client.get_signing_key_from_jwt(token)
                return jwt_decode(
                    token,
                    signing_key.key,
                    algorithms=["RS256", "ES256"],
                    options={"verify_aud": False},
                )
            except Exception as exc:
                print(f"[Kest.IdentityMiddleware] JWT verification failed: {exc}")
                return {}

        # Dev/fallback: unverified base64 decode of the payload segment
        try:
            parts = token.split(".")
            if len(parts) >= 2:
                pad = "=" * ((4 - len(parts[1]) % 4) % 4)
                return json.loads(base64.urlsafe_b64decode(parts[1] + pad))
        except Exception as exc:
            print(f"[Kest.IdentityMiddleware] Failed to decode token payload: {exc}")
        return {}

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        headers = dict(scope.get("headers", []))
        auth_header = headers.get(b"authorization", b"").decode()

        ctx = otel_context.get_current()

        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            claims = self._decode_token(token)

            if claims:
                act = claims.get("act", {})
                if act and "sub" in act:
                    # OBO token: original user is in act.sub, the acting service is sub
                    user = str(act.get("sub", ""))
                    agent = str(claims.get("sub", "") or claims.get("azp", ""))
                else:
                    # Regular token
                    user = str(
                        claims.get(self.user_claim)
                        or claims.get("preferred_username")
                        or claims.get("sub", "")
                    )
                    agent = str(claims.get("azp") or claims.get("client_id", ""))

                scope_str = str(claims.get("scope", ""))
                roles: list = claims.get("realm_access", {}).get("roles", [])

                if user:
                    ctx = baggage.set_baggage("kest.principal_user", user, context=ctx)
                if agent:
                    ctx = baggage.set_baggage(
                        "kest.principal_agent", agent, context=ctx
                    )
                if scope_str:
                    ctx = baggage.set_baggage(
                        "kest.principal_scope", scope_str, context=ctx
                    )
                if roles:
                    ctx = baggage.set_baggage(
                        "kest.principal_roles", json.dumps(roles), context=ctx
                    )

                print(
                    f"[Kest.IdentityMiddleware] Extracted principal: "
                    f"user={user}, agent={agent}, roles={json.dumps(roles)}"
                )

        token_ctx = otel_context.attach(ctx)
        try:
            return await self.app(scope, receive, send)
        finally:
            otel_context.detach(token_ctx)

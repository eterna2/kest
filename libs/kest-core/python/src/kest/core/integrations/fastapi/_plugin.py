"""
kest.core.integrations.fastapi._plugin — Core implementation.

This module is intentionally private (``_plugin``); consumers should import
from ``kest.core.integrations.fastapi`` (the public namespace).

Dependencies (all optional, guarded by ImportError at call-time):
  fastapi          >= 0.115.0   (kest[fastapi])
  python-jose      >= 3.3.0     (kest[fastapi])

No FastAPI or jose symbols appear at the module level so that ``kest.core``
can be imported without those packages installed.  All FastAPI types are
imported lazily inside functions or behind ``TYPE_CHECKING``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, TypedDict

if TYPE_CHECKING:
    # Imported only for type annotations in user-facing subclasses/protocols.
    # Guarded so kest.core is importable without fastapi installed.
    from fastapi import Request  # noqa: F401

from kest.core.vault.errors import (
    HandleAccessDeniedError,
    HandleExpiredError,
    HandleNotFoundError,
)
from kest.core.vault.vault import HandleVault

# ---------------------------------------------------------------------------
# Public response type
# ---------------------------------------------------------------------------


class HandleResponse(TypedDict):
    """Serialisable response carrying an opaque handle + its safe_view."""

    handle_id: str
    safe_view: str


# ---------------------------------------------------------------------------
# PrincipalExtractor protocol
# ---------------------------------------------------------------------------


class PrincipalExtractor:
    """
    Protocol for mapping an incoming HTTP request to a caller principal string.

    Implement this class to integrate your own auth mechanism
    (mTLS SPIFFE SAN, OIDC, API-key lookup, etc.).

    The returned string should be a stable identity such as a SPIFFE URI,
    e.g. ``"spiffe://example.com/services/gateway"``.

    Raise ``fastapi.HTTPException(status_code=401)`` for unauthenticated
    requests and ``fastapi.HTTPException(status_code=403)`` for authenticated
    but unauthorised ones.
    """

    async def extract(self, request: Any) -> str:  # noqa: D102
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Built-in extractors
# ---------------------------------------------------------------------------


class JWTPrincipalExtractor(PrincipalExtractor):
    """
    Extract a caller principal from a JWT Bearer token.

    The token must contain a ``principal`` claim (configurable via
    ``claim``) holding the identity string, e.g.
    ``"spiffe://hospital.internal/services/gateway"``.

    Args:
        secret:    HS256 shared secret (or RSA/EC public key for RS/ES algs).
        algorithm: JWT algorithm.  Defaults to ``"HS256"``.
        claim:     Payload claim name that holds the principal.
                   Defaults to ``"principal"``.
    """

    def __init__(
        self,
        secret: str,
        algorithm: str = "HS256",
        claim: str = "principal",
    ) -> None:
        self._secret = secret
        self._algorithm = algorithm
        self._claim = claim

    async def extract(self, request: Any) -> str:
        try:
            from fastapi import HTTPException, status
            from fastapi.security.utils import get_authorization_scheme_param
            from jose import JWTError, jwt
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "kest[fastapi] extras not installed. Run: pip install kest[fastapi]"
            ) from exc

        auth_header = request.headers.get("Authorization", "")
        scheme, token = get_authorization_scheme_param(auth_header)
        if scheme.lower() != "bearer" or not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing or malformed Authorization: Bearer <token> header.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        try:
            payload = jwt.decode(token, self._secret, algorithms=[self._algorithm])
        except JWTError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid or expired JWT: {exc}",
                headers={"WWW-Authenticate": "Bearer"},
            ) from exc

        principal = payload.get(self._claim, "")
        if not principal:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"JWT is missing the '{self._claim}' claim.",
            )
        return str(principal)


class HeaderPrincipalExtractor(PrincipalExtractor):
    """
    Extract a caller principal from a plain HTTP request header.

    Useful for trusted-proxy setups, integration tests, or environments
    where principal injection is handled upstream (e.g. an Envoy sidecar).

    Args:
        header_name: The header whose value is the principal string.
                     Case-insensitive per HTTP spec.
    """

    def __init__(self, header_name: str) -> None:
        self._header = header_name.lower()

    async def extract(self, request: Any) -> str:
        try:
            from fastapi import HTTPException, status
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "kest[fastapi] extras not installed. Run: pip install kest[fastapi]"
            ) from exc

        principal = request.headers.get(self._header, "")
        if not principal:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Missing required header '{self._header}'.",
            )
        return principal


# ---------------------------------------------------------------------------
# VaultDependency — Depends() factory
# ---------------------------------------------------------------------------


class VaultDependency:
    """
    A FastAPI `Depends`-compatible callable that unseals a HandleVault handle.

    Usage::

        get_data = VaultDependency(vault=vault, extractor=jwt_extractor)

        @app.get("/resource/{handle_id}")
        async def endpoint(data = Depends(get_data)):
            ...

    The ``handle_id`` path parameter is automatically read from the request.
    Raises ``HTTP 401`` if auth fails, ``HTTP 403`` if the caller's principal
    is not in the handle's ACL, ``HTTP 404`` if the handle is unknown, and
    ``HTTP 410`` if the handle has expired.

    Args:
        vault:     The ``HandleVault`` instance to unseal from.
        extractor: A ``PrincipalExtractor`` that maps the request to a principal.
    """

    def __init__(self, vault: HandleVault, extractor: PrincipalExtractor) -> None:
        self._vault = vault
        self._extractor = extractor
        # Inject the real fastapi.Request class into __call__.__annotations__ so
        # FastAPI's get_type_hints() resolves it correctly (bypasses the
        # `from __future__ import annotations` string-ification problem).
        try:
            from fastapi import Request

            self.__call__.__func__.__annotations__["request"] = Request  # type: ignore[attr-defined]
        except ImportError:  # pragma: no cover
            pass

    async def __call__(self, request: Any) -> Any:
        try:
            from fastapi import HTTPException, status
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "kest[fastapi] extras not installed. Run: pip install kest[fastapi]"
            ) from exc

        # Extract caller principal (raises HTTP 401/403 on failure)
        principal = await self._extractor.extract(request)

        # Read handle_id from path parameters
        handle_id: str = request.path_params.get("handle_id", "")
        if not handle_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="'handle_id' path parameter is required.",
            )

        # Unseal
        try:
            data = self._vault.unseal(
                handle_id=handle_id, requesting_principal=principal
            )
        except HandleAccessDeniedError as exc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied for principal '{principal}': {exc}",
            ) from exc
        except HandleExpiredError as exc:
            raise HTTPException(
                status_code=status.HTTP_410_GONE,
                detail=f"Handle '{handle_id}' has expired: {exc}",
            ) from exc
        except HandleNotFoundError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Handle '{handle_id}' not found.",
            ) from exc

        return data


# ---------------------------------------------------------------------------
# VaultRouter — pre-built APIRouter
# ---------------------------------------------------------------------------


class VaultRouter:
    """
    A pre-built FastAPI ``APIRouter`` exposing HandleVault over HTTP.

    Mount it with::

        app.include_router(VaultRouter(vault, extractor), prefix="/vault")

    Routes
    ------
    ``GET /safe-view/{handle_id}``
        Public.  Returns ``{"handle_id": ..., "safe_view": ...}``.

    ``GET /resolve/{handle_id}``
        Privileged.  Unseals the vault; caller's principal must be in
        ``gateway_principals`` **and** in the handle's ACL.

    Args:
        vault:               The ``HandleVault`` instance.
        extractor:           A ``PrincipalExtractor`` for the resolve endpoint.
        gateway_principals:  Set of principal strings permitted to resolve
                             handles.  If empty, any authenticated principal
                             may resolve.
    """

    def __init__(
        self,
        vault: HandleVault,
        extractor: PrincipalExtractor,
        gateway_principals: list[str] | None = None,
    ) -> None:
        self._vault = vault
        self._extractor = extractor
        self._gateway_principals: frozenset[str] = frozenset(gateway_principals or [])
        self._router = self._build()

    # Delegate APIRouter interface so include_router() just works
    def __getattr__(self, item: str) -> Any:
        return getattr(self._router, item)

    def _build(self) -> Any:  # returns fastapi.APIRouter
        try:
            from fastapi import APIRouter, HTTPException, Request, status
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "kest[fastapi] extras not installed. Run: pip install kest[fastapi]"
            ) from exc

        router = APIRouter(tags=["Vault"])

        vault = self._vault
        extractor = self._extractor
        gateway_principals = self._gateway_principals

        # Alias so that FastAPI's get_type_hints() sees fastapi.Request directly.
        # With `from __future__ import annotations`, annotations are strings;
        # we must pass the real class object via __annotations__ after definition.

        # ------------------------------------------------------------------ #
        # GET /safe-view/{handle_id}  — public, no auth                       #
        # ------------------------------------------------------------------ #

        @router.get(
            "/safe-view/{handle_id}",
            summary="Read safe_view (no auth required)",
            description=(
                "Returns the non-sensitive ``safe_view`` string for a vault handle. "
                "No authentication is required — safe_views are intentionally "
                "non-sensitive and safe to cache, log, and share."
            ),
        )
        async def get_safe_view(handle_id: str) -> dict:
            try:
                safe_view = vault.get_safe_view(handle_id)
            except (HandleNotFoundError, HandleExpiredError):
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Handle '{handle_id}' not found.",
                )
            return {"handle_id": handle_id, "safe_view": safe_view}

        # ------------------------------------------------------------------ #
        # GET /resolve/{handle_id}  — privileged                              #
        # ------------------------------------------------------------------ #

        @router.get(
            "/resolve/{handle_id}",
            summary="Resolve handle → raw data (privileged)",
            description=(
                "Unseals a vault handle and returns the raw (potentially sensitive) data. "
                "Requires a valid credential whose principal is in the gateway "
                "allow-list **and** in the handle's ACL."
            ),
        )
        async def resolve_handle(handle_id: str, request) -> dict:  # type: ignore[no-untyped-def]
            # Step 1: authenticate + extract principal
            principal = await extractor.extract(request)

            # Step 2: enforce gateway allow-list (before touching the vault)
            if gateway_principals and principal not in gateway_principals:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=(
                        f"Principal '{principal}' is not in the gateway allow-list. "
                        f"Allowed: {sorted(gateway_principals)}"
                    ),
                )

            # Step 3: vault ACL enforcement
            try:
                data = vault.unseal(handle_id=handle_id, requesting_principal=principal)
            except HandleAccessDeniedError as exc:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Vault ACL denied access for '{principal}': {exc}",
                ) from exc
            except HandleExpiredError as exc:
                raise HTTPException(
                    status_code=status.HTTP_410_GONE,
                    detail=f"Handle '{handle_id}' has expired.",
                ) from exc
            except HandleNotFoundError:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Handle '{handle_id}' not found.",
                )

            return {
                "handle_id": handle_id,
                "data": data,
                "resolved_by": principal,
            }

        # Inject the real Request class so FastAPI's get_type_hints() sees it.
        resolve_handle.__annotations__["request"] = Request

        return router


# ---------------------------------------------------------------------------
# Helper: seal and return HandleResponse
# ---------------------------------------------------------------------------


def vault_seal_response(
    vault: HandleVault,
    data: Any,
    safe_view: str,
    owner_principal: str,
    granted_principals: list[str] | None = None,
    ttl_seconds: int | None = None,
) -> HandleResponse:
    """
    Seal ``data`` into the vault and return a ``HandleResponse`` dict.

    This is a convenience wrapper for use in FastAPI route handlers that
    produce vault-sealed responses::

        @app.post("/patient")
        async def create_record(payload: PatientPayload) -> HandleResponse:
            return vault_seal_response(
                vault=vault,
                data=payload.sensitive_fields,
                safe_view=payload.summary,
                owner_principal="spiffe://...",
                granted_principals=["spiffe://.../gateway"],
            )

    Args:
        vault:               The ``HandleVault`` to seal into.
        data:                The sensitive payload to seal (any JSON-serialisable value).
        safe_view:           Human-readable, non-sensitive description.
        owner_principal:     SPIFFE identity of the sealing service.
        granted_principals:  Additional principals allowed to unseal.
        ttl_seconds:         Optional TTL.  ``None`` means the handle never expires.

    Returns:
        A ``HandleResponse`` TypedDict with ``handle_id`` and ``safe_view``.
    """
    handle = vault.seal(
        data=data,
        owner_principal=owner_principal,
        safe_view=safe_view,
        granted_principals=granted_principals or [],
        ttl_seconds=ttl_seconds if ttl_seconds is not None else 300,
    )
    return HandleResponse(handle_id=handle.id, safe_view=handle.safe_view)

"""
kest.core.integrations.fastapi — FastAPI integration plugin for HandleVault.

Install the optional dependency group to use this module:

    pip install kest[fastapi]
    # or
    uv add kest[fastapi]

Quick-start
===========

::

    from fastapi import FastAPI
    from kest.core import HandleVault, VaultCodec
    from kest.core.integrations.fastapi import VaultRouter, JWTPrincipalExtractor

    vault = HandleVault(codec=VaultCodec())
    extractor = JWTPrincipalExtractor(
        secret="your-jwt-secret",
        gateway_principals=["spiffe://example.com/services/gateway"],
    )
    router = VaultRouter(
        vault=vault,
        extractor=extractor,
        gateway_principals=["spiffe://example.com/services/gateway"],
    )

    app = FastAPI()
    app.include_router(router, prefix="/vault")

Endpoints added by ``VaultRouter``
===================================

``GET /vault/safe-view/{handle_id}``
    Returns the non-sensitive ``safe_view`` string.  No auth required.

``GET /vault/resolve/{handle_id}``
    Unseals the vault handle and returns raw data.
    Requires a JWT (or custom extractor) whose principal is in
    ``gateway_principals``.

Custom principal extractors
============================

Implement the ``PrincipalExtractor`` protocol::

    class MyExtractor(PrincipalExtractor):
        async def extract(self, request: Request) -> str:
            ...  # return a SPIFFE URI or similar string

See ``HeaderPrincipalExtractor`` and ``JWTPrincipalExtractor`` for reference
implementations.
"""

from kest.core.integrations.fastapi._plugin import (
    HandleResponse,
    HeaderPrincipalExtractor,
    JWTPrincipalExtractor,
    PrincipalExtractor,
    VaultDependency,
    VaultRouter,
    vault_seal_response,
)

__all__ = [
    "HandleResponse",
    "HeaderPrincipalExtractor",
    "JWTPrincipalExtractor",
    "PrincipalExtractor",
    "VaultDependency",
    "VaultRouter",
    "vault_seal_response",
]

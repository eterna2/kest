"""
HandleVault: in-memory secure store for sensitive data payloads.

Raw sensitive data is sealed into the vault and referenced only by an
OpaqueHandle (an opaque pointer with a non-sensitive safe_view). The LLM
operates on safe_views; only authorised principals may call unseal() to
retrieve the original payload.

Design decisions:
- Lazy TTL eviction: expiry is checked at access time (no background thread,
  no external scheduler, no extra dependencies).
- ACL is enforced strictly on unseal() only. get_safe_view() is ACL-free
  because the safe_view is intentionally non-sensitive.
- The cache stores a tuple of (OpaqueHandle, data) to keep metadata and
  payload co-located under a single key.
- The backing store is pluggable via the CacheProvider interface, defaulting
  to SimpleCache (in-memory dict). This allows future Redis / DynamoDB backends.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional

from kest.core.framework.cache import CacheProvider, SimpleCache
from kest.core.vault.errors import (
    HandleAccessDeniedError,
    HandleExpiredError,
    HandleNotFoundError,
)
from kest.core.vault.handle import OpaqueHandle

# Internal sentinel: value stored in cache keyed by handle.id
_Entry = tuple[OpaqueHandle, Any]


class HandleVault:
    """
    Secure in-memory vault for sensitive data payloads.

    Example::

        vault = HandleVault()
        handle = vault.seal(
            data="John Doe, SSN: 123-45-6789",
            owner_principal="spiffe://example.com/service-a",
            safe_view="A person record with name and SSN",
            ttl_seconds=300,
        )
        # handle.safe_view -> "A person record with name and SSN"  (safe for LLM)
        # handle.id        -> "hdl_a1b2c3..."                      (opaque pointer)

        raw = vault.unseal(handle.id, requesting_principal="spiffe://example.com/service-a")
    """

    def __init__(self, cache: Optional[CacheProvider] = None) -> None:
        self._cache: CacheProvider = cache if cache is not None else SimpleCache()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def seal(
        self,
        data: Any,
        owner_principal: str,
        safe_view: str,
        ttl_seconds: int = 300,
        granted_principals: Iterable[str] = (),
    ) -> OpaqueHandle:
        """
        Store *data* in the vault and return an opaque handle.

        Args:
            data: Any Python object to seal. Only returned to authorised
                principals via :meth:`unseal`.
            owner_principal: The principal that owns this handle (may always unseal).
            safe_view: A non-sensitive human-readable description of *data*.
                Safe to include in LLM prompts, audit logs, and API responses.
            ttl_seconds: Lifetime of the handle in seconds (default 300 = 5 min).
                Pass ``0`` to create an already-expired handle (useful in tests).
            granted_principals: Additional principals permitted to unseal.

        Returns:
            A frozen :class:`OpaqueHandle` referencing the sealed data.
        """
        now = datetime.now(tz=timezone.utc)
        handle = OpaqueHandle(
            id=f"hdl_{uuid.uuid4().hex}",
            safe_view=safe_view,
            owner_principal=owner_principal,
            created_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
            granted_principals=frozenset(granted_principals),
        )
        entry: _Entry = (handle, data)
        self._cache.set(handle.id, entry)
        return handle

    def unseal(self, handle_id: str, requesting_principal: str) -> Any:
        """
        Retrieve the sealed payload for *handle_id*.

        Checks (in order):
        1. Handle exists in vault.
        2. Handle has not expired (lazy TTL check).
        3. *requesting_principal* is the owner or in ``granted_principals``.

        Args:
            handle_id: The ``id`` field of a previously returned :class:`OpaqueHandle`.
            requesting_principal: The principal requesting access.

        Returns:
            The original *data* passed to :meth:`seal`.

        Raises:
            HandleNotFoundError: Handle was never created or has been invalidated.
            HandleExpiredError: Handle's TTL has elapsed.
            HandleAccessDeniedError: Principal is not authorised.
        """
        handle, data = self._get_entry(handle_id)
        self._check_expiry(handle)
        self._check_acl(handle, requesting_principal)
        return data

    def invalidate(self, handle_id: str) -> None:
        """
        Immediately remove a handle from the vault before its TTL elapses.

        Idempotent: calling this with an unknown or already-invalidated handle
        does not raise.

        Args:
            handle_id: The ``id`` of the handle to invalidate.
        """
        # SimpleCache doesn't expose delete; overwrite with None sentinel.
        # For CacheProvider implementations that support deletion this still works
        # because None is treated as "not found" in _get_entry.
        self._cache.set(handle_id, None)

    def get_safe_view(self, handle_id: str) -> str:
        """
        Return the non-sensitive ``safe_view`` string without ACL enforcement.

        The safe_view is intentionally non-sensitive (it's designed for LLM consumption),
        so no principal check is performed here.

        Args:
            handle_id: The ``id`` of the handle.

        Returns:
            The ``safe_view`` string.

        Raises:
            HandleNotFoundError: Handle does not exist or was invalidated.
            HandleExpiredError: Handle's TTL has elapsed.
        """
        handle, _data = self._get_entry(handle_id)
        self._check_expiry(handle)
        return handle.safe_view

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _get_entry(self, handle_id: str) -> _Entry:
        """Retrieve the raw cache entry or raise HandleNotFoundError."""
        value = self._cache.get(handle_id)
        if value is None:
            raise HandleNotFoundError(handle_id)
        return value  # type: ignore[return-value]

    @staticmethod
    def _check_expiry(handle: OpaqueHandle) -> None:
        """Raise HandleExpiredError if the handle's TTL has elapsed."""
        now = datetime.now(tz=timezone.utc)
        if now >= handle.expires_at:
            raise HandleExpiredError(
                f"Handle '{handle.id}' expired at {handle.expires_at.isoformat()} UTC."
            )

    @staticmethod
    def _check_acl(handle: OpaqueHandle, requesting_principal: str) -> None:
        """Raise HandleAccessDeniedError if the principal is not authorised."""
        authorised = {handle.owner_principal} | handle.granted_principals
        if requesting_principal not in authorised:
            raise HandleAccessDeniedError(
                f"Principal '{requesting_principal}' is not authorised to unseal "
                f"handle '{handle.id}'. Authorised principals: {sorted(authorised)}."
            )

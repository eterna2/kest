"""
TDD tests for the Data Vault / Opaque Handle pattern (Issue #79).

Covers:
- OpaqueHandle dataclass field correctness
- HandleVault.seal(): unique IDs, correct metadata, TTL
- HandleVault.unseal(): owner access, granted principals, ACL rejection, expiry
- HandleVault.invalidate(): immediate invalidation
- HandleVault.get_safe_view(): ACL-free access, missing handle
- Custom CacheProvider injection
- Public API importability from kest.core
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

import pytest

from kest.core.vault import HandleVault, OpaqueHandle
from kest.core.vault.errors import (
    HandleAccessDeniedError,
    HandleExpiredError,
    HandleNotFoundError,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

OWNER = "spiffe://example.com/service-a"
OTHER = "spiffe://example.com/service-b"
GRANTED = "spiffe://example.com/service-c"


def _fresh_vault() -> HandleVault:
    return HandleVault()


def _seal_simple(vault: HandleVault, ttl: int = 300) -> OpaqueHandle:
    return vault.seal(
        data="John Doe, SSN: 123-45-6789",
        owner_principal=OWNER,
        safe_view="A person record with name and SSN",
        ttl_seconds=ttl,
    )


# ---------------------------------------------------------------------------
# OpaqueHandle dataclass
# ---------------------------------------------------------------------------


def test_opaque_handle_has_required_fields():
    vault = _fresh_vault()
    handle = _seal_simple(vault)
    assert handle.id is not None
    assert handle.safe_view == "A person record with name and SSN"
    assert handle.owner_principal == OWNER
    assert isinstance(handle.created_at, datetime)
    assert isinstance(handle.expires_at, datetime)


def test_opaque_handle_id_has_hdl_prefix():
    vault = _fresh_vault()
    handle = _seal_simple(vault)
    assert handle.id.startswith("hdl_")


def test_opaque_handle_expires_at_after_created_at():
    vault = _fresh_vault()
    handle = _seal_simple(vault, ttl=60)
    delta = (handle.expires_at - handle.created_at).total_seconds()
    assert abs(delta - 60) < 1  # within 1 second


def test_opaque_handle_is_frozen():
    vault = _fresh_vault()
    handle = _seal_simple(vault)
    with pytest.raises((AttributeError, TypeError)):
        handle.safe_view = "mutated"  # type: ignore[misc]


def test_opaque_handle_timestamps_are_utc():
    vault = _fresh_vault()
    handle = _seal_simple(vault)
    assert handle.created_at.tzinfo == timezone.utc
    assert handle.expires_at.tzinfo == timezone.utc


# ---------------------------------------------------------------------------
# HandleVault.seal()
# ---------------------------------------------------------------------------


def test_seal_returns_opaque_handle():
    vault = _fresh_vault()
    handle = _seal_simple(vault)
    assert isinstance(handle, OpaqueHandle)


def test_seal_generates_unique_ids():
    vault = _fresh_vault()
    ids = {_seal_simple(vault).id for _ in range(20)}
    assert len(ids) == 20


def test_seal_stores_data_retrievable_by_unseal():
    vault = _fresh_vault()
    handle = _seal_simple(vault)
    result = vault.unseal(handle.id, requesting_principal=OWNER)
    assert result == "John Doe, SSN: 123-45-6789"


def test_seal_stores_arbitrary_data_types():
    vault = _fresh_vault()
    payload = {"name": "Alice", "score": 42, "tags": ["vip"]}
    handle = vault.seal(
        data=payload,
        owner_principal=OWNER,
        safe_view="User profile summary",
    )
    assert vault.unseal(handle.id, requesting_principal=OWNER) == payload


def test_seal_with_granted_principals():
    vault = _fresh_vault()
    handle = vault.seal(
        data="secret",
        owner_principal=OWNER,
        safe_view="summary",
        granted_principals=[GRANTED],
    )
    assert vault.unseal(handle.id, requesting_principal=GRANTED) == "secret"


# ---------------------------------------------------------------------------
# HandleVault.unseal()
# ---------------------------------------------------------------------------


def test_unseal_by_owner_succeeds():
    vault = _fresh_vault()
    handle = _seal_simple(vault)
    assert (
        vault.unseal(handle.id, requesting_principal=OWNER)
        == "John Doe, SSN: 123-45-6789"
    )


def test_unseal_by_granted_principal_succeeds():
    vault = _fresh_vault()
    handle = vault.seal(
        data="confidential",
        owner_principal=OWNER,
        safe_view="summary",
        granted_principals=[GRANTED],
    )
    assert vault.unseal(handle.id, requesting_principal=GRANTED) == "confidential"


def test_unseal_by_unauthorised_principal_raises_access_denied():
    vault = _fresh_vault()
    handle = _seal_simple(vault)
    with pytest.raises(HandleAccessDeniedError):
        vault.unseal(handle.id, requesting_principal=OTHER)


def test_unseal_expired_handle_raises_handle_expired():
    vault = _fresh_vault()
    handle = vault.seal(
        data="ephemeral",
        owner_principal=OWNER,
        safe_view="short-lived data",
        ttl_seconds=0,  # expires immediately
    )
    # Ensure expiry by sleeping a tiny bit
    time.sleep(0.05)
    with pytest.raises(HandleExpiredError):
        vault.unseal(handle.id, requesting_principal=OWNER)


def test_unseal_unknown_handle_raises_not_found():
    vault = _fresh_vault()
    with pytest.raises(HandleNotFoundError):
        vault.unseal("hdl_doesnotexist", requesting_principal=OWNER)


# ---------------------------------------------------------------------------
# HandleVault.invalidate()
# ---------------------------------------------------------------------------


def test_invalidate_makes_unseal_raise_not_found():
    vault = _fresh_vault()
    handle = _seal_simple(vault)
    vault.invalidate(handle.id)
    with pytest.raises(HandleNotFoundError):
        vault.unseal(handle.id, requesting_principal=OWNER)


def test_invalidate_makes_get_safe_view_raise_not_found():
    vault = _fresh_vault()
    handle = _seal_simple(vault)
    vault.invalidate(handle.id)
    with pytest.raises(HandleNotFoundError):
        vault.get_safe_view(handle.id)


def test_invalidate_unknown_handle_is_idempotent():
    vault = _fresh_vault()
    # Should not raise
    vault.invalidate("hdl_doesnotexist")


# ---------------------------------------------------------------------------
# HandleVault.get_safe_view()
# ---------------------------------------------------------------------------


def test_get_safe_view_returns_safe_view_without_acl():
    vault = _fresh_vault()
    handle = _seal_simple(vault)
    # Any caller can get the safe view — it's intentionally non-sensitive
    assert vault.get_safe_view(handle.id) == "A person record with name and SSN"


def test_get_safe_view_unknown_handle_raises_not_found():
    vault = _fresh_vault()
    with pytest.raises(HandleNotFoundError):
        vault.get_safe_view("hdl_doesnotexist")


def test_get_safe_view_expired_handle_raises_not_found_or_expired():
    vault = _fresh_vault()
    handle = vault.seal(
        data="gone",
        owner_principal=OWNER,
        safe_view="short-lived",
        ttl_seconds=0,
    )
    time.sleep(0.05)
    with pytest.raises((HandleNotFoundError, HandleExpiredError)):
        vault.get_safe_view(handle.id)


# ---------------------------------------------------------------------------
# Custom CacheProvider injection
# ---------------------------------------------------------------------------


def test_handle_vault_accepts_custom_cache_provider():
    """HandleVault should work with any CacheProvider implementation."""
    from kest.core.framework.cache import SimpleCache

    cache = SimpleCache()
    vault = HandleVault(cache=cache)
    handle = _seal_simple(vault)
    assert (
        vault.unseal(handle.id, requesting_principal=OWNER)
        == "John Doe, SSN: 123-45-6789"
    )


# ---------------------------------------------------------------------------
# Multiple independent vaults don't share state
# ---------------------------------------------------------------------------


def test_separate_vaults_are_isolated():
    vault_a = HandleVault()
    vault_b = HandleVault()
    handle = _seal_simple(vault_a)
    with pytest.raises(HandleNotFoundError):
        vault_b.unseal(handle.id, requesting_principal=OWNER)


# ---------------------------------------------------------------------------
# Public API importability from kest.core
# ---------------------------------------------------------------------------


def test_vault_symbols_importable_from_kest_core():
    from kest.core import (  # noqa: F401
        HandleAccessDeniedError,
        HandleExpiredError,
        HandleNotFoundError,
        HandleVault,
        OpaqueHandle,
    )

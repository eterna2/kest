"""
TDD tests for classification-based automatic taint tagging (Issue #80).

Coverage:
- classification param on @kest_verified defaults to "system"
- CLASSIFICATION_TAINT_MAP defaults (data, critic, sanitizer)
- Auto-taints merged into signed KestEntry.taints
- Unknown classification → no auto-taints
- Manual added_taints + auto-taints are both included
- configure(classification_taint_map=...) overrides the default map globally
- configure(clear=True) resets the map to defaults
- Async path: auto-taints applied correctly
"""

import asyncio

from kest.core import (
    MockIdentityProvider,
    MockPolicyEngine,
    configure,
    kest_verified,
)
from kest.core.framework.decorators import (
    DEFAULT_CLASSIFICATION_TAINT_MAP,
    invalidate_policy_cache,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _configure_fresh(classification_taint_map=None):
    kwargs = dict(
        engine=MockPolicyEngine(allow_all=True),
        identity=MockIdentityProvider(),
        clear=True,
    )
    if classification_taint_map is not None:
        kwargs["classification_taint_map"] = classification_taint_map
    configure(**kwargs)
    invalidate_policy_cache()


def _capture_taints(fn):
    """Call @kest_verified-decorated fn and return the taints from the signed KestEntry."""
    import kest.core._core as _core_mod
    import kest.core.framework.decorators as dec_mod

    captured_entries = []
    original_sign = _core_mod.sign_entry

    def capturing_sign(entry, identity):
        captured_entries.append(entry)
        return original_sign(entry, identity)

    _core_mod.sign_entry = capturing_sign
    dec_mod.sign_entry = capturing_sign
    try:
        fn()
    finally:
        _core_mod.sign_entry = original_sign
        dec_mod.sign_entry = original_sign

    assert captured_entries, "Expected at least one sign call"
    return captured_entries[0].taints


# ---------------------------------------------------------------------------
# DEFAULT_CLASSIFICATION_TAINT_MAP
# ---------------------------------------------------------------------------


def test_default_map_is_exported():
    """DEFAULT_CLASSIFICATION_TAINT_MAP must be importable from kest.core.framework.decorators."""
    assert isinstance(DEFAULT_CLASSIFICATION_TAINT_MAP, dict)


def test_default_map_has_data_entry():
    assert "data" in DEFAULT_CLASSIFICATION_TAINT_MAP
    assert "contains_data" in DEFAULT_CLASSIFICATION_TAINT_MAP["data"]


def test_default_map_has_critic_entry():
    assert "critic" in DEFAULT_CLASSIFICATION_TAINT_MAP
    assert "requires_review" in DEFAULT_CLASSIFICATION_TAINT_MAP["critic"]


def test_default_map_has_sanitizer_entry():
    assert "sanitizer" in DEFAULT_CLASSIFICATION_TAINT_MAP
    assert "sanitized" in DEFAULT_CLASSIFICATION_TAINT_MAP["sanitizer"]


# ---------------------------------------------------------------------------
# classification param — default behaviour
# ---------------------------------------------------------------------------


def test_default_classification_is_system_no_auto_taints():
    """Default classification='system' should not add any auto-taints."""
    _configure_fresh()

    @kest_verified(policy="test")
    def op():
        return "result"

    taints = _capture_taints(op)
    assert "contains_data" not in taints
    assert "requires_review" not in taints
    assert "sanitized" not in taints


def test_classification_system_explicit_no_auto_taints():
    """Explicitly passing classification='system' also adds no auto-taints."""
    _configure_fresh()

    @kest_verified(policy="test", classification="system")
    def op():
        return "result"

    taints = _capture_taints(op)
    assert "contains_data" not in taints


def test_classification_data_adds_contains_data_taint():
    """classification='data' should auto-add 'contains_data' taint."""
    _configure_fresh()

    @kest_verified(policy="test", classification="data")
    def op():
        return "result"

    taints = _capture_taints(op)
    assert "contains_data" in taints


def test_classification_critic_adds_requires_review_taint():
    """classification='critic' should auto-add 'requires_review' taint."""
    _configure_fresh()

    @kest_verified(policy="test", classification="critic")
    def op():
        return "result"

    taints = _capture_taints(op)
    assert "requires_review" in taints


def test_classification_sanitizer_adds_sanitized_taint():
    """classification='sanitizer' should auto-add 'sanitized' taint."""
    _configure_fresh()

    @kest_verified(policy="test", classification="sanitizer")
    def op():
        return "result"

    taints = _capture_taints(op)
    assert "sanitized" in taints


def test_unmapped_classification_adds_no_auto_taints():
    """A valid classification not in the map silently adds no auto-taints."""
    _configure_fresh()

    @kest_verified(policy="test", classification="snapshot")
    def op():
        return "result"

    taints = _capture_taints(op)
    # 'snapshot' is not in DEFAULT_CLASSIFICATION_TAINT_MAP, so no auto-taints
    assert "contains_data" not in taints
    assert "requires_review" not in taints


def test_manual_added_taints_and_auto_taints_both_present():
    """Manually specified added_taints and auto-taints from classification must both appear."""
    _configure_fresh()

    @kest_verified(
        policy="test", classification="data", added_taints=["my_custom_taint"]
    )
    def op():
        return "result"

    taints = _capture_taints(op)
    assert "contains_data" in taints
    assert "my_custom_taint" in taints


# ---------------------------------------------------------------------------
# configure() override
# ---------------------------------------------------------------------------


def test_configure_overrides_classification_taint_map():
    """configure(classification_taint_map=...) should replace the active map."""
    custom_map = {"data": ["pii_detected", "needs_encryption"]}
    _configure_fresh(classification_taint_map=custom_map)

    @kest_verified(policy="test", classification="data")
    def op():
        return "result"

    taints = _capture_taints(op)
    assert "pii_detected" in taints
    assert "needs_encryption" in taints
    # Default taint for 'data' should NOT be present since map was replaced
    assert "contains_data" not in taints


def test_configure_clear_resets_to_default_map():
    """configure(clear=True) should reset the classification_taint_map to defaults."""
    custom_map = {"data": ["custom_taint_only"]}
    configure(classification_taint_map=custom_map)

    # Now clear — should revert to defaults
    _configure_fresh()  # calls configure(clear=True)

    @kest_verified(policy="test", classification="data")
    def op():
        return "result"

    taints = _capture_taints(op)
    assert "contains_data" in taints
    assert "custom_taint_only" not in taints


# ---------------------------------------------------------------------------
# Async path
# ---------------------------------------------------------------------------


def test_async_classification_data_adds_taint():
    """Async @kest_verified also applies auto-taints from classification."""
    import kest.core._core as _core_mod
    import kest.core.framework.decorators as dec_mod

    _configure_fresh()
    captured_entries = []
    original_sign = _core_mod.sign_entry

    def capturing_sign(entry, identity):
        captured_entries.append(entry)
        return original_sign(entry, identity)

    _core_mod.sign_entry = capturing_sign
    dec_mod.sign_entry = capturing_sign

    try:

        @kest_verified(policy="test", classification="data")
        async def async_op():
            return "ok"

        asyncio.run(async_op())
    finally:
        _core_mod.sign_entry = original_sign
        dec_mod.sign_entry = original_sign

    assert captured_entries, "Expected at least one sign call"
    assert "contains_data" in captured_entries[0].taints


# ---------------------------------------------------------------------------
# Public API export
# ---------------------------------------------------------------------------


def test_configure_accepts_classification_taint_map():
    """configure() must accept classification_taint_map without error."""
    configure(classification_taint_map={"data": ["test_taint"]})
    # Reset to defaults for subsequent tests
    configure(
        clear=True,
        engine=MockPolicyEngine(allow_all=True),
        identity=MockIdentityProvider(),
    )

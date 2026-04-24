"""
TDD tests for resource_id and resource_attr parameters on @kest_verified.

Spec reference: SPEC-v0.3.0 §2.7 F-IC-01, F-IC-02, F-IC-04 and §9.2.

These tests MUST BE WRITTEN BEFORE the implementation and must initially fail (RED).

All tests use MockPolicyEngine with an evaluate() override that captures the
context dict passed during policy evaluation, allowing assertions on the
structure of ctx_to_eval["object"] without requiring a live policy sidecar.
"""

import asyncio

from kest.core import (
    MockIdentityProvider,
    MockPolicyEngine,
    configure,
    kest_verified,
)
from kest.core.framework.decorators import invalidate_policy_cache

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _CapturingEngine(MockPolicyEngine):
    """MockPolicyEngine that records every context dict passed to evaluate()."""

    def __init__(self, allow_all: bool = True):
        super().__init__(allow_all=allow_all)
        self.captured_contexts: list[dict] = []

    def evaluate(self, entry_id, policy_names, context):
        self.captured_contexts.append(context)
        return self.allow_all  # type: ignore[attr-defined]


def _fresh_engine() -> _CapturingEngine:
    engine = _CapturingEngine(allow_all=True)
    configure(engine=engine, identity=MockIdentityProvider(), clear=True)
    invalidate_policy_cache()
    return engine


# ---------------------------------------------------------------------------
# Static resource_id tests
# ---------------------------------------------------------------------------


def test_resource_id_static_forwarded_to_policy_context():
    """resource_id='res-1' must appear as context['object']['id'] == 'res-1'."""
    engine = _fresh_engine()

    @kest_verified(policy="test", resource_id="res-1")
    def op():
        return "ok"

    result = op()
    assert result == "ok"
    assert len(engine.captured_contexts) == 1
    ctx = engine.captured_contexts[0]
    assert ctx["object"]["id"] == "res-1"


def test_resource_id_none_sets_null_in_object_id():
    """When resource_id=None, context['object']['id'] must be None."""
    engine = _fresh_engine()

    @kest_verified(policy="test", resource_id=None)
    def op():
        return "ok"

    op()
    ctx = engine.captured_contexts[0]
    assert ctx["object"]["id"] is None


# ---------------------------------------------------------------------------
# resource_id resolver tests
# ---------------------------------------------------------------------------


def test_resource_id_resolver_called_with_invocation_args():
    """A callable resource_id receives the decorated function's arguments."""
    engine = _fresh_engine()

    @kest_verified(policy="test", resource_id=lambda doc_id, **kw: doc_id)
    def op(doc_id: str):
        return doc_id

    op("doc-42")
    ctx = engine.captured_contexts[0]
    assert ctx["object"]["id"] == "doc-42"


def test_resource_id_resolver_with_kwargs():
    """A callable resource_id can extract values from keyword arguments."""
    engine = _fresh_engine()

    @kest_verified(
        policy="test", resource_id=lambda *args, **kwargs: kwargs.get("resource")
    )
    def op(resource: str = ""):
        return resource

    op(resource="kw-res")
    ctx = engine.captured_contexts[0]
    assert ctx["object"]["id"] == "kw-res"


# ---------------------------------------------------------------------------
# Static resource_attr tests
# ---------------------------------------------------------------------------


def test_resource_attr_static_forwarded_to_policy_context():
    """Static resource_attr dict must appear as context['object']['attributes']."""
    engine = _fresh_engine()
    attrs = {"dept": "engineering", "classification": "internal"}

    @kest_verified(policy="test", resource_attr=attrs)
    def op():
        return "ok"

    op()
    ctx = engine.captured_contexts[0]
    assert ctx["object"]["attributes"] == attrs


def test_resource_attr_none_sets_empty_dict_in_object_attributes():
    """When resource_attr=None, context['object']['attributes'] must be {}."""
    engine = _fresh_engine()

    @kest_verified(policy="test", resource_attr=None)
    def op():
        return "ok"

    op()
    ctx = engine.captured_contexts[0]
    assert ctx["object"]["attributes"] == {}


# ---------------------------------------------------------------------------
# resource_attr resolver tests
# ---------------------------------------------------------------------------


def test_resource_attr_resolver_called_with_invocation_args():
    """A callable resource_attr receives the decorated function's arguments."""
    engine = _fresh_engine()

    def resolve_attrs(category: str, **kw):
        return {"category": category, "sensitive": False}

    @kest_verified(policy="test", resource_attr=resolve_attrs)
    def op(category: str):
        return category

    op("legal")
    ctx = engine.captured_contexts[0]
    assert ctx["object"]["attributes"] == {"category": "legal", "sensitive": False}


# ---------------------------------------------------------------------------
# KestEntry label embedding (F-IC-04)
# ---------------------------------------------------------------------------


def test_resource_attr_embedded_in_kest_entry_labels():
    """Resolved resource_attr must be serialized into labels['kest.resource_attr']."""
    import json as _json

    _fresh_engine()
    captured_entries: list = []

    # Patch sign_entry to capture the KestEntry before signing
    import kest.core._core as _core_mod

    original_sign = _core_mod.sign_entry

    def capturing_sign(entry, identity):
        captured_entries.append(entry)
        return original_sign(entry, identity)

    _core_mod.sign_entry = capturing_sign

    import kest.core as kest_core_mod

    kest_core_mod.sign_entry = capturing_sign

    import kest.core.framework.decorators as dec_mod

    dec_mod.sign_entry = capturing_sign

    try:
        attrs = {"dept": "finance"}

        @kest_verified(policy="test", resource_attr=attrs)
        def op():
            return "ok"

        op()
    finally:
        _core_mod.sign_entry = original_sign
        kest_core_mod.sign_entry = original_sign
        dec_mod.sign_entry = original_sign

    assert len(captured_entries) >= 1
    entry = captured_entries[0]
    assert "kest.resource_attr" in entry.labels
    assert _json.loads(entry.labels["kest.resource_attr"]) == attrs


def test_resource_attr_not_in_labels_when_none():
    """When resource_attr=None, labels must NOT contain 'kest.resource_attr'."""
    import kest.core._core as _core_mod

    _fresh_engine()
    captured_entries: list = []
    original_sign = _core_mod.sign_entry

    def capturing_sign(entry, identity):
        captured_entries.append(entry)
        return original_sign(entry, identity)

    _core_mod.sign_entry = capturing_sign

    import kest.core as kest_core_mod

    kest_core_mod.sign_entry = capturing_sign

    import kest.core.framework.decorators as dec_mod

    dec_mod.sign_entry = capturing_sign

    try:

        @kest_verified(policy="test", resource_attr=None)
        def op():
            return "ok"

        op()
    finally:
        _core_mod.sign_entry = original_sign
        kest_core_mod.sign_entry = original_sign
        dec_mod.sign_entry = original_sign

    assert len(captured_entries) >= 1
    entry = captured_entries[0]
    assert "kest.resource_attr" not in entry.labels


# ---------------------------------------------------------------------------
# Cache isolation tests (security-critical)
# ---------------------------------------------------------------------------


def test_cache_miss_on_different_resource_ids():
    """Calls with different resource_id values must each trigger engine.evaluate()."""
    engine = _CapturingEngine(allow_all=True)
    configure(engine=engine, identity=MockIdentityProvider(), clear=True)
    invalidate_policy_cache()

    @kest_verified(policy="test", resource_id=lambda doc_id, **kw: doc_id)
    def op(doc_id: str):
        return doc_id

    op("res-A")
    op("res-B")

    # Must have triggered evaluate() twice — one per resource
    assert len(engine.captured_contexts) == 2
    resource_ids = [c["object"]["id"] for c in engine.captured_contexts]
    assert "res-A" in resource_ids
    assert "res-B" in resource_ids


# ---------------------------------------------------------------------------
# Async path
# ---------------------------------------------------------------------------


def test_async_resource_id_forwarded():
    """Async decorated function with resource_id must resolve and forward correctly."""
    engine = _fresh_engine()

    @kest_verified(policy="test", resource_id="async-res-99")
    async def async_op():
        return "ok"

    result = asyncio.run(async_op())
    assert result == "ok"
    assert len(engine.captured_contexts) >= 1
    ctx = engine.captured_contexts[0]
    assert ctx["object"]["id"] == "async-res-99"

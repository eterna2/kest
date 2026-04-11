"""
Tests for _get_baggage() in decorators.py.

Covers:
  R-02 — Core library baggage reads must go through OTel context exclusively.
          No coupling to _LAB_BAGGAGE_STORE or any global dict.
"""

import opentelemetry.context as otel_context
from opentelemetry import baggage

from kest.core.decorators import _get_baggage
from kest.core.ext import _LAB_BAGGAGE_STORE, _LAB_LOCK

# ---------------------------------------------------------------------------
# R-02 tests
# ---------------------------------------------------------------------------


def test_get_baggage_reads_from_otel_context():
    """
    R-02: _get_baggage("kest.user") must return the value placed in OTel baggage
    context via baggage.set_baggage() — i.e., it routes through OTel, not a dict.
    """
    ctx = baggage.set_baggage("kest.user", "alice")
    token = otel_context.attach(ctx)
    try:
        assert _get_baggage("kest.user") == "alice"
    finally:
        otel_context.detach(token)


def test_get_baggage_returns_none_without_context():
    """
    R-02: When no baggage is attached to the current OTel context,
    _get_baggage() must return None — not raise, not return a stale value.
    """
    # Ensure a clean context (no token from any parent fixture)
    clean_ctx = otel_context.get_current()
    token = otel_context.attach(clean_ctx)
    try:
        result = _get_baggage("kest.user")
        assert result is None, f"Expected None without context, got {result!r}"
    finally:
        otel_context.detach(token)


def test_get_baggage_ignores_lab_store():
    """
    R-02: Placing a value into _LAB_BAGGAGE_STORE (the ext.py global dict used
    by the lab infrastructure) must NOT influence _get_baggage().

    This is the regression guard for the R-02 fix: core reads must not depend
    on any global state outside the OTel context.
    """
    from opentelemetry import trace

    tracer = trace.get_tracer("test")
    with tracer.start_as_current_span("test-span") as span:
        trace_id = span.get_span_context().trace_id
        # Inject a value directly into the lab store
        with _LAB_LOCK:
            _LAB_BAGGAGE_STORE[trace_id] = {"kest.user": "injected-from-lab-store"}

        try:
            # _get_baggage must NOT pick up "injected-from-lab-store"
            result = _get_baggage("kest.user")
            assert result is None, (
                f"_get_baggage() must not read from _LAB_BAGGAGE_STORE; "
                f"got {result!r} instead of None (R-02 regression)"
            )
        finally:
            with _LAB_LOCK:
                _LAB_BAGGAGE_STORE.pop(trace_id, None)

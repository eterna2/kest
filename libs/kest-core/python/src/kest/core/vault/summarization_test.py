"""
TDD tests for the SummarizationProvider interface and concrete implementations (Issue #82).

Covers:
- SafeView dataclass: required fields, immutability, optional fields
- SummarizationProvider ABC: cannot be instantiated directly
- SchemaBasedSummarizer: dict introspection, pandas DataFrame, list-of-dicts
- TruncatingSummarizer: truncation at N chars, passthrough for short strings
- AggregationSummarizer: count/sum/min/max for numeric sequences and dicts
- HandleVault.seal() auto-summarization when a SummarizationProvider is injected
- Public API importability from kest.core.vault
"""

from __future__ import annotations

from typing import Any

import pytest

from kest.core.vault.summarization import (
    AggregationSummarizer,
    SafeView,
    SchemaBasedSummarizer,
    SummarizationProvider,
    TruncatingSummarizer,
)
from kest.core.vault.vault import HandleVault

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

OWNER = "spiffe://example.com/service-a"


# ---------------------------------------------------------------------------
# SafeView dataclass
# ---------------------------------------------------------------------------


def test_safe_view_required_fields():
    sv = SafeView(summary="A table of 5,000 transactions")
    assert sv.summary == "A table of 5,000 transactions"


def test_safe_view_optional_fields_default_none():
    sv = SafeView(summary="test")
    assert sv.data_type is None
    assert sv.row_count is None
    assert sv.schema is None


def test_safe_view_with_all_fields():
    sv = SafeView(
        summary="5,000 transactions; Total: $1.2M",
        data_type="tabular",
        row_count=5000,
        schema={"id": "int", "amount": "float", "date": "datetime"},
    )
    assert sv.data_type == "tabular"
    assert sv.row_count == 5000
    assert sv.schema == {"id": "int", "amount": "float", "date": "datetime"}


def test_safe_view_is_frozen():
    sv = SafeView(summary="immutable")
    with pytest.raises((AttributeError, TypeError)):
        sv.summary = "mutated"  # type: ignore[misc]


def test_safe_view_str_returns_summary():
    """str(safe_view) should return the summary text for easy embedding."""
    sv = SafeView(summary="Q3 total expenditure")
    assert str(sv) == "Q3 total expenditure"


# ---------------------------------------------------------------------------
# SummarizationProvider ABC
# ---------------------------------------------------------------------------


def test_summarization_provider_is_abstract():
    """Cannot instantiate the ABC directly."""
    with pytest.raises(TypeError):
        SummarizationProvider()  # type: ignore[abstract]


def test_summarization_provider_subclass_must_implement_summarize():
    """A subclass that does not implement summarize() raises TypeError."""

    class BadProvider(SummarizationProvider):
        pass  # missing summarize()

    with pytest.raises(TypeError):
        BadProvider()  # type: ignore[abstract]


def test_summarization_provider_concrete_subclass_works():
    class EchoProvider(SummarizationProvider):
        def summarize(self, data: Any, context: dict) -> SafeView:
            return SafeView(summary=str(data))

    p = EchoProvider()
    sv = p.summarize("hello", {})
    assert sv.summary == "hello"


# ---------------------------------------------------------------------------
# SchemaBasedSummarizer
# ---------------------------------------------------------------------------


def test_schema_based_summarizer_with_dict():
    s = SchemaBasedSummarizer()
    data = {"name": "Alice", "age": 30, "active": True}
    sv = s.summarize(data, {})
    assert isinstance(sv, SafeView)
    assert sv.data_type == "object"
    # Schema keys must appear
    assert "name" in (sv.schema or {})
    assert "age" in (sv.schema or {})
    assert "active" in (sv.schema or {})


def test_schema_based_summarizer_with_list_of_dicts():
    s = SchemaBasedSummarizer()
    data = [{"id": 1, "val": 10}, {"id": 2, "val": 20}, {"id": 3, "val": 30}]
    sv = s.summarize(data, {})
    assert sv.data_type == "tabular"
    assert sv.row_count == 3
    schema = sv.schema or {}
    assert "id" in schema
    assert "val" in schema


def test_schema_based_summarizer_with_empty_list():
    s = SchemaBasedSummarizer()
    sv = s.summarize([], {})
    assert sv.row_count == 0
    assert "empty" in sv.summary.lower() or sv.row_count == 0


def test_schema_based_summarizer_with_string():
    s = SchemaBasedSummarizer()
    sv = s.summarize("some raw text", {})
    assert sv.data_type == "text"
    assert isinstance(sv.summary, str)


def test_schema_based_summarizer_with_int():
    s = SchemaBasedSummarizer()
    sv = s.summarize(42, {})
    assert sv.data_type == "scalar"


def test_schema_based_summarizer_passes_context():
    """The context dict is accepted without error (can be empty or populated)."""
    s = SchemaBasedSummarizer()
    sv = s.summarize({"x": 1}, {"hint": "financial"})
    assert isinstance(sv, SafeView)


# ---------------------------------------------------------------------------
# TruncatingSummarizer
# ---------------------------------------------------------------------------


def test_truncating_summarizer_short_string_passthrough():
    s = TruncatingSummarizer(max_chars=100)
    sv = s.summarize("hello world", {})
    assert sv.summary == "hello world"
    assert "[TRUNCATED]" not in sv.summary


def test_truncating_summarizer_long_string_truncated():
    s = TruncatingSummarizer(max_chars=10)
    sv = s.summarize("A" * 50, {})
    assert "[TRUNCATED]" in sv.summary
    assert len(sv.summary) <= 10 + len(" [TRUNCATED]")


def test_truncating_summarizer_non_string_coerced():
    s = TruncatingSummarizer(max_chars=20)
    sv = s.summarize({"key": "value"}, {})
    assert isinstance(sv.summary, str)


def test_truncating_summarizer_default_max_chars():
    """Default max_chars is 200 (a reasonable default)."""
    s = TruncatingSummarizer()
    long_text = "x" * 500
    sv = s.summarize(long_text, {})
    assert "[TRUNCATED]" in sv.summary


def test_truncating_summarizer_data_type_is_text():
    s = TruncatingSummarizer(max_chars=100)
    sv = s.summarize("hi", {})
    assert sv.data_type == "text"


def test_truncating_summarizer_exactly_at_limit():
    s = TruncatingSummarizer(max_chars=5)
    sv = s.summarize("12345", {})
    # Exactly at limit — should NOT be truncated
    assert "[TRUNCATED]" not in sv.summary


# ---------------------------------------------------------------------------
# AggregationSummarizer
# ---------------------------------------------------------------------------


def test_aggregation_summarizer_list_of_numbers():
    s = AggregationSummarizer()
    data = [10, 20, 30, 40, 50]
    sv = s.summarize(data, {})
    assert sv.data_type == "numeric_sequence"
    assert sv.row_count == 5
    assert "10" in sv.summary  # min
    assert "50" in sv.summary  # max
    assert "150" in sv.summary  # sum


def test_aggregation_summarizer_list_of_numeric_strings_raises_or_handles():
    """Non-numeric sequences should still return a valid SafeView."""
    s = AggregationSummarizer()
    sv = s.summarize(["a", "b", "c"], {})
    assert isinstance(sv, SafeView)


def test_aggregation_summarizer_dict_of_numeric_values():
    s = AggregationSummarizer()
    data = {"revenue": 1000, "cost": 400, "profit": 600}
    sv = s.summarize(data, {})
    assert sv.data_type == "key_value_numeric"
    assert "1000" in sv.summary or "600" in sv.summary


def test_aggregation_summarizer_empty_list():
    s = AggregationSummarizer()
    sv = s.summarize([], {})
    assert sv.row_count == 0


def test_aggregation_summarizer_non_numeric_dict():
    s = AggregationSummarizer()
    sv = s.summarize({"name": "Alice", "city": "Paris"}, {})
    assert isinstance(sv, SafeView)


def test_aggregation_summarizer_single_value():
    s = AggregationSummarizer()
    sv = s.summarize([42], {})
    assert sv.row_count == 1
    assert "42" in sv.summary


# ---------------------------------------------------------------------------
# HandleVault integration — auto-summarize on seal()
# ---------------------------------------------------------------------------


def test_handle_vault_seal_with_summarizer_sets_safe_view():
    """When a summarizer is passed to seal(), the safe_view is auto-generated."""
    summarizer = TruncatingSummarizer(max_chars=50)
    vault = HandleVault()
    data = "John Doe, SSN: 123-45-6789"
    handle = vault.seal(
        data=data,
        owner_principal=OWNER,
        summarizer=summarizer,
    )
    # safe_view should be auto-generated from the summarizer
    assert handle.safe_view is not None
    assert len(handle.safe_view) > 0


def test_handle_vault_seal_summarizer_overrides_explicit_safe_view():
    """When both safe_view and summarizer are given, summarizer wins."""
    summarizer = SchemaBasedSummarizer()
    vault = HandleVault()
    data = {"name": "Bob", "score": 99}
    handle = vault.seal(
        data=data,
        owner_principal=OWNER,
        safe_view="manual override",
        summarizer=summarizer,
    )
    # The summarizer's output replaces the manual safe_view
    assert handle.safe_view != "manual override"


def test_handle_vault_seal_without_summarizer_uses_safe_view():
    """Existing seal() without summarizer still works unchanged."""
    vault = HandleVault()
    handle = vault.seal(
        data="raw payload",
        owner_principal=OWNER,
        safe_view="explicit description",
    )
    assert handle.safe_view == "explicit description"


# ---------------------------------------------------------------------------
# Public API importability from kest.core.vault
# ---------------------------------------------------------------------------


def test_summarization_symbols_importable_from_vault():
    from kest.core.vault import (  # noqa: F401
        AggregationSummarizer,
        SafeView,
        SchemaBasedSummarizer,
        SummarizationProvider,
        TruncatingSummarizer,
    )

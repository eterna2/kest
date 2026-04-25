"""
SummarizationProvider: abstraction for producing non-sensitive safe views of raw data.

When sensitive data is sealed into a HandleVault, the LLM still needs to reason about
*what* the data represents without seeing individual records or PII. A
SummarizationProvider generates a SafeView — a metadata-rich, non-sensitive textual
summary — that is stored on the OpaqueHandle and safe to include in LLM prompts.

Design decisions:
- ``SafeView`` is an immutable dataclass. Its ``summary`` field is the primary textual
  description; optional fields (data_type, row_count, schema) carry structured metadata.
- ``SummarizationProvider`` is a minimal ABC: one required method ``summarize(data,
  context) → SafeView``. The ``context`` dict allows callers to pass hints (e.g.
  classification, field-level annotations) without coupling the interface to any schema.
- The three bundled implementations cover the most common summarization patterns:
  schema introspection, truncation, and statistical aggregation.
- pandas / numpy are NOT required dependencies. ``SchemaBasedSummarizer`` introspects
  DataFrames via duck-typing (checks for ``.dtypes`` / ``.shape``) so the vault stays
  importable without heavyweight ML libraries.

Public API::

    from kest.core.vault.summarization import (
        SafeView,
        SummarizationProvider,
        SchemaBasedSummarizer,
        TruncatingSummarizer,
        AggregationSummarizer,
    )
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional

# ---------------------------------------------------------------------------
# SafeView — immutable result container
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SafeView:
    """
    A non-sensitive, human-readable summary of sealed data.

    Designed to be embedded directly in LLM prompts, audit logs, and API
    responses without exposing raw records or PII.

    Attributes:
        summary: The primary textual description of the data. Must be safe for
            LLM consumption (no raw PII, no individual records).
        data_type: Optional categorical label for the data's structure, e.g.
            ``"tabular"``, ``"text"``, ``"numeric_sequence"``, ``"object"``,
            ``"scalar"``, ``"key_value_numeric"``.
        row_count: Optional count of rows or items in the dataset.
        schema: Optional mapping of field name → type descriptor, e.g.
            ``{"id": "int", "amount": "float"}``.
    """

    summary: str
    data_type: Optional[str] = field(default=None)
    row_count: Optional[int] = field(default=None)
    schema: Optional[dict[str, str]] = field(default=None)

    def __str__(self) -> str:
        """Return the summary text for easy embedding in prompts."""
        return self.summary


# ---------------------------------------------------------------------------
# SummarizationProvider — abstract base class
# ---------------------------------------------------------------------------


class SummarizationProvider(ABC):
    """
    Abstract interface for generating non-sensitive safe views of raw data.

    Implementors receive the raw data object and an optional context dict,
    and must return a :class:`SafeView` that describes the data without
    exposing sensitive content.

    Example::

        class MyProvider(SummarizationProvider):
            def summarize(self, data: Any, context: dict) -> SafeView:
                return SafeView(summary=f"Object of type {type(data).__name__}")
    """

    @abstractmethod
    def summarize(self, data: Any, context: dict) -> SafeView:
        """
        Produce a non-sensitive SafeView for *data*.

        Args:
            data: The raw data to summarize. May be any Python object.
            context: Caller-supplied hints (e.g. classification tags, field
                annotations). Implementors MAY use or ignore this dict.

        Returns:
            A :class:`SafeView` describing *data* without exposing raw content.
        """


# ---------------------------------------------------------------------------
# SchemaBasedSummarizer — structural / schema introspection
# ---------------------------------------------------------------------------


class SchemaBasedSummarizer(SummarizationProvider):
    """
    Summarizes data by describing its structure, schema, and basic statistics.

    Understands the following data shapes:
    - ``dict``               → ``data_type="object"``; keys and value types in schema.
    - ``list[dict]``         → ``data_type="tabular"``; column names and types from first row.
    - ``list`` (empty)       → ``data_type="tabular"``; row_count=0.
    - ``list`` (non-dict)    → ``data_type="sequence"``; element type from first item.
    - ``str``                → ``data_type="text"``; character count in summary.
    - scalar (int/float/bool)→ ``data_type="scalar"``; value in summary.
    - pandas DataFrame       → ``data_type="tabular"``; uses ``.dtypes`` + ``.shape``.
    - anything else          → ``data_type="unknown"``.

    pandas is NOT a required dependency. DataFrame support is activated via
    duck-typing so this class works with or without pandas installed.
    """

    def summarize(self, data: Any, context: dict) -> SafeView:  # noqa: ARG002
        # --- pandas DataFrame (duck-typed, no import required) ---
        if hasattr(data, "dtypes") and hasattr(data, "shape"):
            return self._summarize_dataframe(data)

        if isinstance(data, dict):
            return self._summarize_dict(data)

        if isinstance(data, list):
            return self._summarize_list(data)

        if isinstance(data, str):
            return SafeView(
                summary=f"Text value; {len(data)} characters.",
                data_type="text",
            )

        if isinstance(data, (int, float, bool)):
            return SafeView(
                summary=f"Scalar value of type {type(data).__name__}.",
                data_type="scalar",
            )

        return SafeView(
            summary=f"Data of type '{type(data).__name__}'.",
            data_type="unknown",
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _summarize_dict(data: dict) -> SafeView:
        schema = {k: type(v).__name__ for k, v in data.items()}
        key_list = ", ".join(list(schema.keys())[:10])
        suffix = "" if len(schema) <= 10 else f" … (+{len(schema) - 10} more)"
        summary = f"Object with {len(schema)} field(s): {key_list}{suffix}."
        return SafeView(summary=summary, data_type="object", schema=schema)

    @staticmethod
    def _summarize_list(data: list) -> SafeView:
        n = len(data)
        if n == 0:
            return SafeView(
                summary="Empty sequence (0 items).",
                data_type="tabular",
                row_count=0,
            )

        first = data[0]
        if isinstance(first, dict):
            # List-of-dicts → tabular
            schema = {k: type(v).__name__ for k, v in first.items()}
            col_list = ", ".join(list(schema.keys())[:8])
            suffix = "" if len(schema) <= 8 else f" … (+{len(schema) - 8} more)"
            summary = f"Tabular data: {n} row(s); columns: {col_list}{suffix}."
            return SafeView(
                summary=summary,
                data_type="tabular",
                row_count=n,
                schema=schema,
            )

        elem_type = type(first).__name__
        return SafeView(
            summary=f"Sequence of {n} {elem_type}(s).",
            data_type="sequence",
            row_count=n,
        )

    @staticmethod
    def _summarize_dataframe(df: Any) -> SafeView:
        """Summarize a pandas DataFrame via duck-typing."""
        rows, cols = df.shape
        schema = {str(col): str(dtype) for col, dtype in df.dtypes.items()}
        col_list = ", ".join(list(schema.keys())[:8])
        suffix = "" if cols <= 8 else f" … (+{cols - 8} more)"
        summary = (
            f"DataFrame: {rows} row(s) × {cols} column(s); columns: {col_list}{suffix}."
        )
        return SafeView(
            summary=summary,
            data_type="tabular",
            row_count=rows,
            schema=schema,
        )


# ---------------------------------------------------------------------------
# TruncatingSummarizer — first-N-chars with [TRUNCATED] marker
# ---------------------------------------------------------------------------


class TruncatingSummarizer(SummarizationProvider):
    """
    Returns the first *max_chars* characters of a string representation of *data*.

    If the string representation exceeds *max_chars*, the summary is truncated
    and suffixed with ``" [TRUNCATED]"`` so consumers know data was elided.

    Args:
        max_chars: Maximum number of characters before truncation (default: 200).
    """

    def __init__(self, max_chars: int = 200) -> None:
        self._max_chars = max_chars

    def summarize(self, data: Any, context: dict) -> SafeView:  # noqa: ARG002
        text = data if isinstance(data, str) else str(data)
        if len(text) > self._max_chars:
            summary = text[: self._max_chars] + " [TRUNCATED]"
        else:
            summary = text
        return SafeView(summary=summary, data_type="text")


# ---------------------------------------------------------------------------
# AggregationSummarizer — count / sum / min / max
# ---------------------------------------------------------------------------


class AggregationSummarizer(SummarizationProvider):
    """
    Computes statistical aggregates (count, sum, min, max) for numeric data.

    Understands:
    - ``list[int | float]``  → ``data_type="numeric_sequence"``
    - ``dict[str, int | float]`` → ``data_type="key_value_numeric"``
    - empty sequences        → row_count=0, no arithmetic
    - non-numeric data       → falls back to a safe type/count summary
    """

    def summarize(self, data: Any, context: dict) -> SafeView:  # noqa: ARG002
        if isinstance(data, list):
            return self._summarize_list(data)
        if isinstance(data, dict):
            return self._summarize_dict(data)
        return SafeView(
            summary=f"Data of type '{type(data).__name__}'.",
            data_type="unknown",
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _summarize_list(data: list) -> SafeView:
        n = len(data)
        if n == 0:
            return SafeView(
                summary="Empty sequence (0 items).",
                data_type="numeric_sequence",
                row_count=0,
            )

        numeric = [
            v for v in data if isinstance(v, (int, float)) and not isinstance(v, bool)
        ]
        if not numeric:
            return SafeView(
                summary=f"Sequence of {n} non-numeric item(s) (type: {type(data[0]).__name__}).",
                data_type="sequence",
                row_count=n,
            )

        total = sum(numeric)
        minimum = min(numeric)
        maximum = max(numeric)
        count = len(numeric)
        summary = (
            f"Numeric sequence: {count} value(s); "
            f"sum={total}; min={minimum}; max={maximum}."
        )
        return SafeView(
            summary=summary,
            data_type="numeric_sequence",
            row_count=count,
        )

    @staticmethod
    def _summarize_dict(data: dict) -> SafeView:
        numeric = {
            k: v
            for k, v in data.items()
            if isinstance(v, (int, float)) and not isinstance(v, bool)
        }
        if not numeric:
            return SafeView(
                summary=f"Key-value map with {len(data)} field(s); no numeric values.",
                data_type="key_value",
                row_count=len(data),
            )

        total = sum(numeric.values())
        minimum = min(numeric.values())
        maximum = max(numeric.values())
        key_list = ", ".join(f"{k}={v}" for k, v in list(numeric.items())[:5])
        suffix = "" if len(numeric) <= 5 else f" … (+{len(numeric) - 5} more)"
        summary = (
            f"Key-value map: {len(numeric)} numeric field(s); "
            f"sum={total}; min={minimum}; max={maximum}. "
            f"Fields: {key_list}{suffix}."
        )
        return SafeView(
            summary=summary,
            data_type="key_value_numeric",
            row_count=len(numeric),
        )

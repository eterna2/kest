"""
Output guardrail validators for @kest_verified (Issue #78).

Spec reference: SPEC-v0.3.0 — Defense-in-Depth Structural Validation.

Provides:
- OutputValidator: ABC for post-execution output validation hooks.
- OutputValidationError: exception raised when a validator rejects output.
- MaxLengthValidator: rejects outputs whose string representation exceeds a character limit.
- RegexDenyListValidator: rejects outputs matching any of a list of regex patterns.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import Any


class OutputValidationError(ValueError):
    """Raised by an OutputValidator when the decorated function's output fails validation.

    Caught by @kest_verified to add the ``output_validation_failed`` taint to the
    KestEntry before re-raising, ensuring a tamper-evident audit trail of the failure.
    """


class OutputValidator(ABC):
    """Abstract base class for post-execution output guardrail validators.

    Subclasses must implement :meth:`validate`.  The method should raise
    :class:`OutputValidationError` when the output fails the check.  Any other
    exception type will propagate unmodified (it will NOT trigger the
    ``output_validation_failed`` taint).

    Example::

        class NoNullBytesValidator(OutputValidator):
            def validate(self, output: Any) -> None:
                if "\\x00" in str(output):
                    raise OutputValidationError("Null byte detected in output")
    """

    @abstractmethod
    def validate(self, output: Any) -> None:
        """Validate *output*.  Raise :class:`OutputValidationError` on failure.

        Args:
            output: The raw return value of the decorated function.
        """


class MaxLengthValidator(OutputValidator):
    """Rejects outputs whose string representation exceeds *max_chars* characters.

    The output is coerced to ``str`` before measuring length, so this works for
    any return type (strings, dicts, Pydantic models, etc.).

    Args:
        max_chars: Maximum allowed length (inclusive).

    Raises:
        OutputValidationError: When ``len(str(output)) > max_chars``.
    """

    def __init__(self, max_chars: int) -> None:
        self._max_chars = max_chars

    def validate(self, output: Any) -> None:
        length = len(str(output))
        if length > self._max_chars:
            raise OutputValidationError(
                f"Output length {length} exceeds maximum allowed {self._max_chars} characters"
            )


class RegexDenyListValidator(OutputValidator):
    """Rejects outputs matching any of the provided regex *patterns*.

    The output is coerced to ``str`` before matching.  Uses :func:`re.search`
    so patterns match anywhere in the string (not just at the start).

    Args:
        patterns: List of regex pattern strings.  Any match causes rejection.

    Raises:
        OutputValidationError: When any pattern matches the output.
    """

    def __init__(self, patterns: list[str]) -> None:
        self._compiled = [(p, re.compile(p)) for p in patterns]

    def validate(self, output: Any) -> None:
        text = str(output)
        for raw_pattern, compiled in self._compiled:
            if compiled.search(text):
                raise OutputValidationError(
                    f"Output matched deny-list pattern: {raw_pattern!r}"
                )

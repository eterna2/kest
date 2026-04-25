"""
Structured output validation framework for @kest_verified (Issue #81).

Builds on the basic OutputValidator ABC (#78) with a full composable pipeline,
severity levels, structured violation tracking, and new built-in validators.

Provides:
- ValidationSeverity: Ordered enum — INFO, WARNING, BLOCK.
- ValidationViolation: Single validator finding with message, severity, and name.
- ValidationResult: Aggregated pipeline outcome with pass/fail and all violations.
- ValidationPipeline: Runs multiple OutputValidator instances; aggregates results.
  Also implements OutputValidator itself so it can be used in output_validators.
- LengthBoundsValidator: min/max character bounds (extends MaxLengthValidator concept).
- JsonSchemaValidator: validates output against a JSON schema dict.
- ContentClassificationValidator: verifies output matches an expected classification label.
- SemanticDriftDetector: abstract interface for similarity-based drift detection.

Backward compatible:
- OutputValidator, OutputValidationError, MaxLengthValidator, RegexDenyListValidator
  are all preserved unchanged.
"""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Callable, Union

# ---------------------------------------------------------------------------
# Preserved from Issue #78 — backward compatible
# ---------------------------------------------------------------------------


class OutputValidationError(ValueError):
    """Raised by an OutputValidator when the decorated function's output fails validation.

    Caught by @kest_verified to add the ``output_validation_failed`` taint to the
    KestEntry before re-raising, ensuring a tamper-evident audit trail of the failure.

    The optional *severity* argument is consumed by :class:`ValidationPipeline` to
    assign the correct :class:`ValidationSeverity` level to the violation.  When
    omitted it defaults to :attr:`ValidationSeverity.BLOCK` (the safe default).
    """

    def __init__(self, message: str, severity: ValidationSeverity = None) -> None:  # type: ignore[assignment]
        super().__init__(message)
        self.severity: ValidationSeverity = (
            severity if severity is not None else ValidationSeverity.BLOCK
        )


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


# ---------------------------------------------------------------------------
# Issue #81 — Structured Validation Framework
# ---------------------------------------------------------------------------


class ValidationSeverity(IntEnum):
    """Ordered severity levels for validation violations.

    Higher numeric values indicate greater severity:
    - ``INFO`` (0): Advisory finding; does not block execution.
    - ``WARNING`` (1): Noteworthy issue; may block depending on pipeline config.
    - ``BLOCK`` (2): Hard block; execution must not proceed.

    :class:`ValidationPipeline` treats any ``BLOCK``-level violation as a
    failure that raises :class:`OutputValidationError`.
    """

    INFO = 0
    WARNING = 1
    BLOCK = 2


@dataclass(frozen=True)
class ValidationViolation:
    """A single finding produced by one validator inside a :class:`ValidationPipeline`.

    Attributes:
        message: Human-readable description of the violation.
        severity: Severity level (:class:`ValidationSeverity`).
        validator_name: ``type(validator).__name__`` of the validator that fired.
    """

    message: str
    severity: ValidationSeverity
    validator_name: str


@dataclass(frozen=True)
class ValidationResult:
    """Aggregated result produced by :meth:`ValidationPipeline.run`.

    Attributes:
        passed: ``True`` if no ``BLOCK``-level violations were found.
        violations: All violations collected across all validators.
        severity: Highest :class:`ValidationSeverity` among violations, or
            :attr:`ValidationSeverity.INFO` when there are none.
    """

    passed: bool
    violations: list[ValidationViolation]
    severity: ValidationSeverity


class ValidationPipeline(OutputValidator):
    """Runs multiple :class:`OutputValidator` instances and aggregates their results.

    Unlike a plain list of ``output_validators``, :class:`ValidationPipeline` does
    **not** short-circuit on the first failure — it collects violations from **all**
    validators before deciding whether to raise.  This gives a complete picture of
    every constraint breach in a single pass.

    It also implements :class:`OutputValidator` itself, so it can be passed directly
    as a single entry inside the ``output_validators`` list of ``@kest_verified``.

    Args:
        validators: List of :class:`OutputValidator` instances to run in order.
        block_on: Minimum severity that causes :meth:`validate` to raise
            :class:`OutputValidationError`.  Defaults to :attr:`ValidationSeverity.BLOCK`.

    Example::

        pipeline = ValidationPipeline([
            LengthBoundsValidator(min_chars=10, max_chars=5000),
            JsonSchemaValidator(schema={"type": "object", "required": ["summary"]}),
        ])

        # Direct usage:
        result = pipeline.run(output)
        if not result.passed:
            for v in result.violations:
                print(v.message)

        # Or as an OutputValidator inside @kest_verified:
        @kest_verified(policy="summarize", output_validators=[pipeline])
        def summarize(doc: str) -> dict: ...
    """

    def __init__(
        self,
        validators: list[OutputValidator],
        block_on: ValidationSeverity = ValidationSeverity.BLOCK,
    ) -> None:
        self._validators = validators
        self._block_on = block_on

    def run(self, output: Any) -> ValidationResult:
        """Run all validators against *output* and return the aggregated result.

        Never raises — all errors are captured as :class:`ValidationViolation` entries.

        Args:
            output: The value to validate.

        Returns:
            :class:`ValidationResult` with all collected violations.
        """
        violations: list[ValidationViolation] = []
        for validator in self._validators:
            try:
                validator.validate(output)
            except OutputValidationError as exc:
                sev = (
                    exc.severity
                    if hasattr(exc, "severity")
                    else ValidationSeverity.BLOCK
                )
                violations.append(
                    ValidationViolation(
                        message=str(exc),
                        severity=sev,
                        validator_name=type(validator).__name__,
                    )
                )

        max_sev = max((v.severity for v in violations), default=ValidationSeverity.INFO)
        passed = max_sev < self._block_on
        return ValidationResult(passed=passed, violations=violations, severity=max_sev)

    def validate(self, output: Any) -> None:
        """Implement the :class:`OutputValidator` protocol.

        Calls :meth:`run` and raises :class:`OutputValidationError` if the result
        contains any violations at or above *block_on* severity.

        Args:
            output: The value to validate.

        Raises:
            OutputValidationError: When one or more blocking violations are found.
        """
        result = self.run(output)
        if not result.passed:
            # Surface the first blocking violation as the primary error message.
            blocking = [v for v in result.violations if v.severity >= self._block_on]
            primary = blocking[0] if blocking else result.violations[0]
            raise OutputValidationError(
                primary.message,
                severity=primary.severity,
            )


# ---------------------------------------------------------------------------
# Built-in Validators (Issue #81)
# ---------------------------------------------------------------------------


class LengthBoundsValidator(OutputValidator):
    """Rejects outputs whose string length falls outside [*min_chars*, *max_chars*].

    Both bounds are inclusive.  At least one of *min_chars* or *max_chars* must
    be provided.

    Args:
        min_chars: Minimum allowed character count (inclusive), or ``None`` for no lower bound.
        max_chars: Maximum allowed character count (inclusive), or ``None`` for no upper bound.

    Raises:
        OutputValidationError: When the coerced string length violates a bound.
    """

    def __init__(
        self,
        min_chars: int | None = None,
        max_chars: int | None = None,
    ) -> None:
        if min_chars is None and max_chars is None:
            raise ValueError(
                "LengthBoundsValidator requires at least one of min_chars or max_chars"
            )
        self._min = min_chars
        self._max = max_chars

    def validate(self, output: Any) -> None:
        text = str(output)
        length = len(text)
        if self._min is not None and length < self._min:
            raise OutputValidationError(
                f"Output length {length} is below minimum allowed {self._min} characters"
            )
        if self._max is not None and length > self._max:
            raise OutputValidationError(
                f"Output length {length} exceeds maximum allowed {self._max} characters"
            )


class JsonSchemaValidator(OutputValidator):
    """Validates that the output conforms to a JSON schema.

    The output may be:
    - A ``dict`` or ``list`` — validated directly.
    - A ``str`` — parsed as JSON first; raises :class:`OutputValidationError` if
      the string is not valid JSON.
    - Any other type — coerced to ``str`` and treated as raw JSON.

    Requires ``jsonschema`` to be installed.  A helpful :class:`ImportError` is
    raised at instantiation time if the dependency is missing.

    Args:
        schema: A JSON Schema dict (Draft 4, 6, or 7 compatible).

    Raises:
        OutputValidationError: When the output does not match *schema*, or when the
            output string cannot be decoded as JSON.
        ImportError: At instantiation if ``jsonschema`` is not installed.
    """

    def __init__(self, schema: dict) -> None:
        try:
            import jsonschema  # noqa: F401
        except ImportError as exc:
            raise ImportError(
                "JsonSchemaValidator requires 'jsonschema'.  "
                "Install it with: uv add 'kest[schema]' or pip install jsonschema"
            ) from exc
        self._schema = schema

    def validate(self, output: Any) -> None:
        import jsonschema
        from jsonschema import ValidationError as _ValidationError

        # Resolve output to a Python object
        if isinstance(output, (dict, list)):
            obj = output
        elif isinstance(output, str):
            try:
                obj = json.loads(output)
            except json.JSONDecodeError as exc:
                raise OutputValidationError(f"Output is not valid JSON: {exc}") from exc
        else:
            try:
                obj = json.loads(str(output))
            except json.JSONDecodeError as exc:
                raise OutputValidationError(
                    f"Output could not be parsed as JSON: {exc}"
                ) from exc

        try:
            jsonschema.validate(instance=obj, schema=self._schema)
        except _ValidationError as exc:
            raise OutputValidationError(
                f"Output failed schema validation: {exc.message}"
            ) from exc


class ContentClassificationValidator(OutputValidator):
    """Verifies that the output matches an expected classification label.

    *expected* may be:
    - A ``list[str]`` of allowed label strings.
    - A ``callable`` that receives the output and returns ``True`` when it matches.

    Args:
        expected: Allowed labels or a predicate callable.
        case_sensitive: When *expected* is a list, controls case folding.
            Defaults to ``True``.

    Raises:
        OutputValidationError: When the output does not satisfy *expected*.
    """

    def __init__(
        self,
        expected: Union[list[str], Callable[[Any], bool]],
        case_sensitive: bool = True,
    ) -> None:
        self._expected = expected
        self._case_sensitive = case_sensitive

    def validate(self, output: Any) -> None:
        if callable(self._expected):
            if not self._expected(output):
                raise OutputValidationError(
                    f"Output failed classification predicate: {output!r}"
                )
            return

        # List-based comparison
        text = str(output)
        allowed = self._expected
        if not self._case_sensitive:
            text = text.lower()
            allowed = [a.lower() for a in allowed]

        if text not in allowed:
            raise OutputValidationError(
                f"Output classification {output!r} is not in expected labels: {self._expected!r}"
            )


class SemanticDriftDetector(OutputValidator, ABC):
    """Abstract interface for similarity-based semantic drift detection.

    Concrete subclasses implement :meth:`detect` to compute a drift score in
    ``[0.0, 1.0]`` (0 = identical, 1 = completely different).  If the score
    meets or exceeds *threshold*, :meth:`validate` raises
    :class:`OutputValidationError`.

    This is an **interface-only** definition — no concrete embedding or model
    implementation is included.  Users are expected to subclass and implement
    :meth:`detect` using their preferred semantic similarity approach
    (e.g., cosine similarity of sentence-transformer embeddings, BM25, etc.).

    Args:
        reference: The canonical reference text or object to compare against.
        threshold: Drift score threshold in ``[0.0, 1.0]``.  Scores *≥ threshold*
            raise :class:`OutputValidationError`.  Defaults to ``0.5``.

    Example::

        class EmbeddingDriftDetector(SemanticDriftDetector):
            def detect(self, reference, output) -> float:
                return 1 - cosine_similarity(embed(reference), embed(output))

        detector = EmbeddingDriftDetector(reference="Expected answer topic", threshold=0.3)
    """

    def __init__(self, reference: Any, threshold: float = 0.5) -> None:
        self._reference = reference
        self._threshold = threshold

    @abstractmethod
    def detect(self, reference: Any, output: Any) -> float:
        """Compute the semantic drift score between *reference* and *output*.

        Args:
            reference: The canonical reference value set at construction time.
            output: The value produced by the decorated function.

        Returns:
            A float in ``[0.0, 1.0]`` where 0 means no drift and 1 means
            maximum drift.
        """

    def validate(self, output: Any) -> None:
        """Run drift detection and raise if drift exceeds the threshold.

        Args:
            output: The value to check against the reference.

        Raises:
            OutputValidationError: When ``detect(reference, output) >= threshold``.
        """
        score = self.detect(self._reference, output)
        if score >= self._threshold:
            raise OutputValidationError(
                f"Semantic drift score {score:.3f} meets or exceeds threshold {self._threshold:.3f}"
            )

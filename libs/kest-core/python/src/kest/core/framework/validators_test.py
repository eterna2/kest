"""
TDD tests for the structured OutputValidator framework (Issue #81).

Covers:
- ValidationSeverity enum
- ValidationViolation dataclass
- ValidationResult dataclass
- ValidationPipeline orchestration
- LengthBoundsValidator (min/max/both)
- JsonSchemaValidator (valid/invalid JSON, schema conformance)
- ContentClassificationValidator (label matching, callable predicate)
- SemanticDriftDetector abstract interface
- ValidationPipeline used as OutputValidator inside @kest_verified
"""

from __future__ import annotations

import asyncio

import pytest

from kest.core import (
    MockIdentityProvider,
    MockPolicyEngine,
    configure,
    kest_verified,
)
from kest.core.framework.decorators import invalidate_policy_cache
from kest.core.framework.validators import (
    ContentClassificationValidator,
    JsonSchemaValidator,
    LengthBoundsValidator,
    MaxLengthValidator,
    OutputValidationError,
    OutputValidator,
    SemanticDriftDetector,
    ValidationPipeline,
    ValidationResult,
    ValidationSeverity,
    ValidationViolation,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _configure_fresh():
    configure(
        engine=MockPolicyEngine(allow_all=True),
        identity=MockIdentityProvider(),
        clear=True,
    )
    invalidate_policy_cache()


# ---------------------------------------------------------------------------
# ValidationSeverity
# ---------------------------------------------------------------------------


def test_validation_severity_has_info_warning_block():
    assert ValidationSeverity.INFO is not None
    assert ValidationSeverity.WARNING is not None
    assert ValidationSeverity.BLOCK is not None


def test_validation_severity_ordering():
    """BLOCK > WARNING > INFO."""
    assert ValidationSeverity.BLOCK > ValidationSeverity.WARNING
    assert ValidationSeverity.WARNING > ValidationSeverity.INFO


# ---------------------------------------------------------------------------
# ValidationViolation
# ---------------------------------------------------------------------------


def test_validation_violation_construction():
    v = ValidationViolation(
        message="too long",
        severity=ValidationSeverity.BLOCK,
        validator_name="LengthBoundsValidator",
    )
    assert v.message == "too long"
    assert v.severity == ValidationSeverity.BLOCK
    assert v.validator_name == "LengthBoundsValidator"


# ---------------------------------------------------------------------------
# ValidationResult
# ---------------------------------------------------------------------------


def test_validation_result_passed_when_no_violations():
    r = ValidationResult(passed=True, violations=[], severity=ValidationSeverity.INFO)
    assert r.passed is True
    assert r.violations == []
    assert r.severity == ValidationSeverity.INFO


def test_validation_result_failed_with_violations():
    violation = ValidationViolation("bad", ValidationSeverity.BLOCK, "Test")
    r = ValidationResult(
        passed=False, violations=[violation], severity=ValidationSeverity.BLOCK
    )
    assert r.passed is False
    assert len(r.violations) == 1
    assert r.severity == ValidationSeverity.BLOCK


# ---------------------------------------------------------------------------
# LengthBoundsValidator
# ---------------------------------------------------------------------------


def test_length_bounds_min_only_passes():
    v = LengthBoundsValidator(min_chars=5)
    v.validate("hello world")


def test_length_bounds_min_only_fails_too_short():
    v = LengthBoundsValidator(min_chars=20)
    with pytest.raises(OutputValidationError, match="minimum"):
        v.validate("short")


def test_length_bounds_max_only_passes():
    v = LengthBoundsValidator(max_chars=100)
    v.validate("hello")


def test_length_bounds_max_only_fails_too_long():
    v = LengthBoundsValidator(max_chars=3)
    with pytest.raises(OutputValidationError, match="maximum"):
        v.validate("this is too long")


def test_length_bounds_both_min_and_max_passes():
    v = LengthBoundsValidator(min_chars=5, max_chars=20)
    v.validate("hello world")


def test_length_bounds_both_fails_below_min():
    v = LengthBoundsValidator(min_chars=5, max_chars=20)
    with pytest.raises(OutputValidationError, match="minimum"):
        v.validate("hi")


def test_length_bounds_both_fails_above_max():
    v = LengthBoundsValidator(min_chars=5, max_chars=10)
    with pytest.raises(OutputValidationError, match="maximum"):
        v.validate("this is way too long text")


def test_length_bounds_works_on_non_string_coerced():
    v = LengthBoundsValidator(min_chars=1, max_chars=50)
    v.validate({"key": "value"})  # coerced to str


def test_length_bounds_error_includes_limit():
    v = LengthBoundsValidator(min_chars=100)
    with pytest.raises(OutputValidationError, match="100"):
        v.validate("short")


# ---------------------------------------------------------------------------
# JsonSchemaValidator
# ---------------------------------------------------------------------------


def test_json_schema_validator_passes_valid_dict():
    schema = {"type": "object", "required": ["summary"]}
    v = JsonSchemaValidator(schema=schema)
    v.validate({"summary": "all good"})


def test_json_schema_validator_passes_valid_json_string():
    schema = {"type": "object", "required": ["summary"]}
    v = JsonSchemaValidator(schema=schema)
    v.validate('{"summary": "all good"}')


def test_json_schema_validator_fails_missing_required_field():
    schema = {"type": "object", "required": ["summary"]}
    v = JsonSchemaValidator(schema=schema)
    with pytest.raises(OutputValidationError, match="schema"):
        v.validate({"data": "no summary here"})


def test_json_schema_validator_fails_wrong_type():
    schema = {"type": "object"}
    v = JsonSchemaValidator(schema=schema)
    # A plain string that isn't parseable as JSON raises a JSON decode error first.
    with pytest.raises(OutputValidationError, match="JSON"):
        v.validate("just a plain string")


def test_json_schema_validator_fails_invalid_json_string():
    schema = {"type": "object"}
    v = JsonSchemaValidator(schema=schema)
    with pytest.raises(OutputValidationError, match="JSON"):
        v.validate("not valid json {{")


def test_json_schema_validator_passes_list_schema():
    schema = {"type": "array", "items": {"type": "string"}}
    v = JsonSchemaValidator(schema=schema)
    v.validate(["hello", "world"])


def test_json_schema_validator_fails_list_with_wrong_item_types():
    schema = {"type": "array", "items": {"type": "string"}}
    v = JsonSchemaValidator(schema=schema)
    with pytest.raises(OutputValidationError, match="schema"):
        v.validate([1, 2, 3])


# ---------------------------------------------------------------------------
# ContentClassificationValidator
# ---------------------------------------------------------------------------


def test_content_classification_passes_expected_label():
    v = ContentClassificationValidator(expected=["safe", "neutral"])
    v.validate("safe")


def test_content_classification_fails_unexpected_label():
    v = ContentClassificationValidator(expected=["safe"])
    with pytest.raises(OutputValidationError, match="classification"):
        v.validate("unsafe")


def test_content_classification_case_sensitive_by_default():
    v = ContentClassificationValidator(expected=["safe"])
    with pytest.raises(OutputValidationError):
        v.validate("Safe")


def test_content_classification_case_insensitive_flag():
    v = ContentClassificationValidator(expected=["safe"], case_sensitive=False)
    v.validate("SAFE")


def test_content_classification_callable_predicate_passes():
    v = ContentClassificationValidator(expected=lambda x: x.startswith("approved:"))
    v.validate("approved: this is fine")


def test_content_classification_callable_predicate_fails():
    v = ContentClassificationValidator(expected=lambda x: x.startswith("approved:"))
    with pytest.raises(OutputValidationError, match="classification"):
        v.validate("rejected: bad content")


# ---------------------------------------------------------------------------
# SemanticDriftDetector interface
# ---------------------------------------------------------------------------


def test_semantic_drift_detector_is_abstract():
    """SemanticDriftDetector cannot be instantiated directly."""
    with pytest.raises(TypeError):
        SemanticDriftDetector()  # type: ignore[abstract]


def test_semantic_drift_detector_concrete_subclass():
    """A concrete subclass implementing detect() can be used."""

    class MockDriftDetector(SemanticDriftDetector):
        def detect(self, reference, output) -> float:
            # Return 0.0 = no drift, 1.0 = complete drift
            return 0.0

    detector = MockDriftDetector(reference="original text", threshold=0.5)
    # Should not raise since drift (0.0) < threshold (0.5)
    detector.validate("very similar text")


def test_semantic_drift_detector_raises_when_drift_exceeds_threshold():
    class HighDriftDetector(SemanticDriftDetector):
        def detect(self, reference, output) -> float:
            return 0.9  # Very high drift

    detector = HighDriftDetector(reference="original text", threshold=0.5)
    with pytest.raises(OutputValidationError, match="drift"):
        detector.validate("completely different text")


def test_semantic_drift_detector_passes_at_threshold_boundary():
    class ExactThresholdDetector(SemanticDriftDetector):
        def detect(self, reference, output) -> float:
            return 0.5  # exactly at threshold — should NOT block (< is strict)

    detector = ExactThresholdDetector(reference="ref", threshold=0.5)
    # drift 0.5 is NOT strictly less than threshold 0.5, so it should block
    with pytest.raises(OutputValidationError, match="drift"):
        detector.validate("output")


# ---------------------------------------------------------------------------
# ValidationPipeline
# ---------------------------------------------------------------------------


def test_validation_pipeline_all_pass():
    pipeline = ValidationPipeline(
        validators=[
            LengthBoundsValidator(min_chars=1, max_chars=100),
            MaxLengthValidator(max_chars=100),
        ]
    )
    result = pipeline.run("hello")
    assert result.passed is True
    assert result.violations == []


def test_validation_pipeline_partial_fail():
    pipeline = ValidationPipeline(
        validators=[
            LengthBoundsValidator(min_chars=100),  # will fail
            MaxLengthValidator(max_chars=1000),  # will pass
        ]
    )
    result = pipeline.run("hello")
    assert result.passed is False
    assert len(result.violations) == 1


def test_validation_pipeline_all_fail():
    pipeline = ValidationPipeline(
        validators=[
            LengthBoundsValidator(min_chars=100),  # fail
            LengthBoundsValidator(max_chars=1),  # fail
        ]
    )
    result = pipeline.run("hello world")
    assert result.passed is False
    assert len(result.violations) == 2


def test_validation_pipeline_severity_is_max_of_violations():
    class WarnValidator(OutputValidator):
        def validate(self, output) -> None:
            raise OutputValidationError("warn", severity=ValidationSeverity.WARNING)

    class BlockValidator(OutputValidator):
        def validate(self, output) -> None:
            raise OutputValidationError("block", severity=ValidationSeverity.BLOCK)

    pipeline = ValidationPipeline(validators=[WarnValidator(), BlockValidator()])
    result = pipeline.run("x")
    assert result.severity == ValidationSeverity.BLOCK


def test_validation_pipeline_used_as_output_validator_in_kest_verified():
    """ValidationPipeline must work as a single item in output_validators."""
    _configure_fresh()

    pipeline = ValidationPipeline(
        validators=[LengthBoundsValidator(min_chars=1, max_chars=100)]
    )

    @kest_verified(policy="test", output_validators=[pipeline])
    def op():
        return "valid output"

    assert op() == "valid output"


def test_validation_pipeline_blocking_validator_raises_in_kest_verified():
    _configure_fresh()

    pipeline = ValidationPipeline(validators=[LengthBoundsValidator(max_chars=1)])

    @kest_verified(policy="test", output_validators=[pipeline])
    def op():
        return "this is way too long"

    with pytest.raises(OutputValidationError):
        op()


def test_validation_pipeline_async_integration():
    _configure_fresh()

    pipeline = ValidationPipeline(
        validators=[LengthBoundsValidator(min_chars=1, max_chars=50)]
    )

    @kest_verified(policy="test", output_validators=[pipeline])
    async def async_op():
        return "ok result"

    assert asyncio.run(async_op()) == "ok result"


# ---------------------------------------------------------------------------
# Public API export check
# ---------------------------------------------------------------------------


def test_new_validators_importable_from_kest_core():
    from kest.core import (  # noqa: F401
        ContentClassificationValidator,
        JsonSchemaValidator,
        LengthBoundsValidator,
        SemanticDriftDetector,
        ValidationPipeline,
        ValidationResult,
        ValidationSeverity,
        ValidationViolation,
    )

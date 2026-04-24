"""
TDD tests for output_validators parameter on @kest_verified (Issue #78).

These tests MUST be written before the implementation and must initially fail (RED).

Coverage:
- OutputValidator ABC contract
- MaxLengthValidator (pass / fail)
- RegexDenyListValidator (pass / fail, multiple patterns)
- output_validators wired into @kest_verified (sync and async)
- Validation failure adds taint "output_validation_failed" to KestEntry
- Validation failure raises (function result not returned to caller)
- Multiple validators: first failure stops execution
- No validators provided: function works normally
"""

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
    MaxLengthValidator,
    OutputValidationError,
    OutputValidator,
    RegexDenyListValidator,
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
# OutputValidator ABC
# ---------------------------------------------------------------------------


def test_output_validator_is_abstract():
    """OutputValidator cannot be instantiated directly — must subclass and implement validate()."""
    with pytest.raises(TypeError):
        OutputValidator()  # type: ignore[abstract]


def test_custom_validator_can_be_implemented():
    """A concrete subclass implementing validate() can be instantiated and called."""

    class AlwaysPassValidator(OutputValidator):
        def validate(self, output) -> None:
            pass  # never raises

    v = AlwaysPassValidator()
    v.validate("anything")  # must not raise


# ---------------------------------------------------------------------------
# MaxLengthValidator unit tests
# ---------------------------------------------------------------------------


def test_max_length_validator_passes_within_limit():
    v = MaxLengthValidator(max_chars=10)
    v.validate("hello")  # 5 chars — should not raise


def test_max_length_validator_passes_at_exact_limit():
    v = MaxLengthValidator(max_chars=5)
    v.validate("hello")  # exactly 5 — should not raise


def test_max_length_validator_fails_when_exceeded():
    v = MaxLengthValidator(max_chars=3)
    with pytest.raises(OutputValidationError):
        v.validate("toolong")


def test_max_length_validator_works_on_non_string_converts_to_str():
    """MaxLengthValidator coerces output to str before measuring length."""
    v = MaxLengthValidator(max_chars=3)
    # str({"x": 1}) = "{'x': 1}" — 8 chars, exceeds limit of 3
    with pytest.raises(OutputValidationError):
        v.validate({"x": 1})


def test_max_length_validator_error_includes_limit():
    v = MaxLengthValidator(max_chars=3)
    with pytest.raises(OutputValidationError, match="3"):
        v.validate("toolong")


# ---------------------------------------------------------------------------
# RegexDenyListValidator unit tests
# ---------------------------------------------------------------------------


def test_regex_deny_list_passes_clean_output():
    v = RegexDenyListValidator(patterns=[r"\b\d{3}-\d{2}-\d{4}\b"])
    v.validate("This is a safe response with no SSN.")


def test_regex_deny_list_fails_on_matching_pattern():
    v = RegexDenyListValidator(patterns=[r"\b\d{3}-\d{2}-\d{4}\b"])
    with pytest.raises(OutputValidationError):
        v.validate("User SSN is 123-45-6789")


def test_regex_deny_list_fails_on_any_of_multiple_patterns():
    v = RegexDenyListValidator(patterns=[r"CONFIDENTIAL", r"\b\d{3}-\d{2}-\d{4}\b"])
    with pytest.raises(OutputValidationError):
        v.validate("CONFIDENTIAL document")


def test_regex_deny_list_passes_when_no_patterns_match():
    v = RegexDenyListValidator(patterns=[r"CONFIDENTIAL", r"\b\d{3}-\d{2}-\d{4}\b"])
    v.validate("This is public information only.")


def test_regex_deny_list_error_includes_pattern():
    v = RegexDenyListValidator(patterns=[r"CONFIDENTIAL"])
    with pytest.raises(OutputValidationError, match="CONFIDENTIAL"):
        v.validate("CONFIDENTIAL data")


# ---------------------------------------------------------------------------
# @kest_verified integration — sync
# ---------------------------------------------------------------------------


def test_output_validators_pass_returns_result():
    """When validators all pass, the function result is returned normally."""
    _configure_fresh()

    @kest_verified(policy="test", output_validators=[MaxLengthValidator(max_chars=100)])
    def op() -> str:
        return "short result"

    assert op() == "short result"


def test_output_validators_fail_raises():
    """When a validator fails, an error is raised and the result is NOT returned."""
    _configure_fresh()

    @kest_verified(policy="test", output_validators=[MaxLengthValidator(max_chars=3)])
    def op() -> str:
        return "way too long output"

    with pytest.raises(OutputValidationError):
        op()


def test_output_validators_fail_adds_taint_to_entry():
    """Validation failure must add taint 'output_validation_failed' to the KestEntry."""
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

        @kest_verified(
            policy="test", output_validators=[MaxLengthValidator(max_chars=3)]
        )
        def op():
            return "this is too long"

        with pytest.raises(OutputValidationError):
            op()
    finally:
        _core_mod.sign_entry = original_sign
        dec_mod.sign_entry = original_sign

    assert len(captured_entries) >= 2, (
        "Expected at least 2 sign calls (normal + failure re-sign)"
    )
    last_entry = captured_entries[-1]
    assert "output_validation_failed" in last_entry.taints


def test_output_validators_no_taint_on_success():
    """Successful validation must NOT add 'output_validation_failed' taint."""
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

        @kest_verified(
            policy="test", output_validators=[MaxLengthValidator(max_chars=1000)]
        )
        def op():
            return "fine"

        op()
    finally:
        _core_mod.sign_entry = original_sign
        dec_mod.sign_entry = original_sign

    assert len(captured_entries) >= 1
    entry = captured_entries[0]
    assert "output_validation_failed" not in entry.taints


def test_multiple_validators_first_failure_raises():
    """First failing validator raises immediately; subsequent validators are not run."""
    _configure_fresh()
    called = []

    class TrackingValidator(OutputValidator):
        def __init__(self, name):
            self._name = name

        def validate(self, output) -> None:
            called.append(self._name)

    @kest_verified(
        policy="test",
        output_validators=[
            MaxLengthValidator(max_chars=3),  # fails first
            TrackingValidator("second"),
        ],
    )
    def op():
        return "toolong"

    with pytest.raises(OutputValidationError):
        op()

    assert "second" not in called


def test_no_validators_returns_result():
    """With output_validators=None (default), function works normally."""
    _configure_fresh()

    @kest_verified(policy="test")
    def op():
        return 42

    assert op() == 42


# ---------------------------------------------------------------------------
# @kest_verified integration — async
# ---------------------------------------------------------------------------


def test_async_output_validators_pass():
    _configure_fresh()

    @kest_verified(policy="test", output_validators=[MaxLengthValidator(max_chars=100)])
    async def async_op():
        return "ok"

    assert asyncio.run(async_op()) == "ok"


def test_async_output_validators_fail_raises():
    _configure_fresh()

    @kest_verified(policy="test", output_validators=[MaxLengthValidator(max_chars=1)])
    async def async_op():
        return "too long response"

    with pytest.raises(OutputValidationError):
        asyncio.run(async_op())


# ---------------------------------------------------------------------------
# Public API export
# ---------------------------------------------------------------------------


def test_validators_importable_from_kest_core():
    """OutputValidator, MaxLengthValidator, RegexDenyListValidator must be importable from kest.core."""
    from kest.core import (  # noqa: F401
        MaxLengthValidator,
        OutputValidationError,
        OutputValidator,
        RegexDenyListValidator,
    )

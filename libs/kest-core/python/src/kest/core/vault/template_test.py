"""
Tests for kest.core.vault.template — RED phase (TDD).

Tests are written against the public API *before* the implementation exists.
Run with: moon run kest-core-python:test
"""

from __future__ import annotations

import json

import pytest

from kest.core.vault import HandleVault, VaultCodec, ZlibCompressor
from kest.core.vault.errors import (
    HandleAccessDeniedError,
    HandleExpiredError,
    HandleNotFoundError,
)
from kest.core.vault.template import HydrationError, TemplateEngine, TemplateParser

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

OWNER = "spiffe://example.com/data-service"
READER = "spiffe://example.com/report-service"
INTRUDER = "spiffe://example.com/intruder"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def vault() -> HandleVault:
    return HandleVault()


@pytest.fixture()
def engine(vault: HandleVault) -> TemplateEngine:
    return TemplateEngine(vault=vault)


def _seal(vault: HandleVault, data: object, *, safe_view: str = "safe") -> str:
    """Seal *data* and return the handle_id."""
    handle = vault.seal(
        data=data,
        owner_principal=OWNER,
        safe_view=safe_view,
        granted_principals=[READER],
    )
    return handle.id


# ---------------------------------------------------------------------------
# TemplateParser — parse()
# ---------------------------------------------------------------------------


def test_parse_extracts_two_distinct_handles() -> None:
    """parse() returns all handle IDs found in a template."""
    hid1 = "hdl_" + "a" * 32
    hid2 = "hdl_" + "b" * 32
    tmpl = f"Start {{{{{hid1}}}}} middle {{{{{hid2}}}}} end."
    result = TemplateParser.parse(tmpl)
    assert result == [hid1, hid2]


def test_parse_preserves_duplicates() -> None:
    """The same handle appearing twice is listed twice in parse() output."""
    hid = "hdl_" + "c" * 32
    tmpl = f"{{{{{hid}}}}} and again {{{{{hid}}}}}."
    result = TemplateParser.parse(tmpl)
    assert result == [hid, hid]


def test_parse_empty_template_returns_empty_list() -> None:
    """A template with no placeholders returns []."""
    assert TemplateParser.parse("no handles here") == []


def test_parse_ignores_non_handle_braces() -> None:
    """Placeholders that don't start with hdl_ are ignored."""
    assert TemplateParser.parse("{{not_a_handle}} {{hdl_but_no_hex}}") == []


def test_parse_valid_handle_must_have_hex_suffix() -> None:
    """hdl_ prefix without a hex suffix is not matched."""
    assert TemplateParser.parse("{{hdl_}}") == []


# ---------------------------------------------------------------------------
# TemplateParser — render()
# ---------------------------------------------------------------------------


def test_render_substitutes_all_placeholders() -> None:
    """render() replaces every matched placeholder with its substitution."""
    hid = "hdl_" + "d" * 32
    result = TemplateParser.render(f"Value: {{{{{hid}}}}}.", {hid: "42"})
    assert result == "Value: 42."


def test_render_leaves_unknown_placeholders_untouched() -> None:
    """Placeholders absent from substitutions dict are left as-is."""
    hid = "hdl_" + "e" * 32
    tmpl = f"{{{{{hid}}}}}"
    result = TemplateParser.render(tmpl, {})
    assert result == tmpl


def test_render_substitutes_duplicate_placeholder_both_times() -> None:
    """A handle appearing twice is replaced at both positions."""
    hid = "hdl_" + "f" * 32
    result = TemplateParser.render(f"{{{{{hid}}}}} and {{{{{hid}}}}}.", {hid: "X"})
    assert result == "X and X."


# ---------------------------------------------------------------------------
# TemplateEngine — hydrate() — success paths
# ---------------------------------------------------------------------------


def test_hydrate_success_end_to_end(vault: HandleVault, engine: TemplateEngine) -> None:
    """Full round-trip: seal → hydrate → verify substitution."""
    hid = _seal(vault, {"amount": 999}, safe_view="total")
    result = engine.hydrate(f"Total: {{{{{hid}}}}}.", requesting_principal=READER)
    assert "999" in result
    assert hid not in result  # placeholder replaced


def test_hydrate_no_placeholders_passes_through(engine: TemplateEngine) -> None:
    """A template with no handle placeholders is returned unchanged."""
    plain = "This report has no handles."
    assert engine.hydrate(plain, requesting_principal=READER) == plain


def test_hydrate_duplicate_handle_unsealed_once(
    vault: HandleVault, engine: TemplateEngine
) -> None:
    """The same handle ID appearing twice is unsealed once and substituted at both positions."""
    hid = _seal(vault, "SECRET", safe_view="a value")
    result = engine.hydrate(
        f"{{{{{hid}}}}} and {{{{{hid}}}}}.", requesting_principal=READER
    )
    assert result.count("SECRET") == 2


def test_hydrate_custom_serializer(vault: HandleVault) -> None:
    """A custom serializer formats the unsealed data as JSON."""
    engine = TemplateEngine(vault=vault, serializer=json.dumps)
    hid = _seal(vault, {"key": "val"}, safe_view="dict value")
    result = engine.hydrate(f"Data: {{{{{hid}}}}}.", requesting_principal=READER)
    assert result == 'Data: {"key": "val"}.'


# ---------------------------------------------------------------------------
# TemplateEngine — hydrate() — error collection
# ---------------------------------------------------------------------------


def test_hydrate_access_denied_raises_hydration_error(
    vault: HandleVault, engine: TemplateEngine
) -> None:
    """A principal not in the ACL causes HydrationError with the denied handle."""
    hid = _seal(vault, "secret", safe_view="denied")
    with pytest.raises(HydrationError) as exc_info:
        engine.hydrate(f"{{{{{hid}}}}}.", requesting_principal=INTRUDER)
    assert hid in exc_info.value.errors
    assert isinstance(exc_info.value.errors[hid], HandleAccessDeniedError)


def test_hydrate_missing_handle_raises_hydration_error(engine: TemplateEngine) -> None:
    """An unknown handle ID causes HydrationError."""
    fake_id = "hdl_" + "0" * 32
    with pytest.raises(HydrationError) as exc_info:
        engine.hydrate(f"{{{{{fake_id}}}}}.", requesting_principal=READER)
    assert fake_id in exc_info.value.errors
    assert isinstance(exc_info.value.errors[fake_id], HandleNotFoundError)


def test_hydrate_expired_handle_raises_hydration_error(
    vault: HandleVault, engine: TemplateEngine
) -> None:
    """An expired handle causes HydrationError."""
    handle = vault.seal(
        data="stale",
        owner_principal=OWNER,
        safe_view="expired",
        ttl_seconds=0,
        granted_principals=[READER],
    )
    with pytest.raises(HydrationError) as exc_info:
        engine.hydrate(f"{{{{{handle.id}}}}}.", requesting_principal=READER)
    assert handle.id in exc_info.value.errors
    assert isinstance(exc_info.value.errors[handle.id], HandleExpiredError)


def test_hydrate_collects_multiple_errors(
    vault: HandleVault, engine: TemplateEngine
) -> None:
    """All failing handles are collected before raising — no short-circuit."""
    hid1 = _seal(vault, "a", safe_view="a")
    fake_id = "hdl_" + "9" * 32
    # hid1 succeeds for INTRUDER? No — INTRUDER not in ACL → denied
    # fake_id → not found
    with pytest.raises(HydrationError) as exc_info:
        engine.hydrate(
            f"{{{{{hid1}}}}} {{{{{fake_id}}}}}.",
            requesting_principal=INTRUDER,
        )
    errors = exc_info.value.errors
    assert hid1 in errors
    assert fake_id in errors
    assert isinstance(errors[hid1], HandleAccessDeniedError)
    assert isinstance(errors[fake_id], HandleNotFoundError)


# ---------------------------------------------------------------------------
# TemplateEngine — hydrate() — output validation
# ---------------------------------------------------------------------------


def test_hydrate_validator_blocks_output(
    vault: HandleVault, engine: TemplateEngine
) -> None:
    """OutputValidator that rejects the hydrated output causes OutputValidationError."""
    from kest.core.framework.validators import (
        OutputValidationError,
        RegexDenyListValidator,
    )

    hid = _seal(vault, "SSN: 123-45-6789", safe_view="pii")
    with pytest.raises(OutputValidationError):
        engine.hydrate(
            f"Record: {{{{{hid}}}}}.",
            requesting_principal=READER,
            output_validators=[RegexDenyListValidator([r"\bSSN\b"])],
        )


def test_hydrate_with_codec(vault: HandleVault) -> None:
    """TemplateEngine works correctly when the vault uses a VaultCodec."""
    coded_vault = HandleVault(codec=VaultCodec(compressor=ZlibCompressor()))
    engine = TemplateEngine(vault=coded_vault)
    handle = coded_vault.seal(
        data={"compressed": True},
        owner_principal=OWNER,
        safe_view="compressed data",
        granted_principals=[READER],
    )
    result = engine.hydrate(
        f"Payload: {{{{{handle.id}}}}}.",
        requesting_principal=READER,
    )
    assert "True" in result

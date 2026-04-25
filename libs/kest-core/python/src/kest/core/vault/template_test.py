"""
Tests for kest.core.vault.template — XML tag redesign.

Placeholder format: <kest-handle id="hdl_..." safe_view="human readable text"/>

The safe_view is embedded in the tag so LLMs receiving a template can read the
semantic description of each handle without touching the underlying data.
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
from kest.core.vault.handle import OpaqueHandle
from kest.core.vault.template import HydrationError, TemplateEngine, TemplateParser

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

OWNER = "spiffe://example.com/data-service"
READER = "spiffe://example.com/report-service"
INTRUDER = "spiffe://example.com/intruder"

_HID1 = "hdl_" + "a" * 32
_HID2 = "hdl_" + "b" * 32


def _tag(handle_id: str, safe_view: str = "a value") -> str:
    """Build a canonical kest-handle XML tag."""
    return f'<kest-handle id="{handle_id}" safe_view="{safe_view}"/>'


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def vault() -> HandleVault:
    return HandleVault()


@pytest.fixture()
def engine(vault: HandleVault) -> TemplateEngine:
    return TemplateEngine(vault=vault)


def _seal(
    vault: HandleVault,
    data: object,
    *,
    safe_view: str = "safe",
    extra_principals: list[str] | None = None,
) -> str:
    """Seal *data* and return the handle_id."""
    handle = vault.seal(
        data=data,
        owner_principal=OWNER,
        safe_view=safe_view,
        granted_principals=extra_principals or [READER],
    )
    return handle.id


# ---------------------------------------------------------------------------
# OpaqueHandle.to_tag()
# ---------------------------------------------------------------------------


def test_to_tag_produces_xml_tag() -> None:
    """to_tag() returns a self-closing XML kest-handle tag."""
    from datetime import datetime, timezone

    handle = OpaqueHandle(
        id=_HID1,
        safe_view="Q3 total expenditure",
        owner_principal=OWNER,
        created_at=datetime.now(tz=timezone.utc),
        expires_at=datetime.now(tz=timezone.utc),
    )
    tag = handle.to_tag()
    assert tag == f'<kest-handle id="{_HID1}" safe_view="Q3 total expenditure"/>'


def test_to_tag_escapes_double_quotes_in_safe_view() -> None:
    """to_tag() escapes any double-quote characters in safe_view."""
    from datetime import datetime, timezone

    handle = OpaqueHandle(
        id=_HID1,
        safe_view='Amount: "big"',
        owner_principal=OWNER,
        created_at=datetime.now(tz=timezone.utc),
        expires_at=datetime.now(tz=timezone.utc),
    )
    tag = handle.to_tag()
    assert '"' not in tag.split("safe_view=")[1].strip('"/>')


# ---------------------------------------------------------------------------
# TemplateParser.parse()
# ---------------------------------------------------------------------------


def test_parse_extracts_two_distinct_handles() -> None:
    tmpl = f"Start {_tag(_HID1, 'first')} middle {_tag(_HID2, 'second')} end."
    assert TemplateParser.parse(tmpl) == [_HID1, _HID2]


def test_parse_preserves_duplicates() -> None:
    tmpl = f"{_tag(_HID1)} and again {_tag(_HID1)}."
    assert TemplateParser.parse(tmpl) == [_HID1, _HID1]


def test_parse_empty_template_returns_empty_list() -> None:
    assert TemplateParser.parse("no handles here") == []


def test_parse_ignores_non_handle_braces() -> None:
    """Legacy moustache syntax is no longer recognised."""
    assert TemplateParser.parse(f"{{{{{_HID1}}}}}") == []


def test_parse_ignores_unclosed_tags() -> None:
    """Tags without self-closing slash are not matched."""
    assert TemplateParser.parse(f'<kest-handle id="{_HID1}" safe_view="x">') == []


def test_parse_valid_handle_must_have_hdl_prefix() -> None:
    assert TemplateParser.parse('<kest-handle id="foo_123" safe_view="x"/>') == []


# ---------------------------------------------------------------------------
# TemplateParser.render()
# ---------------------------------------------------------------------------


def test_render_substitutes_all_placeholders() -> None:
    tag = _tag(_HID1, "total")
    result = TemplateParser.render(f"Value: {tag}.", {_HID1: "42"})
    assert result == "Value: 42."


def test_render_leaves_unknown_placeholders_untouched() -> None:
    tag = _tag(_HID1, "total")
    result = TemplateParser.render(tag, {})
    assert result == tag


def test_render_substitutes_duplicate_placeholder_both_times() -> None:
    tag = _tag(_HID1, "amount")
    result = TemplateParser.render(f"{tag} and {tag}.", {_HID1: "X"})
    assert result == "X and X."


# ---------------------------------------------------------------------------
# TemplateEngine.hydrate() — success paths
# ---------------------------------------------------------------------------


def test_hydrate_success_end_to_end(vault: HandleVault, engine: TemplateEngine) -> None:
    hid = _seal(vault, {"amount": 999}, safe_view="total")
    tag = _tag(hid, "total")
    result = engine.hydrate(f"Total: {tag}.", requesting_principal=READER)
    assert "999" in result
    assert "<kest-handle" not in result  # tag fully replaced


def test_hydrate_no_placeholders_passes_through(engine: TemplateEngine) -> None:
    plain = "This report has no handles."
    assert engine.hydrate(plain, requesting_principal=READER) == plain


def test_hydrate_duplicate_handle_unsealed_once(
    vault: HandleVault, engine: TemplateEngine
) -> None:
    hid = _seal(vault, "SECRET", safe_view="a value")
    tag = _tag(hid, "a value")
    result = engine.hydrate(f"{tag} and {tag}.", requesting_principal=READER)
    assert result.count("SECRET") == 2


def test_hydrate_custom_serializer(vault: HandleVault) -> None:
    engine = TemplateEngine(vault=vault, serializer=json.dumps)
    hid = _seal(vault, {"key": "val"}, safe_view="dict value")
    tag = _tag(hid, "dict value")
    result = engine.hydrate(f"Data: {tag}.", requesting_principal=READER)
    assert result == 'Data: {"key": "val"}.'


def test_hydrate_attribute_order_agnostic(
    vault: HandleVault, engine: TemplateEngine
) -> None:
    """Parser handles safe_view before id as well as id before safe_view."""
    hid = _seal(vault, "hello", safe_view="greeting")
    # Reverse attribute order
    reverse_tag = f'<kest-handle safe_view="greeting" id="{hid}"/>'
    result = engine.hydrate(f"Says: {reverse_tag}.", requesting_principal=READER)
    assert result == "Says: hello."


# ---------------------------------------------------------------------------
# TemplateEngine.hydrate() — error collection
# ---------------------------------------------------------------------------


def test_hydrate_access_denied_raises_hydration_error(
    vault: HandleVault, engine: TemplateEngine
) -> None:
    hid = _seal(vault, "secret", safe_view="denied")
    with pytest.raises(HydrationError) as exc_info:
        engine.hydrate(_tag(hid, "denied"), requesting_principal=INTRUDER)
    assert hid in exc_info.value.errors
    assert isinstance(exc_info.value.errors[hid], HandleAccessDeniedError)


def test_hydrate_missing_handle_raises_hydration_error(engine: TemplateEngine) -> None:
    fake_id = "hdl_" + "0" * 32
    with pytest.raises(HydrationError) as exc_info:
        engine.hydrate(_tag(fake_id, "ghost"), requesting_principal=READER)
    assert fake_id in exc_info.value.errors
    assert isinstance(exc_info.value.errors[fake_id], HandleNotFoundError)


def test_hydrate_expired_handle_raises_hydration_error(
    vault: HandleVault, engine: TemplateEngine
) -> None:
    handle = vault.seal(
        data="stale",
        owner_principal=OWNER,
        safe_view="expired",
        ttl_seconds=0,
        granted_principals=[READER],
    )
    with pytest.raises(HydrationError) as exc_info:
        engine.hydrate(_tag(handle.id, "expired"), requesting_principal=READER)
    assert isinstance(exc_info.value.errors[handle.id], HandleExpiredError)


def test_hydrate_collects_multiple_errors(
    vault: HandleVault, engine: TemplateEngine
) -> None:
    hid1 = _seal(vault, "a", safe_view="a")
    fake_id = "hdl_" + "9" * 32
    with pytest.raises(HydrationError) as exc_info:
        engine.hydrate(
            f"{_tag(hid1, 'a')} {_tag(fake_id, 'ghost')}.",
            requesting_principal=INTRUDER,
        )
    errors = exc_info.value.errors
    assert hid1 in errors and fake_id in errors
    assert isinstance(errors[hid1], HandleAccessDeniedError)
    assert isinstance(errors[fake_id], HandleNotFoundError)


# ---------------------------------------------------------------------------
# TemplateEngine.hydrate() — output validation
# ---------------------------------------------------------------------------


def test_hydrate_validator_blocks_output(
    vault: HandleVault, engine: TemplateEngine
) -> None:
    from kest.core.framework.validators import (
        OutputValidationError,
        RegexDenyListValidator,
    )

    hid = _seal(vault, "SSN: 123-45-6789", safe_view="pii")
    with pytest.raises(OutputValidationError):
        engine.hydrate(
            f"Record: {_tag(hid, 'pii')}.",
            requesting_principal=READER,
            output_validators=[RegexDenyListValidator([r"\bSSN\b"])],
        )


def test_hydrate_with_codec(vault: HandleVault) -> None:
    coded_vault = HandleVault(codec=VaultCodec(compressor=ZlibCompressor()))
    engine = TemplateEngine(vault=coded_vault)
    handle = coded_vault.seal(
        data={"compressed": True},
        owner_principal=OWNER,
        safe_view="compressed data",
        granted_principals=[READER],
    )
    result = engine.hydrate(
        f"Payload: {_tag(handle.id, 'compressed data')}.",
        requesting_principal=READER,
    )
    assert "True" in result

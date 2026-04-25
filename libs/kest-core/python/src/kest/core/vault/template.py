"""
Template & Hydrate engine for data-safe report composition.

The Template & Hydrate pattern allows LLMs to produce report *structure* using
opaque handle placeholders (``{{hdl_...}}``) without ever seeing the underlying
sensitive data. A trusted component then:

1. Parses the LLM output for ``{{hdl_...}}`` placeholders.
2. Verifies the requesting principal has read access to each handle via the
   ``HandleVault`` ACL. All failures are collected before raising — no
   short-circuit.
3. Substitutes each placeholder with the serialised real data.
4. Passes the final string through optional outbound guardrail validators.

Example::

    from kest.core.vault import HandleVault, TemplateEngine
    from kest.core.framework.validators import RegexDenyListValidator

    vault = HandleVault()
    engine = TemplateEngine(vault=vault)

    handle = vault.seal(
        data={"total": "$1,234,567"},
        owner_principal="spiffe://example.com/data-service",
        safe_view="Q3 total expenditure figure",
        granted_principals=["spiffe://example.com/report-service"],
    )

    skeleton = f"Expenditure: {{{{{handle.id}}}}}."
    report = engine.hydrate(
        template=skeleton,
        requesting_principal="spiffe://example.com/report-service",
        output_validators=[RegexDenyListValidator([r"\\bSSN\\b"])],
    )
"""

from __future__ import annotations

import re
from typing import Any, Callable, Iterable

from kest.core.vault.errors import (
    HandleAccessDeniedError,
    HandleExpiredError,
    HandleNotFoundError,
)

# ---------------------------------------------------------------------------
# Handle placeholder pattern
# ---------------------------------------------------------------------------

# Matches {{ hdl_<hex-chars> }} where hex-chars is at least 1 character.
# Double-brace delimiters avoid collision with Jinja2 / f-string single braces.
_HANDLE_RE = re.compile(r"\{\{(hdl_[0-9a-f]+)\}\}")


# ---------------------------------------------------------------------------
# HydrationError
# ---------------------------------------------------------------------------


class HydrationError(Exception):
    """Raised when one or more handle resolutions fail during hydration.

    All failing handles are attempted before this exception is raised so
    the caller receives a complete picture of every ACL denial or missing
    handle in a single pass.

    Attributes:
        errors: Mapping from ``handle_id`` to the underlying exception
            (``HandleNotFoundError``, ``HandleExpiredError``, or
            ``HandleAccessDeniedError``).
    """

    def __init__(self, errors: dict[str, Exception]) -> None:
        self.errors: dict[str, Exception] = errors
        summary = "; ".join(
            f"{hid}: {type(exc).__name__}" for hid, exc in errors.items()
        )
        super().__init__(f"Hydration failed for {len(errors)} handle(s): {summary}")


# ---------------------------------------------------------------------------
# TemplateParser
# ---------------------------------------------------------------------------


class TemplateParser:
    """Pure parsing and rendering logic for handle-placeholder templates.

    This class has no state and all methods are class-level. It is kept
    separate from :class:`TemplateEngine` to satisfy SRP and to allow
    independent unit testing of the regex / substitution logic.
    """

    #: Compiled regex matching ``{{hdl_<hex>}}`` placeholders.
    HANDLE_PATTERN: re.Pattern[str] = _HANDLE_RE

    @classmethod
    def parse(cls, template: str) -> list[str]:
        """Return an ordered list of handle IDs found in *template*.

        Duplicates are preserved (the same handle may appear multiple times).

        Args:
            template: The raw LLM-produced string to scan.

        Returns:
            List of handle ID strings (e.g. ``["hdl_abc123…", "hdl_def456…"]``).
            Returns ``[]`` if no placeholders are found.
        """
        return cls.HANDLE_PATTERN.findall(template)

    @classmethod
    def render(cls, template: str, substitutions: dict[str, str]) -> str:
        """Replace every ``{{hdl_X}}`` placeholder whose ID is in *substitutions*.

        Placeholders whose ID is absent from *substitutions* are left
        untouched (safety valve — callers should not rely on this for normal
        operation; :class:`TemplateEngine` raises :class:`HydrationError`
        before reaching this step if any handles are unresolvable).

        Args:
            template: The raw template string.
            substitutions: Mapping from handle ID to its rendered value.

        Returns:
            The hydrated string.
        """

        def _replace(match: re.Match[str]) -> str:
            handle_id = match.group(1)
            return substitutions.get(handle_id, match.group(0))

        return cls.HANDLE_PATTERN.sub(_replace, template)


# ---------------------------------------------------------------------------
# TemplateEngine
# ---------------------------------------------------------------------------


class TemplateEngine:
    """Orchestrates parse → ACL-checked unseal → substitution → validation.

    Args:
        vault: The :class:`~kest.core.vault.HandleVault` instance to unseal
            handles from.
        serializer: Callable that converts unsealed data to a string for
            substitution into the template. Defaults to :func:`str`.
            Pass ``json.dumps`` for JSON formatting, etc.

    Example::

        import json
        engine = TemplateEngine(vault=vault, serializer=json.dumps)
    """

    def __init__(
        self,
        vault: Any,  # HandleVault — typed as Any to avoid circular import
        serializer: Callable[[Any], str] = str,
    ) -> None:
        self._vault = vault
        self._serializer = serializer

    def hydrate(
        self,
        template: str,
        requesting_principal: str,
        output_validators: Iterable[Any] = (),
    ) -> str:
        """Hydrate *template* by resolving all ``{{hdl_...}}`` placeholders.

        Steps:

        1. Parse all handle IDs from *template* (unique IDs only for unseal,
           but duplicates are substituted at all positions).
        2. Attempt ``vault.unseal()`` for every unique handle ID against
           *requesting_principal*. **All** errors are collected before raising.
        3. If any errors occurred, raise :class:`HydrationError`.
        4. Substitute every placeholder with ``serializer(data)``.
        5. Run *output_validators* on the final string.
        6. Return the hydrated string.

        Args:
            template: LLM-produced skeleton string with ``{{hdl_...}}``
                placeholders.
            requesting_principal: The SPIFFE URI (or other principal string)
                of the component performing the hydration. ACL-checked against
                each handle's ``granted_principals`` / ``owner_principal``.
            output_validators: Optional sequence of :class:`OutputValidator`
                instances run after hydration (e.g. DLP / regex guardrails).

        Returns:
            The fully hydrated report string.

        Raises:
            HydrationError: One or more handles failed ACL / not-found /
                expiry checks. ``HydrationError.errors`` maps each failing
                handle ID to its exception.
            OutputValidationError: The hydrated string failed a post-hydration
                validator.
        """
        all_ids = TemplateParser.parse(template)
        unique_ids = list(dict.fromkeys(all_ids))  # deduplicate, preserve order

        # --- Step 2: attempt all unseals, collect errors ---
        resolved: dict[str, Any] = {}
        errors: dict[str, Exception] = {}

        for handle_id in unique_ids:
            try:
                resolved[handle_id] = self._vault.unseal(
                    handle_id, requesting_principal
                )
            except (
                HandleNotFoundError,
                HandleExpiredError,
                HandleAccessDeniedError,
            ) as exc:
                errors[handle_id] = exc

        # --- Step 3: raise collected errors ---
        if errors:
            raise HydrationError(errors)

        # --- Step 4: build substitutions and render ---
        substitutions = {hid: self._serializer(data) for hid, data in resolved.items()}
        result = TemplateParser.render(template, substitutions)

        # --- Step 5: run output validators ---
        for validator in output_validators:
            validator.validate(result)

        return result

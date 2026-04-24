"""
Public context accessor functions for reading Kest identity and lineage
data from the ambient OTel Baggage context.

These functions implement SPEC-v0.3.0 §2.8 F-CP-06.
"""

from typing import cast

from opentelemetry import baggage


def _get_baggage_str(key: str) -> str | None:
    """Read a string value from OTel Baggage, returning None if absent.

    OTel's ``baggage.get_baggage`` returns ``object | None`` but all Kest
    baggage values are strings, so we narrow the type here.
    """
    val = baggage.get_baggage(key)
    if val is None:
        return None
    return cast(str, val)


def get_current_user() -> str | None:
    """Return the current user principal from OTel Baggage (``kest.user``).

    Returns ``None`` if the key is absent. The value is typically set by
    :class:`~kest.core.KestIdentityMiddleware` from the JWT ``sub`` claim.
    """
    return _get_baggage_str("kest.user")


def get_current_agent() -> str | None:
    """Return the current agent identity from OTel Baggage (``kest.agent``).

    Returns ``None`` if the key is absent. The value is typically set by
    :class:`~kest.core.KestIdentityMiddleware` from the JWT ``azp`` /
    ``client_id`` claim.
    """
    return _get_baggage_str("kest.agent")


def get_current_task() -> str | None:
    """Return the current task/scope from OTel Baggage (``kest.task``).

    Returns ``None`` if the key is absent. The value is typically set by
    :class:`~kest.core.KestIdentityMiddleware` from the JWT ``scope`` claim.
    """
    return _get_baggage_str("kest.task")


def get_current_jwt() -> str | None:
    """Return the raw JWT string from OTel Baggage (``kest.jwt``).

    Returns ``None`` if the key is absent. The value is set by
    :class:`~kest.core.KestIdentityMiddleware` from the ``Authorization``
    header.
    """
    return _get_baggage_str("kest.jwt")


def get_current_passport() -> str | None:
    """Return the serialized Passport from OTel Baggage (``kest.passport``).

    Returns ``None`` if the key is absent. The value is set by
    :class:`~kest.core.KestMiddleware` from the incoming ``baggage`` header.
    """
    return _get_baggage_str("kest.passport")

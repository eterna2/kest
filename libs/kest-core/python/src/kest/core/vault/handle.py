"""
OpaqueHandle dataclass: the opaque pointer returned by HandleVault.seal().

A handle carries only non-sensitive metadata (safe_view) and is safe to
pass to an LLM context window. The actual sensitive payload is stored in
the vault and only accessible to authorised principals via HandleVault.unseal().
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class OpaqueHandle:
    """
    An immutable pointer to sealed data stored in a HandleVault.

    Attributes:
        id: Unique handle identifier, prefixed with ``hdl_``.
        safe_view: A human-readable, non-sensitive summary of the sealed data.
            Safe to include in LLM prompts or logs.
        owner_principal: The SPIFFE URI (or any principal string) that owns
            this handle and may unseal it without additional grants.
        created_at: UTC timestamp of when the handle was created.
        expires_at: UTC timestamp after which the handle is considered expired.
        granted_principals: Additional principals allowed to unseal this handle.
    """

    id: str
    safe_view: str
    owner_principal: str
    created_at: datetime
    expires_at: datetime
    granted_principals: frozenset = field(default_factory=frozenset)

    def to_tag(self) -> str:
        """Return a self-closing XML tag embedding this handle for LLM prompts.

        The tag includes both the opaque ``id`` (for resolution by a trusted
        gateway) and the ``safe_view`` (a human-readable description that is
        safe to expose to the LLM).

        Example output::

            <kest-handle id="hdl_a1b2c3..." safe_view="Q3 total expenditure"/>

        Double-quote characters in ``safe_view`` are escaped as ``&quot;`` to
        keep the XML well-formed.

        Returns:
            A self-closing ``<kest-handle .../>`` XML tag string.
        """
        escaped_view = self.safe_view.replace('"', "&quot;")
        return f'<kest-handle id="{self.id}" safe_view="{escaped_view}"/>'

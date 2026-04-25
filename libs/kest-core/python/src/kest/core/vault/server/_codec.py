"""JSON wire codec helpers for vault service transports."""

from __future__ import annotations

import json
from typing import Any

from kest.core.vault.handle import OpaqueHandle


def handle_to_dict(handle: OpaqueHandle) -> dict:
    """Serialise an OpaqueHandle to a JSON-safe dict."""
    return {
        "id": handle.id,
        "safe_view": handle.safe_view,
        "owner_principal": handle.owner_principal,
        "created_at": handle.created_at.isoformat(),
        "expires_at": handle.expires_at.isoformat(),
        "granted_principals": sorted(handle.granted_principals),
    }


def encode_data(data: Any) -> str:
    """JSON-encode *data* for wire transport. Data must be JSON-serialisable."""
    return json.dumps(data)


def decode_data(raw: str) -> Any:
    """Decode a JSON-encoded wire payload."""
    return json.loads(raw)

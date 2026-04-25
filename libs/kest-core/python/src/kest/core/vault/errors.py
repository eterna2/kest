"""
Custom exception types for the HandleVault / OpaqueHandle pattern.
"""

from __future__ import annotations


class HandleNotFoundError(KeyError):
    """Raised when a handle ID does not exist in the vault (or was invalidated)."""


class HandleExpiredError(Exception):
    """Raised when a handle's TTL has elapsed and the data is no longer accessible."""


class HandleAccessDeniedError(PermissionError):
    """Raised when the requesting principal is not authorised to unseal a handle."""

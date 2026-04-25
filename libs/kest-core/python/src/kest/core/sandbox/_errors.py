"""Sandbox exception hierarchy."""

from __future__ import annotations


class SandboxError(Exception):
    """Base for all sandbox errors."""


class SandboxTimeoutError(SandboxError):
    """Raised when timeout_seconds is exceeded."""


class SandboxConfigurationError(SandboxError):
    """Raised for invalid or incompatible SandboxConfig."""


class SandboxExecutionError(SandboxError):
    """Runtime error inside sandboxed code."""


class SandboxImportError(SandboxExecutionError):
    """A blocked module import was attempted."""


class SandboxSecurityError(SandboxExecutionError):
    """A blocked builtin was called."""


class SandboxNotAvailableError(SandboxError):
    """Backend optional extra is not installed."""

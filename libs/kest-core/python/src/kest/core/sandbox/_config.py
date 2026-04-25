"""SandboxConfig — unified configuration for all backends."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SandboxConfig:
    """
    Unified configuration for all SandboxProvider backends.
    Backends that do not support a field MUST ignore it and emit a WARNING.

    Default posture is deny-by-default: dangerous builtins and network-capable
    modules are blocked unless explicitly removed from the list.
    """

    # ── Module-level control (CPython-based backends) ────────────────────────
    allowed_modules: list[str] | None = None
    """Explicit allowlist. None = no allowlist (all non-blocked modules importable).
    When set, ONLY these modules (plus builtins) may be imported.
    blocked_modules is still applied as a secondary deny-filter."""

    blocked_modules: list[str] = field(
        default_factory=lambda: [
            "subprocess",
            "socket",
            "http",
            "urllib",
            "ftplib",
            "telnetlib",
            "smtplib",
            "xmlrpc",
            "multiprocessing",
            "ctypes",
            "cffi",
        ]
    )
    """Modules always blocked, even if present in the environment.
    Enforced via sys.meta_path hook injected before user code runs."""

    # ── Builtin-level control (CPython-based backends) ───────────────────────
    blocked_builtins: list[str] = field(
        default_factory=lambda: [
            "eval",
            "exec",
            "compile",
            "open",
            "breakpoint",
            "input",
        ]
    )
    """Builtins replaced with a SecurityError-raising stub."""

    # ── Package installation ─────────────────────────────────────────────────
    allowed_packages: list[str] | None = None
    """Packages to pre-install before script execution.
    Not supported by MontySandbox (logs WARNING and ignores).
    Pure-Python packages only recommended for SubprocessSandbox."""

    package_index_url: str | None = None
    """Exclusive PyPI index URL. None = default PyPI.
    When set, ALL package installs use this index exclusively (no fallback)."""

    # ── Network (backend-specific) ───────────────────────────────────────────
    network_mode: str = "none"
    """Backend-specific network mode hint.
    SubprocessSandbox / MontySandbox: ignored.
    AgentCoreSandbox: 'vpc' (recommended), 'sandbox' (unpatched DNS-tunnel risk,
      WARNING logged), or 'public' (unrestricted internet, WARNING logged).
    E2BSandbox: template-level setting.
    DockerSandbox: maps to Docker --network flag."""

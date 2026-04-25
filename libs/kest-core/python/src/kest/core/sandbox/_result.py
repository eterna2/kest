"""SandboxResult — immutable result of a sandboxed script execution."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class SandboxResult:
    """Immutable result of a sandboxed script execution."""

    stdout: str
    """Captured stdout from script execution."""

    stderr: str
    """Captured stderr (warnings, tracebacks, etc.)."""

    return_value: Any
    """The value returned by the script's last expression, or None."""

    exit_code: int
    """0 = success; non-zero = failure (including timeout)."""

    taints_added: frozenset[str]
    """Union of all taints from tool_proxy.call_tool() during this execution.
    Populated from tool_proxy.accumulated_taints after execute() completes."""

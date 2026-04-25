"""kest.core.sandbox — public API surface."""

from kest.core.sandbox._config import SandboxConfig
from kest.core.sandbox._errors import (
    SandboxConfigurationError,
    SandboxError,
    SandboxExecutionError,
    SandboxImportError,
    SandboxNotAvailableError,
    SandboxSecurityError,
    SandboxTimeoutError,
)
from kest.core.sandbox._provider import SandboxProvider
from kest.core.sandbox._result import SandboxResult
from kest.core.sandbox._tool_proxy import ToolProxy
from kest.core.sandbox.subprocess_sandbox import SubprocessSandbox

# Optional extras — lazy-imported so kest.core remains installable without them.
try:
    from kest.core.sandbox.e2b_sandbox import E2BSandbox

    _E2B_AVAILABLE = True
except ImportError:
    _E2B_AVAILABLE = False

try:
    from kest.core.sandbox.agentcore_sandbox import AgentCoreSandbox

    _AGENTCORE_AVAILABLE = True
except ImportError:
    _AGENTCORE_AVAILABLE = False

try:
    from kest.core.sandbox.monty_sandbox import MontySandbox

    _MONTY_AVAILABLE = True
except ImportError:
    _MONTY_AVAILABLE = False

__all__ = [
    # Configuration
    "SandboxConfig",
    # ABCs
    "SandboxProvider",
    "ToolProxy",
    # Result
    "SandboxResult",
    # Errors
    "SandboxError",
    "SandboxTimeoutError",
    "SandboxConfigurationError",
    "SandboxExecutionError",
    "SandboxImportError",
    "SandboxSecurityError",
    "SandboxNotAvailableError",
    # Backends (always available)
    "SubprocessSandbox",
    # Backends (optional extras)
    "E2BSandbox",
    "AgentCoreSandbox",
    "MontySandbox",
]

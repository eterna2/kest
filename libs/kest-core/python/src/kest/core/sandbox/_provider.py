"""SandboxProvider — abstract base class for all Kest sandbox backends."""

from __future__ import annotations

from abc import ABC, abstractmethod

from kest.core.sandbox._config import SandboxConfig
from kest.core.sandbox._result import SandboxResult
from kest.core.sandbox._tool_proxy import ToolProxy


class SandboxProvider(ABC):
    """
    Abstract base class for all Kest sandbox backends.

    All implementations must:
    - Call tool_proxy.reset() before executing the script.
    - Enforce timeout_seconds (raise SandboxTimeoutError on breach).
    - Populate SandboxResult.taints_added from tool_proxy.accumulated_taints.
    - Be re-entrant: multiple concurrent execute() calls must not interfere.

    Available backends (import from kest.core.sandbox):
      SubprocessSandbox   — no extra deps; baseline CPython
      MontySandbox        — [monty]; in-process Rust interpreter
      AgentCoreSandbox    — [agentcore]; AWS Bedrock
      E2BSandbox          — [e2b]; Firecracker microVM
      DockerSandbox       — [docker]; OCI container
      WasmSandbox         — stub only
    """

    @abstractmethod
    async def execute(
        self,
        script: str,
        tool_proxy: ToolProxy,
        timeout_seconds: int = 30,
        config: SandboxConfig | None = None,
    ) -> SandboxResult:
        """
        Execute `script` in the sandbox.

        Parameters
        ----------
        script:
            Python source code to execute.
        tool_proxy:
            All tool calls are routed through this proxy.
            MUST apply @kest_verified for every call_tool().
        timeout_seconds:
            Maximum wall-clock time allowed. SandboxTimeoutError raised on breach.
        config:
            Security configuration. None = safe deny-by-default defaults.

        Returns
        -------
        SandboxResult with stdout, stderr, return_value, exit_code, taints_added.
        """

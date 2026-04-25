"""E2BSandbox — Firecracker microVM via E2B Code Interpreter.

Install: uv add 'kest-core[e2b]'
Requires: E2B_API_KEY environment variable.

SDK (v1): e2b-code-interpreter
  - Sandbox.create(api_key=...) → context manager / sandbox instance
  - sandbox.run_code(code, timeout=N) → Execution(results, logs, error)
  - Execution.logs.stdout → list[str]
  - Execution.logs.stderr → list[str]
  - Execution.error → ExecutionError | None  (name, value, traceback: str)

Security note:
  E2B runs on a Jupyter kernel, which uses exec() internally for cell evaluation.
  Blocking exec() at the builtins level would break the kernel itself.
  Module blocking is therefore done exclusively via the sys.meta_path hook
  (_KestImportBlocker), which is kernel-safe. Builtin blocking is omitted for
  E2B; rely on the microVM's OS-level isolation for privilege separation.
"""

from __future__ import annotations

import asyncio
import logging
import os

from kest.core.sandbox._config import SandboxConfig
from kest.core.sandbox._errors import SandboxNotAvailableError, SandboxTimeoutError
from kest.core.sandbox._preamble import build_preamble
from kest.core.sandbox._provider import SandboxProvider
from kest.core.sandbox._result import SandboxResult
from kest.core.sandbox._tool_proxy import ToolProxy

logger = logging.getLogger(__name__)

try:
    from e2b_code_interpreter import Sandbox as _E2BSandboxClient
    from e2b_code_interpreter import TimeoutException as _E2BTimeoutException

    _E2B_AVAILABLE = True
except ImportError:
    _E2B_AVAILABLE = False
    _E2BSandboxClient = None  # type: ignore[assignment,misc]
    _E2BTimeoutException = Exception  # type: ignore[assignment,misc]


def _build_e2b_preamble(config: SandboxConfig) -> str:
    """
    Build a kernel-safe preamble for E2B (Jupyter).

    Unlike SubprocessSandbox, Jupyter uses exec() internally for cell evaluation.
    We therefore apply ONLY the sys.meta_path import blocker — not builtin stubs.
    The microVM boundary provides the privilege isolation.

    For allowlist mode, we must NOT purge Jupyter's kernel-internal modules
    (ipykernel, IPython, zmq, tornado, etc.) from sys.modules or the kernel
    crashes mid-stream. Instead we extend the kernel-safe allowlist.
    """
    # Jupyter kernel modules that must never be evicted from sys.modules.
    _JUPYTER_INTERNALS = {
        "ipykernel",
        "IPython",
        "zmq",
        "tornado",
        "comm",
        "traitlets",
        "pygments",
        "dateutil",
        "packaging",
        "six",
        "decorator",
        "debugpy",
        "psutil",
        "stack_data",
        "executing",
        "parso",
        "jedi",
        "prompt_toolkit",
        # CPython bootstrap / encoding infrastructure
        "encodings",
        "codecs",
        "abc",
        "_abc",
        "_io",
        "io",
        "_codecs",
        "threading",
        "queue",
        "_thread",
        "signal",
    }

    safe_allowed = None
    if config.allowed_modules is not None:
        # Merge user allowlist with Jupyter internals
        safe_allowed = list(set(config.allowed_modules) | _JUPYTER_INTERNALS)

    safe_config = SandboxConfig(
        blocked_builtins=[],  # no builtin stubs — exec() is kernel-unsafe
        blocked_modules=config.blocked_modules,
        allowed_modules=safe_allowed,
        allowed_packages=config.allowed_packages,
        package_index_url=config.package_index_url,
        network_mode=config.network_mode,
    )
    return build_preamble(safe_config)


class E2BSandbox(SandboxProvider):
    """
    Sandbox using E2B's Firecracker microVM code interpreter.

    Network isolation is template-level (set at E2B dashboard / template creation).
    The sys.meta_path import blocker is injected before user code.

    Required environment variable: E2B_API_KEY
    """

    def __init__(self, api_key: str | None = None) -> None:
        if not _E2B_AVAILABLE:
            raise SandboxNotAvailableError(
                "E2BSandbox requires the [e2b] extra. Run: uv add 'kest-core[e2b]'"
            )
        self._api_key = api_key or os.environ.get("E2B_API_KEY")
        if not self._api_key:
            raise SandboxNotAvailableError(
                "E2BSandbox requires E2B_API_KEY to be set in the environment."
            )

    async def execute(
        self,
        script: str,
        tool_proxy: ToolProxy,
        timeout_seconds: int = 30,
        config: SandboxConfig | None = None,
    ) -> SandboxResult:
        config = config or SandboxConfig()
        tool_proxy.reset()

        preamble = _build_e2b_preamble(config)
        full_script = preamble + "\n" + script

        loop = asyncio.get_event_loop()
        try:
            result = await loop.run_in_executor(
                None, self._run_sync, full_script, config, timeout_seconds
            )
        except _E2BTimeoutException:
            raise SandboxTimeoutError(
                f"E2B script exceeded timeout of {timeout_seconds}s"
            )

        return SandboxResult(
            stdout=result["stdout"],
            stderr=result["stderr"],
            return_value=result.get("return_value"),
            exit_code=result["exit_code"],
            taints_added=tool_proxy.accumulated_taints,
        )

    def _run_sync(
        self, script: str, config: SandboxConfig, timeout_seconds: int
    ) -> dict:
        assert _E2BSandboxClient is not None
        # v1 SDK: use Sandbox.create() factory, not the constructor directly
        with _E2BSandboxClient.create(api_key=self._api_key) as sandbox:
            # Pre-install packages if requested (before user code)
            if config.allowed_packages:
                install_script = (
                    f"import subprocess; subprocess.run("
                    f"['pip', 'install', '-q'] + {config.allowed_packages!r}, check=True)"
                )
                sandbox.run_code(install_script)

            execution = sandbox.run_code(script, timeout=float(timeout_seconds))

        stdout_lines = execution.logs.stdout if execution.logs else []
        stderr_lines = execution.logs.stderr if execution.logs else []

        if execution.error:
            err = execution.error
            stderr = f"{err.name}: {err.value}"
            if err.traceback:
                stderr += "\n" + err.traceback
            # Prepend any kernel stderr too
            if stderr_lines:
                stderr = "\n".join(stderr_lines) + "\n" + stderr
            exit_code = 1
        else:
            stdout = "\n".join(stdout_lines)
            # Fallback: rich text output from the kernel
            if not stdout and execution.text:
                stdout = execution.text
            return {
                "stdout": stdout,
                "stderr": "\n".join(stderr_lines),
                "exit_code": 0,
            }

        return {
            "stdout": "\n".join(stdout_lines),
            "stderr": stderr,
            "exit_code": exit_code,
        }

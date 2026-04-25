"""SubprocessSandbox — baseline CPython sandbox via ephemeral uv venv.

No optional extras required. Uses sys.meta_path import blocking and
__builtins__ replacement for security enforcement.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
import tempfile
from pathlib import Path
from typing import Any

from kest.core.sandbox._config import SandboxConfig
from kest.core.sandbox._errors import SandboxTimeoutError
from kest.core.sandbox._preamble import build_preamble
from kest.core.sandbox._provider import SandboxProvider
from kest.core.sandbox._result import SandboxResult
from kest.core.sandbox._tool_proxy import ToolProxy

logger = logging.getLogger(__name__)

# IPC wrapper — injected AFTER the preamble. Reuses _kest_sys and _kest_json
# which are pre-imported by the preamble BEFORE any builtin stubs are applied.
_IPC_WRAPPER_TEMPLATE = """\
class _KestToolBridge:
    \"\"\"Forwards call_tool() to the host process via JSON lines on stdout/stdin.\"\"\"
    _taints: set[str] = set()

    def __call__(self, tool_name: str, args: dict):
        msg = _kest_json.dumps({{"type": "call_tool", "tool_name": tool_name, "args": args}})
        print(msg, flush=True)
        raw = _kest_sys.stdin.readline()
        response = _kest_json.loads(raw)
        if response.get("error"):
            raise RuntimeError(response["error"])
        taints = response.get("taints", [])
        self._taints.update(taints)
        return response["result"]

call_tool = _KestToolBridge()

# ── User script ───────────────────────────────────────────────────────────
{user_script}
# ── End user script ───────────────────────────────────────────────────────
print(_kest_json.dumps({{"type": "done", "taints": list(call_tool._taints)}}), flush=True)
"""


class SubprocessSandbox(SandboxProvider):
    """
    Baseline sandbox using CPython in a child process.

    Isolation:
    - OS process boundary — host memory, env vars, and open FDs are inaccessible.
    - Import hook (sys.meta_path) blocks dangerous modules.
    - __builtins__ override stubs out dangerous builtins.
    - Ephemeral uv venv per execute() when allowed_packages is set.

    Security note:
    Native-extension packages (.so/.pyd) can bypass the Python-level import hook.
    For SubprocessSandbox, restrict allowed_packages to pure-Python packages
    from a controlled package_index_url.
    """

    async def execute(
        self,
        script: str,
        tool_proxy: ToolProxy,
        timeout_seconds: int = 30,
        config: SandboxConfig | None = None,
    ) -> SandboxResult:
        config = config or SandboxConfig()
        tool_proxy.reset()

        with tempfile.TemporaryDirectory(prefix="kest_sandbox_") as tmpdir:
            tmp = Path(tmpdir)
            python_bin = await self._prepare_venv(tmp, config)
            script_path = self._write_script(tmp, config, script)

            try:
                return await asyncio.wait_for(
                    self._run(python_bin, script_path, tool_proxy, config),
                    timeout=timeout_seconds,
                )
            except asyncio.TimeoutError:
                raise SandboxTimeoutError(
                    f"Script exceeded timeout of {timeout_seconds}s"
                )

    # ── internal helpers ─────────────────────────────────────────────────────

    async def _prepare_venv(self, tmp: Path, config: SandboxConfig) -> Path:
        """Create an ephemeral uv venv if packages are needed, return python path."""
        if not config.allowed_packages:
            return Path(sys.executable)

        venv_dir = tmp / ".sandbox-venv"
        uv_args = ["uv", "venv", str(venv_dir)]
        proc = await asyncio.create_subprocess_exec(
            *uv_args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError(f"uv venv failed: {stderr.decode()}")

        pip_args = [
            "uv",
            "pip",
            "install",
            "--python",
            str(venv_dir),
            "--quiet",
        ]
        if config.package_index_url:
            pip_args += ["--index-url", config.package_index_url]
        pip_args += config.allowed_packages

        proc = await asyncio.create_subprocess_exec(
            *pip_args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError(f"uv pip install failed: {stderr.decode()}")

        return venv_dir / "bin" / "python"

    def _write_script(self, tmp: Path, config: SandboxConfig, user_script: str) -> Path:
        """Combine preamble + IPC wrapper + user script into a temp file."""
        preamble = build_preamble(config)
        full = preamble + _IPC_WRAPPER_TEMPLATE.format(user_script=user_script)
        path = tmp / "script.py"
        path.write_text(full, encoding="utf-8")
        return path

    async def _run(
        self,
        python_bin: Path,
        script_path: Path,
        tool_proxy: ToolProxy,
        config: SandboxConfig,
    ) -> SandboxResult:
        """Start the subprocess, drive the IPC tool-call loop, return result."""
        import os

        # Minimal env: only PATH so the child can find stdlib dynamic libs.
        # All other host env vars (secrets, tokens, credentials) are stripped.
        safe_env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}

        proc = await asyncio.create_subprocess_exec(
            str(python_bin),
            str(script_path),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=safe_env,
        )

        stdout_lines: list[str] = []
        return_value: Any = None
        sandbox_taints: frozenset[str] = frozenset()

        assert proc.stdout is not None
        assert proc.stdin is not None
        assert proc.stderr is not None

        try:
            # Read stdout line by line; handle IPC messages inline.
            async for raw_line in proc.stdout:
                line = raw_line.decode("utf-8", errors="replace").rstrip("\n")
                if not line:
                    continue

                # Try to parse as an IPC message
                if line.startswith("{"):
                    try:
                        msg = json.loads(line)
                        msg_type = msg.get("type")

                        if msg_type == "call_tool":
                            tool_name = msg["tool_name"]
                            args = msg.get("args", {})
                            try:
                                result = await tool_proxy.call_tool(tool_name, args)
                                response = {"result": result, "taints": []}
                            except Exception as exc:
                                response = {
                                    "result": None,
                                    "error": str(exc),
                                    "taints": [],
                                }
                            reply = json.dumps(response) + "\n"
                            proc.stdin.write(reply.encode())
                            await proc.stdin.drain()
                            continue

                        if msg_type == "done":
                            sandbox_taints = frozenset(msg.get("taints", []))
                            continue
                    except json.JSONDecodeError:
                        pass  # not an IPC message — treat as stdout

                stdout_lines.append(line)

        except asyncio.CancelledError:
            # Timeout fired — kill the child process cleanly then re-raise
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            await proc.wait()
            raise

        # Drain stderr and wait for exit
        stderr_data = await proc.stderr.read()
        await proc.wait()
        exit_code = proc.returncode or 0

        all_taints = tool_proxy.accumulated_taints | sandbox_taints

        return SandboxResult(
            stdout="\n".join(stdout_lines),
            stderr=stderr_data.decode("utf-8", errors="replace"),
            return_value=return_value,
            exit_code=exit_code,
            taints_added=all_taints,
        )

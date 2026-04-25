"""Tests for SubprocessSandbox — real subprocess execution, no mocking.

These tests run an actual child Python process via SubprocessSandbox.
No infrastructure (E2B, AWS) is required. The ToolProxy is a minimal
in-process implementation (not mocked) that records calls for assertion.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from kest.core.sandbox import (
    SandboxConfig,
    SandboxResult,
    SandboxTimeoutError,
    SubprocessSandbox,
    ToolProxy,
)

# ── Minimal ToolProxy (not a mock — it runs real logic) ─────────────────────


class RecordingToolProxy(ToolProxy):
    """A real ToolProxy that records calls and accumulates taints.
    Used in tests to verify the IPC call/response cycle end-to-end.
    """

    def __init__(self, return_values: dict[str, Any] | None = None):
        self._calls: list[tuple[str, dict]] = []
        self._taints: set[str] = set()
        self._return_values = return_values or {}

    async def call_tool(self, tool_name: str, args: dict) -> Any:
        self._calls.append((tool_name, args))
        # Simulate that some tools return taint-laden results
        if tool_name in ("read_secret", "fetch_pii"):
            self._taints.add("SENSITIVE")
        return self._return_values.get(tool_name, f"result_of_{tool_name}")

    @property
    def accumulated_taints(self) -> frozenset[str]:
        return frozenset(self._taints)

    def reset(self) -> None:
        self._calls.clear()
        self._taints.clear()

    @property
    def calls(self) -> list[tuple[str, dict]]:
        return list(self._calls)


# ── Helpers ──────────────────────────────────────────────────────────────────


def run(coro):
    """Run a coroutine in a fresh event loop (pytest-asyncio marks can be used
    but we keep plain helpers for clarity)."""
    return asyncio.get_event_loop().run_until_complete(coro)


SANDBOX = SubprocessSandbox()


# ── Basic execution ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_prints_stdout():
    """A script that prints text produces it in SandboxResult.stdout."""
    proxy = RecordingToolProxy()
    result = await SANDBOX.execute('print("hello sandbox")', proxy)

    assert isinstance(result, SandboxResult)
    assert "hello sandbox" in result.stdout
    assert result.exit_code == 0


@pytest.mark.asyncio
async def test_multiple_prints():
    script = 'print("line1")\nprint("line2")\nprint("line3")'
    proxy = RecordingToolProxy()
    result = await SANDBOX.execute(script, proxy)

    assert "line1" in result.stdout
    assert "line2" in result.stdout
    assert "line3" in result.stdout


@pytest.mark.asyncio
async def test_stderr_captured():
    """Stderr from the child process ends up in SandboxResult.stderr."""
    script = "import sys; sys.stderr.write('oops\\n')"
    proxy = RecordingToolProxy()
    result = await SANDBOX.execute(script, proxy)

    assert "oops" in result.stderr


@pytest.mark.asyncio
async def test_script_error_returns_nonzero_exit_code():
    """An uncaught exception in the script produces non-zero exit_code."""
    proxy = RecordingToolProxy()
    result = await SANDBOX.execute("raise ValueError('intentional')", proxy)

    assert result.exit_code != 0
    assert (
        result.stdout == "" or "Traceback" not in result.stdout
    )  # error goes to stderr
    assert "ValueError" in result.stderr


# ── Preamble security (import blocking) ──────────────────────────────────────


@pytest.mark.asyncio
async def test_blocked_module_raises_import_error():
    """socket is in the default blocked_modules list; importing it must fail."""
    proxy = RecordingToolProxy()
    result = await SANDBOX.execute("import socket", proxy)

    assert result.exit_code != 0
    assert "not allowed" in result.stderr or "ImportError" in result.stderr


@pytest.mark.asyncio
async def test_blocked_subprocess_module():
    proxy = RecordingToolProxy()
    result = await SANDBOX.execute("import subprocess", proxy)
    assert result.exit_code != 0


@pytest.mark.asyncio
async def test_allowed_module_allowlist_permits():
    """With an explicit allowlist, an allowed module imports successfully."""
    config = SandboxConfig(
        allowed_modules=["math"],
        blocked_modules=[],  # no block-list; allowlist does the filtering
    )
    proxy = RecordingToolProxy()
    result = await SANDBOX.execute("import math; print(math.pi)", proxy, config=config)
    assert result.exit_code == 0
    assert "3.14" in result.stdout


@pytest.mark.asyncio
async def test_allowlist_blocks_unlisted_module():
    """With an allowlist, importing anything not on it must fail."""
    config = SandboxConfig(
        allowed_modules=["math"],
        blocked_modules=[],
    )
    proxy = RecordingToolProxy()
    result = await SANDBOX.execute("import os", proxy, config=config)
    assert result.exit_code != 0
    assert "allowlist" in result.stderr


# ── Preamble security (builtin blocking) ─────────────────────────────────────


@pytest.mark.asyncio
async def test_blocked_builtin_open_raises():
    """open() is in the default blocked_builtins; using it raises SecurityError."""
    proxy = RecordingToolProxy()
    result = await SANDBOX.execute("open('/etc/passwd', 'r')", proxy)
    assert result.exit_code != 0
    # SecurityError or TypeError from the stub
    assert "open" in result.stderr or result.exit_code != 0


@pytest.mark.asyncio
async def test_blocked_builtin_eval_raises():
    proxy = RecordingToolProxy()
    result = await SANDBOX.execute("eval('1+1')", proxy)
    assert result.exit_code != 0


@pytest.mark.asyncio
async def test_blocked_builtin_exec_raises():
    proxy = RecordingToolProxy()
    result = await SANDBOX.execute("exec('x=1')", proxy)
    assert result.exit_code != 0


# ── IPC tool-call round-trip ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_tool_call_roundtrip():
    """Script calls call_tool(); host proxy handles it; result is echoed back."""
    proxy = RecordingToolProxy(return_values={"get_data": "42"})
    script = """
result = call_tool("get_data", {"key": "answer"})
print(result)
"""
    result = await SANDBOX.execute(script, proxy)

    assert result.exit_code == 0
    assert "42" in result.stdout
    assert len(proxy.calls) == 1
    tool_name, args = proxy.calls[0]
    assert tool_name == "get_data"
    assert args == {"key": "answer"}


@pytest.mark.asyncio
async def test_multiple_tool_calls_ordered():
    """Tool calls within the script are executed and recorded in order."""
    proxy = RecordingToolProxy(return_values={"step1": "a", "step2": "b"})
    script = """
r1 = call_tool("step1", {})
r2 = call_tool("step2", {"prev": r1})
print(r1, r2)
"""
    result = await SANDBOX.execute(script, proxy)

    assert result.exit_code == 0
    assert "a b" in result.stdout
    assert [c[0] for c in proxy.calls] == ["step1", "step2"]
    # step2 received the return value of step1 as arg
    assert proxy.calls[1][1]["prev"] == "a"


@pytest.mark.asyncio
async def test_taint_propagation_from_tool():
    """Calling 'read_secret' via proxy adds SENSITIVE taint to the result."""
    proxy = RecordingToolProxy(return_values={"read_secret": "s3cr3t"})
    script = 'result = call_tool("read_secret", {"id": "key1"})\nprint(result)'
    result = await SANDBOX.execute(script, proxy)

    assert result.exit_code == 0
    assert "SENSITIVE" in result.taints_added


@pytest.mark.asyncio
async def test_no_taints_without_sensitive_tool_call():
    """A tool call that doesn't add taints leaves taints_added empty."""
    proxy = RecordingToolProxy(return_values={"ping": "pong"})
    result = await SANDBOX.execute('call_tool("ping", {})', proxy)
    assert result.exit_code == 0
    assert result.taints_added == frozenset()


# ── Proxy reset between calls ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_proxy_reset_between_execute_calls():
    """reset() is called at the start of each execute(); taints don't leak."""
    proxy = RecordingToolProxy(return_values={"read_secret": "x"})

    await SANDBOX.execute('call_tool("read_secret", {})', proxy)
    assert "SENSITIVE" in proxy.accumulated_taints

    # Second execute — taints from first run must NOT carry over
    result = await SANDBOX.execute('print("clean")', proxy)
    assert result.taints_added == frozenset()
    assert "SENSITIVE" not in proxy.accumulated_taints


# ── Timeout ──────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_timeout_raises_sandbox_timeout_error():
    """A script that sleeps longer than timeout_seconds raises SandboxTimeoutError."""
    proxy = RecordingToolProxy()
    with pytest.raises(SandboxTimeoutError):
        await SANDBOX.execute("import time; time.sleep(60)", proxy, timeout_seconds=2)


# ── Env isolation ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_host_env_vars_not_leaked():
    """The child process runs with an empty environment."""
    import os

    os.environ["KEST_SECRET_TEST"] = "should_not_leak"
    proxy = RecordingToolProxy()
    script = """
import os
val = os.environ.get("KEST_SECRET_TEST", "NOT_PRESENT")
print(val)
"""
    result = await SANDBOX.execute(script, proxy)
    # os module itself is not blocked by default; but env var must not be present
    assert "NOT_PRESENT" in result.stdout
    del os.environ["KEST_SECRET_TEST"]


# ── Custom config smoke tests ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_empty_blocked_builtins_allows_open():
    """When blocked_builtins is empty, open() is allowed."""
    import os
    import tempfile

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("safe_content")
        fname = f.name

    config = SandboxConfig(blocked_builtins=[], blocked_modules=[])
    proxy = RecordingToolProxy()
    script = f"f = open({fname!r}); print(f.read()); f.close()"
    result = await SANDBOX.execute(script, proxy, config=config)
    os.unlink(fname)

    assert result.exit_code == 0
    assert "safe_content" in result.stdout

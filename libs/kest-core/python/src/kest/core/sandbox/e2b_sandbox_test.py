"""E2BSandbox live integration tests.

Requires: E2B_API_KEY in the environment.
Run with:
    E2B_API_KEY=<key> uv run pytest -m sandbox_live -v src/kest/core/sandbox/e2b_sandbox_test.py

These tests spin up real Firecracker microVMs. They are skipped automatically
if E2B_API_KEY is not set.
"""

from __future__ import annotations

import os
from typing import Any

import pytest

from kest.core.sandbox import (
    SandboxConfig,
    SandboxResult,
    SandboxTimeoutError,
    ToolProxy,
)

# ── Skip marker ───────────────────────────────────────────────────────────────

_API_KEY = os.environ.get("E2B_API_KEY")
pytestmark = pytest.mark.sandbox_live

skip_no_key = pytest.mark.skipif(
    not _API_KEY, reason="E2B_API_KEY not set; skipping live E2B tests"
)


# ── Inline ToolProxy ──────────────────────────────────────────────────────────


class SimpleProxy(ToolProxy):
    """Minimal real proxy — no mocking; records calls and accumulates taints."""

    def __init__(self, return_values: dict[str, Any] | None = None):
        self._calls: list[tuple[str, dict]] = []
        self._taints: set[str] = set()
        self._return_values = return_values or {}

    async def call_tool(self, tool_name: str, args: dict) -> Any:
        self._calls.append((tool_name, args))
        if tool_name in ("read_secret", "fetch_pii"):
            self._taints.add("SENSITIVE")
        return self._return_values.get(tool_name, f"result_of_{tool_name}")

    @property
    def accumulated_taints(self) -> frozenset[str]:
        return frozenset(self._taints)

    def reset(self) -> None:
        self._calls.clear()
        self._taints.clear()


# ── Lazy import so the test file doesn't crash without the extra installed ────


def _get_sandbox():
    try:
        from kest.core.sandbox import E2BSandbox

        return E2BSandbox(api_key=_API_KEY)
    except Exception as exc:
        pytest.skip(f"E2BSandbox not available: {exc}")


# ── Tests ─────────────────────────────────────────────────────────────────────


@skip_no_key
@pytest.mark.asyncio
async def test_e2b_basic_execution():
    """A simple print statement executes and stdout is captured."""
    sandbox = _get_sandbox()
    proxy = SimpleProxy()
    result = await sandbox.execute('print("e2b-hello")', proxy)

    assert isinstance(result, SandboxResult)
    assert "e2b-hello" in result.stdout
    assert result.exit_code == 0


@skip_no_key
@pytest.mark.asyncio
async def test_e2b_arithmetic():
    """Arithmetic in the sandbox produces the expected result."""
    sandbox = _get_sandbox()
    proxy = SimpleProxy()
    result = await sandbox.execute("print(6 * 7)", proxy)

    assert result.exit_code == 0
    assert "42" in result.stdout


@skip_no_key
@pytest.mark.asyncio
async def test_e2b_multiline_script():
    """A multi-step script maintains state across statements."""
    sandbox = _get_sandbox()
    proxy = SimpleProxy()
    script = """
x = 10
y = 20
z = x + y
print(f"sum={z}")
"""
    result = await sandbox.execute(script, proxy)
    assert result.exit_code == 0
    assert "sum=30" in result.stdout


@skip_no_key
@pytest.mark.asyncio
async def test_e2b_stdlib_import():
    """Standard library imports work inside the microVM."""
    sandbox = _get_sandbox()
    proxy = SimpleProxy()
    result = await sandbox.execute(
        "import math; print(round(math.sqrt(144), 1))", proxy
    )
    assert result.exit_code == 0
    assert "12" in result.stdout


@skip_no_key
@pytest.mark.asyncio
async def test_e2b_script_error_captured():
    """An uncaught exception produces a non-zero exit code and stderr output."""
    sandbox = _get_sandbox()
    proxy = SimpleProxy()
    result = await sandbox.execute("raise RuntimeError('e2b-boom')", proxy)

    assert result.exit_code != 0
    assert "e2b-boom" in result.stderr or "RuntimeError" in result.stderr


@skip_no_key
@pytest.mark.asyncio
async def test_e2b_blocked_module_import():
    """Default blocked_modules (e.g. socket) are rejected by the preamble."""
    sandbox = _get_sandbox()
    proxy = SimpleProxy()
    result = await sandbox.execute("import socket", proxy)

    assert result.exit_code != 0
    assert "not allowed" in result.stderr or "ImportError" in result.stderr


@skip_no_key
@pytest.mark.asyncio
async def test_e2b_custom_allowlist():
    """An explicit allowed_modules allowlist blocks non-listed imports."""
    sandbox = _get_sandbox()
    config = SandboxConfig(allowed_modules=["math"], blocked_modules=[])
    proxy = SimpleProxy()
    result = await sandbox.execute("import os", proxy, config=config)

    assert result.exit_code != 0
    assert "allowlist" in result.stderr


@skip_no_key
@pytest.mark.asyncio
async def test_e2b_result_is_isolated_between_calls():
    """Two execute() calls produce independent results; no state shared between runs."""
    sandbox = _get_sandbox()
    proxy = SimpleProxy()

    r1 = await sandbox.execute("x = 99; print(x)", proxy)
    r2 = await sandbox.execute("print(x)", proxy)  # x should NOT exist in r2

    assert r1.exit_code == 0
    assert "99" in r1.stdout
    # Second sandbox has a fresh microVM — x is undefined
    assert r2.exit_code != 0


@skip_no_key
@pytest.mark.asyncio
async def test_e2b_timeout():
    """A long-running script is terminated when timeout_seconds is exceeded."""
    sandbox = _get_sandbox()
    proxy = SimpleProxy()

    with pytest.raises(SandboxTimeoutError):
        await sandbox.execute("import time; time.sleep(300)", proxy, timeout_seconds=5)

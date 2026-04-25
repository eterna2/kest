"""Tests for MontySandbox (pydantic-monty Rust interpreter backend).

Design notes
------------
* pydantic_monty is an optional extra (``kest[monty]``).  All tests skip
  gracefully when the package is absent.
* The Monty interpreter runs Rust-in-process — no subprocess, no network,
  no filesystem access.  Tests are entirely in-process with no external
  calls, so they never carry the ``sandbox_live`` marker.
* The ``run_async`` API returns the last evaluated expression as the Python
  object directly; stdout is captured via ``print_callback``.
* Timeout is enforced via ``asyncio.wait_for``; a ``TimeoutError`` is
  re-raised as ``SandboxTimeoutError``.
* ``SandboxConfig`` fields that Monty cannot honour (``allowed_modules``,
  ``blocked_modules``, ``blocked_builtins``, ``allowed_packages``,
  ``package_index_url``) trigger a WARNING rather than an error.
"""

from __future__ import annotations

import logging

import pytest

from kest.core.sandbox import (
    SandboxConfig,
    SandboxResult,
    SandboxTimeoutError,
    ToolProxy,
)

# ── skip guard ────────────────────────────────────────────────────────────────

try:
    import pydantic_monty  # noqa: F401

    _MONTY_AVAILABLE = True
except ImportError:
    _MONTY_AVAILABLE = False

skip_if_no_monty = pytest.mark.skipif(
    not _MONTY_AVAILABLE,
    reason="pydantic-monty not installed (run: uv add 'kest-core[monty]')",
)

# ── helpers ───────────────────────────────────────────────────────────────────


class _EchoProxy(ToolProxy):
    """Returns a configurable static value for every tool call and records args."""

    def __init__(
        self, return_value: object = "echo_result", taints: frozenset[str] = frozenset()
    ) -> None:
        self._return_value = return_value
        self._taints = taints
        self.calls: list[tuple[str, tuple, dict]] = []

    async def call_tool(
        self, tool_name: str, *args: object, **kwargs: object
    ) -> object:
        self.calls.append((tool_name, args, kwargs))
        return self._return_value

    @property
    def accumulated_taints(self) -> frozenset[str]:
        return self._taints

    def reset(self) -> None:
        self.calls.clear()


# ── basic execution ───────────────────────────────────────────────────────────


@skip_if_no_monty
async def test_monty_basic_print_captured_as_stdout() -> None:
    from kest.core.sandbox.monty_sandbox import MontySandbox

    sandbox = MontySandbox()
    proxy = _EchoProxy()
    result = await sandbox.execute(
        script='print("hello monty")',
        tool_proxy=proxy,
    )
    assert isinstance(result, SandboxResult)
    assert "hello monty" in result.stdout
    assert result.exit_code == 0


@skip_if_no_monty
async def test_monty_arithmetic_return_value() -> None:
    from kest.core.sandbox.monty_sandbox import MontySandbox

    sandbox = MontySandbox()
    proxy = _EchoProxy()
    result = await sandbox.execute(script="1 + 2", tool_proxy=proxy)
    assert result.return_value == 3
    assert result.exit_code == 0


@skip_if_no_monty
async def test_monty_multiline_script() -> None:
    from kest.core.sandbox.monty_sandbox import MontySandbox

    sandbox = MontySandbox()
    proxy = _EchoProxy()
    result = await sandbox.execute(
        script="x = 6\ny = 7\nprint(x * y)",
        tool_proxy=proxy,
    )
    assert "42" in result.stdout
    assert result.exit_code == 0


# ── error handling ────────────────────────────────────────────────────────────


@skip_if_no_monty
async def test_monty_runtime_error_sets_nonzero_exit_and_stderr() -> None:
    from kest.core.sandbox.monty_sandbox import MontySandbox

    sandbox = MontySandbox()
    proxy = _EchoProxy()
    result = await sandbox.execute(
        script='raise RuntimeError("boom")',
        tool_proxy=proxy,
    )
    assert result.exit_code != 0
    assert "RuntimeError" in result.stderr or "boom" in result.stderr


@skip_if_no_monty
async def test_monty_syntax_error_sets_nonzero_exit_and_stderr() -> None:
    from kest.core.sandbox.monty_sandbox import MontySandbox

    sandbox = MontySandbox()
    proxy = _EchoProxy()
    result = await sandbox.execute(
        script="def (: pass",
        tool_proxy=proxy,
    )
    assert result.exit_code != 0
    assert result.stderr != ""


# ── tool call bridge ──────────────────────────────────────────────────────────


@skip_if_no_monty
async def test_monty_tool_call_roundtrip() -> None:
    """Monty pauses at call_tool(), bridge awaits proxy, resumes with value."""
    from kest.core.sandbox.monty_sandbox import MontySandbox

    proxy = _EchoProxy(return_value="injected")
    sandbox = MontySandbox()
    result = await sandbox.execute(
        script='x = call_tool("add", 1, 2)\nprint(x)',
        tool_proxy=proxy,
    )
    assert result.exit_code == 0
    assert "injected" in result.stdout
    assert len(proxy.calls) == 1
    assert proxy.calls[0][0] == "add"


@skip_if_no_monty
async def test_monty_multiple_tool_calls_ordered() -> None:
    from kest.core.sandbox.monty_sandbox import MontySandbox

    proxy = _EchoProxy(return_value=99)
    sandbox = MontySandbox()
    result = await sandbox.execute(
        script='a = call_tool("t1")\nb = call_tool("t2")\nprint(a + b)',
        tool_proxy=proxy,
    )
    assert result.exit_code == 0
    assert len(proxy.calls) == 2
    assert proxy.calls[0][0] == "t1"
    assert proxy.calls[1][0] == "t2"


@skip_if_no_monty
async def test_monty_taint_propagation_from_proxy() -> None:
    from kest.core.sandbox.monty_sandbox import MontySandbox

    proxy = _EchoProxy(taints=frozenset(["pii", "secret"]))
    sandbox = MontySandbox()
    result = await sandbox.execute(
        script='call_tool("fetch_user")',
        tool_proxy=proxy,
    )
    assert "pii" in result.taints_added
    assert "secret" in result.taints_added


# ── proxy reset isolation ─────────────────────────────────────────────────────


@skip_if_no_monty
async def test_monty_proxy_reset_between_execute_calls() -> None:
    """proxy.reset() is called at the start of each execute() — no leakage."""
    from kest.core.sandbox.monty_sandbox import MontySandbox

    proxy = _EchoProxy()
    sandbox = MontySandbox()

    await sandbox.execute(script='call_tool("first")', tool_proxy=proxy)
    assert len(proxy.calls) == 1

    await sandbox.execute(script='call_tool("second")', tool_proxy=proxy)
    # After reset, only the second call should remain.
    assert len(proxy.calls) == 1
    assert proxy.calls[0][0] == "second"


# ── timeout ───────────────────────────────────────────────────────────────────


@skip_if_no_monty
async def test_monty_timeout_raises_sandbox_timeout_error() -> None:
    from kest.core.sandbox.monty_sandbox import MontySandbox

    sandbox = MontySandbox()
    proxy = _EchoProxy()
    with pytest.raises(SandboxTimeoutError):
        await sandbox.execute(
            script="i = 0\nwhile True:\n  i += 1",
            tool_proxy=proxy,
            timeout_seconds=0.3,
        )


# ── unsupported config warnings ───────────────────────────────────────────────


@skip_if_no_monty
async def test_monty_warns_on_unsupported_blocked_modules(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from kest.core.sandbox.monty_sandbox import MontySandbox

    proxy = _EchoProxy()
    sandbox = MontySandbox()
    with caplog.at_level(logging.WARNING):
        await sandbox.execute(
            script="print(1)",
            tool_proxy=proxy,
            config=SandboxConfig(blocked_modules=["socket"]),
        )
    assert any("blocked_modules" in r.message for r in caplog.records)


@skip_if_no_monty
async def test_monty_warns_on_unsupported_allowed_packages(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from kest.core.sandbox.monty_sandbox import MontySandbox

    proxy = _EchoProxy()
    sandbox = MontySandbox()
    with caplog.at_level(logging.WARNING):
        await sandbox.execute(
            script="print(1)",
            tool_proxy=proxy,
            config=SandboxConfig(allowed_packages=["numpy"]),
        )
    assert any("allowed_packages" in r.message for r in caplog.records)


@skip_if_no_monty
async def test_monty_no_warning_when_config_is_clean(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from kest.core.sandbox.monty_sandbox import MontySandbox

    proxy = _EchoProxy()
    sandbox = MontySandbox()
    with caplog.at_level(logging.WARNING):
        await sandbox.execute(
            script="print(1)",
            tool_proxy=proxy,
            config=SandboxConfig(),  # all defaults → no warnings
        )
    monty_warnings = [r for r in caplog.records if "MontySandbox" in r.name]
    assert not any(
        any(
            field in r.message
            for field in (
                "blocked_modules",
                "allowed_modules",
                "blocked_builtins",
                "allowed_packages",
                "package_index_url",
            )
        )
        for r in monty_warnings
    )

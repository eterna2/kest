"""AgentCoreSandbox integration tests.

Architecture
------------
The AgentCore Code Interpreter *resource* is provisioned via IaC and identified
by a ``codeInterpreterIdentifier`` (e.g. ``"aws.codeinterpreter.v1"`` or a
custom ARN).  The SDK never creates or deletes this resource.

Sessions (``StartCodeInterpreterSession`` / ``StopCodeInterpreterSession``) are
the only runtime lifecycle boundary.

Cost / quota strategy for testing
----------------------------------
To avoid unnecessary session-creation API calls and stay within AWS per-account
session quotas:

1. **Preferred**: Supply a pre-existing session ID via ``AGENTCORE_SESSION_ID``.
   The sandbox will use it as-is — no ``Start`` / ``Stop`` calls at all.

2. **Fallback**: If no session ID is supplied, the test suite creates exactly
   ONE session using ``sandbox.session()`` (a single ``Start`` call) and runs
   all scenarios inside it.

Running the live suite
-----------------------
Prerequisites:

    # IAM credentials in the boto3 credential chain
    # (for SSO/credential-process profiles use):
    eval "$(aws configure export-credentials --format env)"

    # Code interpreter resource: either use the AWS-managed default or a custom one
    # provisioned with:
    #   aws bedrock-agentcore create-code-interpreter --name my-kest-ci \\
    #       --network-configuration '{"networkMode":"vpc"}' \\
    #       --region us-east-1

    # To skip session Start/Stop costs — reuse an existing session:
    export AGENTCORE_SESSION_ID="<existing-session-id>"
    export AGENTCORE_CODE_INTERPRETER_ID="aws.codeinterpreter.v1"  # or custom ARN
    export AGENTCORE_REGION="us-east-1"

    uv run pytest -m sandbox_live -v src/kest/core/sandbox/agentcore_sandbox_test.py

Note on AWS_BEARER_TOKEN (ABSK):
  ABSK tokens are intra-AgentCore runtime credentials.  They are NOT valid for
  external API access.  Use standard IAM credentials only.

Tests skip automatically when:
  - No IAM credentials are found in the boto3 chain.
  - The ``AGENTCORE_CODE_INTERPRETER_ID`` resource is not reachable.

Warning-mode tests (network_mode=vpc/public/sandbox) run without live AWS
connectivity — they use a mock boto3 client.
"""

from __future__ import annotations

import logging
import os
from typing import Any
from unittest.mock import MagicMock

import pytest

from kest.core.sandbox import (
    SandboxConfig,
    SandboxResult,
    SandboxTimeoutError,
    ToolProxy,
)

# ── Markers ───────────────────────────────────────────────────────────────────

pytestmark = pytest.mark.sandbox_live

# ── Environment config ────────────────────────────────────────────────────────

_REGION = os.environ.get("AGENTCORE_REGION", "ap-southeast-1")
_CODE_INTERPRETER_ID = os.environ.get(
    "AGENTCORE_CODE_INTERPRETER_ID", "aws.codeinterpreter.v1"
)
_INJECTED_SESSION_ID = os.environ.get("AGENTCORE_SESSION_ID")  # may be None

# ── IAM credential probe ──────────────────────────────────────────────────────


def _resolve_iam_creds() -> bool:
    """Return True if boto3 can resolve IAM credentials from any source.

    ABSK bearer tokens (``AWS_BEARER_TOKEN``) are excluded — they are
    intra-AgentCore credentials not valid for direct API access.
    """
    try:
        import boto3

        session = boto3.Session()
        creds = session.get_credentials()
        if creds is None:
            return False
        return bool(getattr(creds, "access_key", None))
    except Exception:
        return False


_HAS_IAM_CREDS = _resolve_iam_creds()

skip_no_creds = pytest.mark.skipif(
    not _HAS_IAM_CREDS,
    reason=(
        "No AWS IAM credentials found in the boto3 credential chain "
        "(env vars, ~/.aws/credentials, instance role, etc.). "
        "For SSO/credential-process profiles run: "
        'eval "$(aws configure export-credentials --format env)" first. '
        "Note: AWS_BEARER_TOKEN (ABSK) is an intra-AgentCore credential "
        "not valid for direct API access. Skipping live AgentCore tests."
    ),
)

# ── Minimal ToolProxy ─────────────────────────────────────────────────────────


class SimpleProxy(ToolProxy):
    """Real (non-mocked) proxy that records calls and accumulates taints."""

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


# ── Sandbox factories ──────────────────────────────────────────────────────────


def _get_sandbox():
    """Build a live AgentCoreSandbox from environment config.

    - Uses ``AGENTCORE_CODE_INTERPRETER_ID`` (defaults to the AWS-managed one).
    - If ``AGENTCORE_SESSION_ID`` is set, injects it — no Start/Stop API calls.
    """
    try:
        from kest.core.sandbox import AgentCoreSandbox

        return AgentCoreSandbox(
            code_interpreter_id=_CODE_INTERPRETER_ID,
            session_id=_INJECTED_SESSION_ID,  # None → sandbox manages sessions itself
            region_name=_REGION,
        )
    except Exception as exc:
        pytest.skip(f"AgentCoreSandbox not available: {exc}")


def _get_sandbox_with_mock_client():
    """Create an AgentCoreSandbox backed by a mock boto3 client.

    Used for tests that validate *local* behaviour (e.g. warning emission)
    without making real API calls.
    """
    from kest.core.sandbox import AgentCoreSandbox

    mock_client = MagicMock()
    # session() context manager calls Start/Stop — mock them
    mock_client.start_code_interpreter_session.return_value = {
        "sessionId": "mock-session-id-001",
        "codeInterpreterIdentifier": _CODE_INTERPRETER_ID,
    }
    stream_event = {
        "result": {
            "isError": False,
            "content": [{"type": "text", "text": "mock-output"}],
        }
    }
    mock_client.invoke_code_interpreter.return_value = {"stream": [stream_event]}
    mock_client.stop_code_interpreter_session.return_value = {}

    # Inject a session_id so the mock sandbox never calls Start/Stop itself
    return AgentCoreSandbox(
        code_interpreter_id=_CODE_INTERPRETER_ID,
        session_id="mock-session-id-001",
        client=mock_client,
    )


# ── Live execution suite ───────────────────────────────────────────────────────


@skip_no_creds
@pytest.mark.asyncio
async def test_agentcore_live_suite():
    """Full live execution suite.

    Session strategy (in priority order):
      1. ``AGENTCORE_SESSION_ID`` set → injected session, zero Start/Stop calls.
      2. Not set → ``sandbox.session()`` starts exactly ONE session for all
         scenarios and stops it when the block exits.

    Each ``execute()`` uses ``clearContext=True`` internally so that previous
    state does not bleed between scenarios.
    """
    sandbox = _get_sandbox()
    proxy = SimpleProxy()

    if _INJECTED_SESSION_ID:
        # Run directly — sandbox reuses the injected session, no Start/Stop.
        await _run_live_scenarios(sandbox, proxy)
    else:
        # Start one shared session for the whole suite.
        async with sandbox.session() as s:
            await _run_live_scenarios(s, proxy)

    # ── timeout test ─────────────────────────────────────────────────────────
    # Uses a separate sandbox/session since the timeout cancels mid-flight.
    with pytest.raises(SandboxTimeoutError):
        sandbox2 = _get_sandbox()
        proxy.reset()
        # Wrap in session() so we start fresh (only relevant if no injected session)
        if _INJECTED_SESSION_ID:
            await sandbox2.execute(
                "import time; time.sleep(300)", proxy, timeout_seconds=2
            )
        else:
            async with sandbox2.session() as s2:
                await s2.execute(
                    "import time; time.sleep(300)", proxy, timeout_seconds=2
                )


async def _run_live_scenarios(sandbox: Any, proxy: SimpleProxy) -> None:
    """Execute a battery of scenarios against the given sandbox.

    All calls share the same session (injected or pinned by session()).
    """
    # ── basic print ──────────────────────────────────────────────────────────
    proxy.reset()
    result = await sandbox.execute('print("agentcore-hello")', proxy)
    assert isinstance(result, SandboxResult), "must return SandboxResult"
    assert "agentcore-hello" in result.stdout, "stdout must contain printed text"
    assert result.exit_code == 0

    # ── arithmetic ───────────────────────────────────────────────────────────
    proxy.reset()
    result = await sandbox.execute("print(6 * 7)", proxy)
    assert result.exit_code == 0
    assert "42" in result.stdout

    # ── multi-line script ─────────────────────────────────────────────────────
    proxy.reset()
    result = await sandbox.execute(
        "x = 10\ny = 20\nz = x + y\nprint(f'sum={z}')", proxy
    )
    assert result.exit_code == 0
    assert "sum=30" in result.stdout

    # ── stdlib import ─────────────────────────────────────────────────────────
    proxy.reset()
    result = await sandbox.execute(
        "import math; print(round(math.sqrt(144), 1))", proxy
    )
    assert result.exit_code == 0
    assert "12" in result.stdout

    # ── error capture ─────────────────────────────────────────────────────────
    proxy.reset()
    result = await sandbox.execute("raise RuntimeError('agentcore-boom')", proxy)
    assert result.exit_code != 0, "uncaught exception must yield non-zero exit"
    assert "agentcore-boom" in result.stderr or "RuntimeError" in result.stderr

    # ── SandboxResult type ────────────────────────────────────────────────────
    proxy.reset()
    result = await sandbox.execute("x = 1", proxy)
    assert isinstance(result, SandboxResult)
    assert isinstance(result.taints_added, frozenset)


# ── Warning-mode tests (mock client — no live credentials needed) ──────────────


@pytest.mark.asyncio
async def test_agentcore_vpc_mode_no_warning(caplog):
    """network_mode='vpc' must not emit any security warnings."""
    sandbox = _get_sandbox_with_mock_client()
    proxy = SimpleProxy()
    config = SandboxConfig(network_mode="vpc")

    with caplog.at_level(logging.WARNING, logger="kest.core.sandbox.agentcore_sandbox"):
        result = await sandbox.execute("print('vpc-ok')", proxy, config=config)

    assert result.exit_code == 0
    warning_msgs = [r.message for r in caplog.records if r.levelno >= logging.WARNING]
    assert not any("DNS egress" in m for m in warning_msgs), (
        f"VPC mode must not warn about DNS egress; got: {warning_msgs}"
    )


@pytest.mark.asyncio
async def test_agentcore_public_mode_emits_warning(caplog):
    """network_mode='public' must emit a DNS egress warning."""
    sandbox = _get_sandbox_with_mock_client()
    proxy = SimpleProxy()
    config = SandboxConfig(network_mode="public")

    with caplog.at_level(logging.WARNING, logger="kest.core.sandbox.agentcore_sandbox"):
        await sandbox.execute("print('public-ok')", proxy, config=config)

    warning_msgs = [r.message for r in caplog.records if r.levelno >= logging.WARNING]
    assert any("DNS egress" in m for m in warning_msgs), (
        f"public mode must warn about DNS egress; got: {warning_msgs}"
    )


@pytest.mark.asyncio
async def test_agentcore_sandbox_mode_emits_warning(caplog):
    """network_mode='sandbox' must emit the DNS-tunnel vulnerability warning."""
    sandbox = _get_sandbox_with_mock_client()
    proxy = SimpleProxy()
    config = SandboxConfig(network_mode="sandbox")

    with caplog.at_level(logging.WARNING, logger="kest.core.sandbox.agentcore_sandbox"):
        await sandbox.execute("print('sandbox-ok')", proxy, config=config)

    warning_msgs = [r.message for r in caplog.records if r.levelno >= logging.WARNING]
    assert any("DNS egress" in m for m in warning_msgs), (
        f"sandbox mode must warn about DNS egress; got: {warning_msgs}"
    )
    assert any(
        "BeyondTrust" in m or "vulnerability" in m.lower() for m in warning_msgs
    ), f"sandbox mode warning must mention the vulnerability; got: {warning_msgs}"


@pytest.mark.asyncio
async def test_agentcore_injected_session_skips_start_stop():
    """When session_id is injected, Start/Stop must never be called."""
    from kest.core.sandbox import AgentCoreSandbox

    mock_client = MagicMock()
    stream_event = {
        "result": {
            "isError": False,
            "content": [{"type": "text", "text": "42"}],
        }
    }
    mock_client.invoke_code_interpreter.return_value = {"stream": [stream_event]}

    sandbox = AgentCoreSandbox(
        code_interpreter_id=_CODE_INTERPRETER_ID,
        session_id="pre-existing-session-abc",
        client=mock_client,
    )
    proxy = SimpleProxy()

    result = await sandbox.execute("print(42)", proxy)
    assert "42" in result.stdout

    # session management calls must NEVER have been made
    mock_client.start_code_interpreter_session.assert_not_called()
    mock_client.stop_code_interpreter_session.assert_not_called()
    # InvokeCodeInterpreter must have used the injected session
    call_args = mock_client.invoke_code_interpreter.call_args
    assert call_args.kwargs["sessionId"] == "pre-existing-session-abc"
    assert call_args.kwargs["codeInterpreterIdentifier"] == _CODE_INTERPRETER_ID


@pytest.mark.asyncio
async def test_agentcore_session_context_manager_starts_and_stops():
    """session() must call Start on entry and Stop on exit when no session_id is injected."""
    from kest.core.sandbox import AgentCoreSandbox

    mock_client = MagicMock()
    mock_client.start_code_interpreter_session.return_value = {
        "sessionId": "ctx-mgr-session-xyz",
        "codeInterpreterIdentifier": _CODE_INTERPRETER_ID,
    }
    stream_event = {
        "result": {
            "isError": False,
            "content": [{"type": "text", "text": "ok"}],
        }
    }
    mock_client.invoke_code_interpreter.return_value = {"stream": [stream_event]}
    mock_client.stop_code_interpreter_session.return_value = {}

    # No session_id injected — let the context manager manage lifecycle
    sandbox = AgentCoreSandbox(
        code_interpreter_id=_CODE_INTERPRETER_ID,
        client=mock_client,
    )
    proxy = SimpleProxy()

    async with sandbox.session() as s:
        await s.execute("print('ok')", proxy)

    mock_client.start_code_interpreter_session.assert_called_once()
    mock_client.stop_code_interpreter_session.assert_called_once()
    invoke_args = mock_client.invoke_code_interpreter.call_args
    assert invoke_args.kwargs["sessionId"] == "ctx-mgr-session-xyz"

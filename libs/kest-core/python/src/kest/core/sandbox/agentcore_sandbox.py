"""AgentCoreSandbox — AWS Bedrock AgentCore Code Interpreter.

Install: uv add 'kest-core[agentcore]'

Design
------
The AgentCore Code Interpreter has two distinct lifecycle layers:

1. **Code Interpreter resource** (Infrastructure-managed)
   Created and deleted via IaC (CloudFormation, Terraform, or the AWS CLI
   ``CreateCodeInterpreter`` / ``DeleteCodeInterpreter`` calls).  The resulting
   identifier — either the AWS-managed default ``"aws.codeinterpreter.v1"`` or
   a custom ARN like ``"arn:aws:bedrock-agentcore:<region>:<account>:code-interpreter/<name>"``
   — is passed into ``AgentCoreSandbox`` at construction time via
   ``code_interpreter_id``.  The SDK never creates or deletes this resource.

2. **Session** (Runtime-managed)
   ``StartCodeInterpreterSession`` / ``StopCodeInterpreterSession`` start and
   stop an ephemeral execution context on top of the Code Interpreter resource.
   Sessions are the only runtime lifecycle boundary the SDK controls.

   For cost-conscious testing (and to avoid the AWS per-account session-creation
   rate quota), callers may supply a pre-existing ``session_id`` at construction
   time.  When a ``session_id`` is provided the sandbox uses it as-is for every
   ``execute()`` call and **never** calls ``StartCodeInterpreterSession`` or
   ``StopCodeInterpreterSession``.

Auth
----
Requires standard AWS credentials resolvable by the boto3 credential chain:
  - AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY (+ optional AWS_SESSION_TOKEN)
  - IAM role via instance metadata (EC2 / ECS / Lambda)
  - ~/.aws/credentials profile

Note on AWS_BEARER_TOKEN (ABSK):
  ABSK tokens are intra-AgentCore runtime credentials used by agents running
  *inside* the AgentCore environment to call back to the service.  They are NOT
  valid for external API access.  External callers must use IAM credentials.

API reference (boto3)
---------------------
  - InvokeCodeInterpreter(codeInterpreterIdentifier, sessionId,
                          name="executeCode",
                          arguments={code, language?, clearContext?}) → EventStream

  Stream event format:
    for event in response['stream']:
        if 'result' in event:
            result = event['result']
            for item in result.get('content', []):
                item['type'] == 'text', item['text'] → stdout / stderr
            result.get('isError', False) → True on error

Network modes (SandboxConfig.network_mode)
------------------------------------------
The network mode is a property of the *Code Interpreter resource*, configured at
IaC provisioning time — not at session or execute time.  The mode passed in
``SandboxConfig.network_mode`` tells the Kest SDK what the resource was
provisioned with, so it can emit the appropriate operator warning:

  'vpc'      — traffic stays within your VPC (recommended for production).
               No warning emitted.
  'public'   — WARNING logged; unrestricted internet access by design.
  'sandbox'  — WARNING logged; unpatched DNS-tunnel vulnerability (CVE, Sep 2025).
               AWS closed the report as "by design".  Use Route 53 DNS Firewall
               to mitigate.

Pass ``network_mode`` in ``SandboxConfig`` to match the mode the interpreter was
provisioned with, so the right warning fires:

    config = SandboxConfig(network_mode="vpc")    # recommended
    config = SandboxConfig(network_mode="public")  # ⚠️ WARNING logged
    config = SandboxConfig(network_mode="sandbox") # ⚠️ WARNING logged (unpatched vuln)
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

from kest.core.sandbox._config import SandboxConfig
from kest.core.sandbox._errors import SandboxNotAvailableError, SandboxTimeoutError
from kest.core.sandbox._provider import SandboxProvider
from kest.core.sandbox._result import SandboxResult
from kest.core.sandbox._tool_proxy import ToolProxy

try:
    import boto3

    _BOTO3_AVAILABLE = True
except ImportError:
    _BOTO3_AVAILABLE = False

logger = logging.getLogger(__name__)

# AWS-managed default interpreter — pre-provisioned by AWS, no IaC required.
# Custom interpreters created via CreateCodeInterpreter get a full ARN:
#   arn:aws:bedrock-agentcore:<region>:<account>:code-interpreter/<name>
_AWS_MANAGED_INTERPRETER = "aws.codeinterpreter.v1"

_WARN_SANDBOX = (
    "AgentCoreSandbox: network_mode='sandbox' has an unpatched DNS-tunnel vulnerability "
    "(BeyondTrust Sep 2025; AWS closed as by-design). DNS egress risk: DNS queries can be "
    "used for data exfiltration / C2 channels. Use network_mode='vpc' for production workloads."
)
_WARN_PUBLIC = (
    "AgentCoreSandbox: network_mode='public' provides unrestricted internet access by design. "
    "DNS egress risk: any external host is reachable. Use network_mode='vpc' for production workloads."
)


def _make_client(region_name: str = "ap-southeast-1") -> Any:
    """
    Build a boto3 bedrock-agentcore client using the standard credential chain.

    Requires: AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY, IAM role, or
    ~/.aws/credentials.  AWS_BEARER_TOKEN (ABSK) is NOT supported here —
    ABSK tokens are intra-AgentCore credentials for agents running inside the service.
    """
    if not _BOTO3_AVAILABLE:
        raise SandboxNotAvailableError(
            "AgentCoreSandbox requires 'boto3'. Install with: pip install 'kest-core[agentcore]'"
        )
    return boto3.client("bedrock-agentcore", region_name=region_name)


class AgentCoreSandbox(SandboxProvider):
    """Sandbox backed by a pre-provisioned AWS Bedrock AgentCore Code Interpreter.

    The Code Interpreter *resource* is managed by IaC (CloudFormation / Terraform /
    ``aws bedrock-agentcore create-code-interpreter``).  The ``AgentCoreSandbox``
    only manages *sessions* on top of that resource.

    Parameters
    ----------
    code_interpreter_id:
        Identifier for the Code Interpreter resource.  Defaults to the AWS-managed
        interpreter (``"aws.codeinterpreter.v1"``).  For a custom interpreter
        provisioned via IaC, pass its full ARN or logical name, e.g.:
        ``"arn:aws:bedrock-agentcore:us-east-1:123456789012:code-interpreter/my-ci"``
    session_id:
        Optional pre-existing session ID.  When provided the sandbox uses it for
        every ``execute()`` call and **never** calls ``Start`` or ``Stop``.
        Use this to reuse a long-lived session in test suites or notebooks,
        avoiding unnecessary session-creation API calls and cost.
    client:
        Optional pre-built boto3 ``bedrock-agentcore`` client (useful for tests).
    region_name:
        AWS region.  Defaults to ``"us-east-1"``.

    Network modes
    -------------
    Pass ``SandboxConfig(network_mode=...)`` to ``execute()`` to tell the SDK
    what mode the interpreter was provisioned with, so it can emit appropriate
    warnings.  The mode is a property of the IaC-provisioned resource, not set
    at runtime:

        config = SandboxConfig(network_mode="vpc")     # recommended — no warning
        config = SandboxConfig(network_mode="public")  # ⚠️ WARNING logged
        config = SandboxConfig(network_mode="sandbox") # ⚠️ WARNING logged (vuln)

    Session management
    ------------------
    For sequential calls that share interpreter state, use ``session()``::

        async with sandbox.session() as s:
            result1 = await s.execute(script1, proxy)
            result2 = await s.execute(script2, proxy)  # same session

    If you supplied ``session_id`` at construction time, ``session()`` is a no-op
    wrapper — the injected session is used directly.
    """

    def __init__(
        self,
        code_interpreter_id: str = _AWS_MANAGED_INTERPRETER,
        session_id: str | None = None,
        client: Any = None,
        region_name: str = "ap-southeast-1",
    ) -> None:
        self._code_interpreter_id = code_interpreter_id
        self._injected_session_id = session_id  # caller-provided; never Start/Stop
        self._pinned_session_id: str | None = None  # set by session() context manager
        self._client = client or _make_client(region_name=region_name)

    # ── session context manager ──────────────────────────────────────────────

    @asynccontextmanager
    async def session(self) -> AsyncIterator["AgentCoreSandbox"]:
        """Async context manager that pins a single session for the duration.

        Starts a new session on entry and stops it on exit.  All ``execute()``
        calls inside the block share the same session, avoiding per-call
        ``StartCodeInterpreterSession`` overhead and quota usage.

        If ``session_id`` was supplied at construction time (injected session),
        this context manager is a no-op — the injected session is used as-is.

        Usage::

            async with sandbox.session() as s:
                r1 = await s.execute(code1, proxy)
                r2 = await s.execute(code2, proxy)
        """
        if self._injected_session_id is not None:
            # Injected session bypasses Start/Stop entirely.
            yield self
            return

        loop = asyncio.get_event_loop()
        start_resp = await loop.run_in_executor(
            None,
            lambda: self._client.start_code_interpreter_session(
                codeInterpreterIdentifier=self._code_interpreter_id,
                name=f"kest-session-{uuid.uuid4().hex[:8]}",
                sessionTimeoutSeconds=900,
            ),
        )
        self._pinned_session_id = start_resp["sessionId"]
        logger.debug("AgentCoreSandbox: pinned session %s", self._pinned_session_id)
        try:
            yield self
        finally:
            sid = self._pinned_session_id
            self._pinned_session_id = None
            if sid:
                try:
                    await loop.run_in_executor(
                        None,
                        lambda: self._client.stop_code_interpreter_session(
                            codeInterpreterIdentifier=self._code_interpreter_id,
                            sessionId=sid,
                        ),
                    )
                    logger.debug("AgentCoreSandbox: stopped session %s", sid)
                except Exception:
                    pass

    async def execute(
        self,
        script: str,
        tool_proxy: ToolProxy,
        timeout_seconds: int = 300,
        config: SandboxConfig | None = None,
    ) -> SandboxResult:
        config = config or SandboxConfig()
        tool_proxy.reset()

        network_mode = (config.network_mode or "sandbox").lower()
        if network_mode == "sandbox":
            logger.warning(_WARN_SANDBOX)
        elif network_mode == "public":
            logger.warning(_WARN_PUBLIC)
        # vpc: no warning — recommended production mode

        try:
            result = await asyncio.wait_for(
                self._run(script, config),
                timeout=timeout_seconds,
            )
        except asyncio.TimeoutError:
            raise SandboxTimeoutError(
                f"AgentCore script exceeded timeout of {timeout_seconds}s"
            )

        return SandboxResult(
            stdout=result["stdout"],
            stderr=result["stderr"],
            return_value=result.get("return_value"),
            exit_code=result["exit_code"],
            taints_added=tool_proxy.accumulated_taints,
        )

    # ── internal ─────────────────────────────────────────────────────────────

    async def _run(self, script: str, config: SandboxConfig) -> dict:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._run_sync, script, config)

    def _run_sync(self, script: str, config: SandboxConfig) -> dict:
        """Resolve the session to use, run the script. Blocking.

        Session resolution priority:
          1. Injected session_id (construction-time, never Start/Stop)
          2. Pinned session from session() context manager
          3. Ephemeral session (Start → execute → Stop within this call)
        """
        session_id = self._injected_session_id or self._pinned_session_id

        if session_id:
            # Reuse an existing session (injected or pinned).
            # clearContext=True so each execute() starts with a clean namespace.
            if config.allowed_packages:
                pkg_str = " ".join(config.allowed_packages)
                self._invoke(session_id, f"pip install -q {pkg_str}", language="python")
            return self._invoke(session_id, script, clear_context=True)

        # No existing session — start an ephemeral one for this call only.
        start_resp = self._client.start_code_interpreter_session(
            codeInterpreterIdentifier=self._code_interpreter_id,
            name=f"kest-session-{uuid.uuid4().hex[:8]}",
            sessionTimeoutSeconds=900,
        )
        eph_session_id = start_resp["sessionId"]

        try:
            if config.allowed_packages:
                pkg_str = " ".join(config.allowed_packages)
                self._invoke(
                    eph_session_id, f"pip install -q {pkg_str}", language="python"
                )
            return self._invoke(eph_session_id, script)
        finally:
            try:
                self._client.stop_code_interpreter_session(
                    codeInterpreterIdentifier=self._code_interpreter_id,
                    sessionId=eph_session_id,
                )
            except Exception:
                pass

    def _invoke(
        self,
        session_id: str,
        code: str,
        language: str = "python",
        clear_context: bool = False,
    ) -> dict:
        """Invoke code in the session and collect the EventStream response."""
        resp = self._client.invoke_code_interpreter(
            codeInterpreterIdentifier=self._code_interpreter_id,
            sessionId=session_id,
            name="executeCode",
            arguments={
                "code": code,
                "language": language,
                "clearContext": clear_context,
            },
        )

        stdout_parts: list[str] = []
        stderr_parts: list[str] = []
        exit_code = 0

        # resp['stream'] is a botocore EventStream — iterate to receive events
        for event in resp.get("stream", []):
            result = event.get("result")
            if result is None:
                # Surface any exception events from the stream
                for exc_key in (
                    "accessDeniedException",
                    "internalServerException",
                    "throttlingException",
                    "validationException",
                    "resourceNotFoundException",
                    "serviceQuotaExceededException",
                    "conflictException",
                ):
                    if exc_key in event:
                        msg = event[exc_key].get("message", exc_key)
                        stderr_parts.append(f"{exc_key}: {msg}")
                        exit_code = 1
                continue

            is_error = result.get("isError", False)
            for item in result.get("content", []):
                if item.get("type") == "text":
                    text = item.get("text", "")
                    if is_error:
                        stderr_parts.append(text)
                        exit_code = 1
                    else:
                        stdout_parts.append(text)

        return {
            "stdout": "\n".join(stdout_parts),
            "stderr": "\n".join(stderr_parts),
            "exit_code": exit_code,
        }

# Kest Sandbox v0.1.0 — Implementation Learnings

> **Spec**: `spec/SPEC-sandbox-v0.1.0.md`
> **Status**: Living document — append on every non-trivial bug or design decision.
> **Read before touching**: `libs/kest-core/python/src/kest/core/sandbox/`

---

## §1 Architecture Deviation: IaC-First Code Interpreter Lifecycle

**Spec reference**: §6.3 (session lifecycle, step 3: `start_code_interpreter_session`)

**What the spec says**: The session lifecycle starts with `StartCodeInterpreterSession` on every `execute()` call.

**What the implementation does**: The Code Interpreter *resource* (`codeInterpreterIdentifier`) is treated as IaC-managed infrastructure — the SDK **never** calls `CreateCodeInterpreter`. This is a clarification of the spec, not a violation:

- `AgentCoreSandbox.__init__()` accepts `code_interpreter_id` (default: `"aws.codeinterpreter.v1"` — the AWS-managed default) to point to a pre-provisioned resource.
- `session()` context manager calls `StartCodeInterpreterSession` / `StopCodeInterpreterSession` (this is exactly what §6.3 specifies).
- An optional `session_id` constructor parameter allows **injecting a pre-existing session**, bypassing `Start`/`Stop` entirely — used for cost-conscious testing to avoid exhausting per-account session quotas.

**Why**: AWS imposes strict session-creation rate quotas. In preview tier accounts, the concurrent session limit is often 0. Treating the Code Interpreter resource as IaC also correctly separates network policy configuration (set at resource provisioning time, fixed) from the runtime session lifecycle.

**Files**: `agentcore_sandbox.py` lines 54–72 (`__init__`), 128–178 (`session()`), 205–245 (`_run_sync`)

---

## §2 Network Mode Warning Semantics

**Spec reference**: `F-EG-03`, `NF-SB-SEC-03`

**Key distinction** (not obvious from spec alone):

| Mode | Nature of risk | Fixed by AWS? |
|---|---|---|
| `sandbox` | DNS-tunnel vulnerability (BeyondTrust Sep 2025). DNS queries can carry data out of bounds. | **No — closed as "by design"** |
| `public` | Unrestricted internet by design. No hidden flaw — just deliberately open. | N/A — intentional |
| `vpc` | Traffic stays in your VPC. Add Route 53 DNS Firewall for full egress control. | ✅ Recommended |

The warning string `"DNS egress risk"` is present in both `sandbox` and `public` mode warnings (for CI greppability as per spec). The `sandbox` mode warning additionally references BeyondTrust and the unpatched nature.

**Network mode is a resource property, not a session property**: It is set at IaC provisioning time (`CreateCodeInterpreter --network-configuration`). The `network_mode` value in `SandboxConfig` is a **declaration to the SDK** of what the resource was provisioned with, so the SDK can emit the right warning. It does not change runtime behaviour.

---

## §3 Session Quota Constraints (Preview Tier)

**Discovery**: On preview-tier AWS accounts, the concurrent active session limit is `0.0`. This means `StartCodeInterpreterSession` fails immediately with a `ServiceQuotaExceededException`.

**Mitigation**:
1. Tests check for IAM credentials (`_resolve_iam_creds()`). If absent, tests skip cleanly.
2. For low-quota accounts, the recommended workaround is to inject a pre-existing session via `AGENTCORE_SESSION_ID` env var — this completely avoids `Start`/`Stop` calls.
3. Production accounts should request a quota increase: "Total number of concurrent active code interpreter sessions per account".

**Note on `AWS_BEARER_TOKEN` (ABSK)**: These tokens are **intra-AgentCore credentials** used by agents running *inside* the AgentCore runtime environment. They are NOT valid for external API access via boto3. External callers must use standard IAM credentials (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / instance role / SSO).

---

## §4 Session Reuse Pattern (Performance / Cost)

**Context**: The `session()` async context manager starts exactly one `StartCodeInterpreterSession` call for all `execute()` calls inside the block. This is the recommended pattern for test suites and notebooks.

**Two session modes**:

1. **`session()` context manager** — Starts a new session on entry, pins it for all `execute()` calls within the block, stops it on exit. One `Start` + one `Stop` per context.

2. **Injected `session_id`** — Pass `session_id=...` at construction. The sandbox uses it as-is. Zero `Start`/`Stop` calls. The caller is responsible for the session's lifecycle. This is the preferred mode for CI tests and notebooks where a long-lived session already exists.

**Per-`execute()` state isolation**: When using a shared session (pinned or injected), each `execute()` call passes `clearContext=True` to `InvokeCodeInterpreter` to reset the interpreter namespace. This prevents state from bleeding between calls.

---

## §5 Spec Compliance Matrix (AgentCore only)

| Requirement ID | Status | Notes |
|---|---|---|
| `F-SB-01` | ✅ | `execute()` abstract method implemented |
| `F-SB-02` | ✅ | boto3 synchronous calls offloaded to thread executor |
| `F-SB-03` | ✅ | `SandboxNotAvailableError` raised at instantiation if boto3 missing |
| `F-SB-04` | ✅ | `asyncio.wait_for()` enforces `timeout_seconds` |
| `F-EG-03` | ✅ | `sandbox`/`public` modes emit WARNING with `"DNS egress risk"` |
| `F-PI-02` | ✅ | `allowed_packages` installed via `pip install` in session |
| `NF-SB-SEC-03` | ✅ | Distinction between `sandbox` (unpatched) and `public` (by design) documented |
| `NF-SB-TEST-01` | ✅ | Mock-client tests cover warning policy without real AWS calls |

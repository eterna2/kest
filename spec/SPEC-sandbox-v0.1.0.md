# Kest SandboxProvider — Design Research & Specification v0.1.0

> **Status**: Draft — pre-implementation  
> **Version**: 0.1.0  
> **Scope**: Secure, isolated execution of LLM-generated code within the Kest Zero-Trust framework.  
> **Audience**: Implementors of `kest-core` sandbox backends; security reviewers; integration authors.  
> **Tracking Issue**: [#84](https://github.com/eterna2/kest/issues/84)

> [!IMPORTANT]
> This file is the normative specification for the Kest Sandbox subsystem. It is **immutable once tagged**. Corrections and implementation findings go into `spec/learnings/sandbox-v0.1.0/LEARNINGS.md`.

---

## Table of Contents

1. [Design Principles](#1-design-principles)
2. [Functional Requirements](#2-functional-requirements)
3. [Non-Functional Requirements](#3-non-functional-requirements)
4. [Data Model Specification](#4-data-model-specification)
5. [Interface Specification](#5-interface-specification)
6. [Backend-Specific Behaviour](#6-backend-specific-behaviour)
7. [Security Specification](#7-security-specification)
8. [Implementation Guidance & Test Strategy](#8-implementation-guidance--test-strategy)
9. [Backend Comparison Reference](#9-backend-comparison-reference)
10. [References](#10-references)

---

## 1. Design Principles

These principles govern every design decision in the Kest Sandbox subsystem. They are **non-negotiable** and complement the core Kest principles in `SPEC-v0.3.0.md`.

### SP-1 — All Tool Access is Mediated

Sandboxed code MUST NOT call host functions directly. Every tool invocation is routed through a `ToolProxy` that is itself a `@kest_verified` operation. This ensures every tool call produces a `KestEntry` in the lineage chain and is subject to the same Zero Trust policy enforcement as any other operation.

### SP-2 — Zero Egress by Default

No sandbox backend MAY allow unsanctioned network egress. Any backend where network isolation cannot be guaranteed at the infrastructure level MUST enforce it via application-level controls (import hooks, blocked builtins). When an infrastructure-level guarantee cannot be achieved, the backend MUST document the residual risk and require explicit operator acknowledgement.

### SP-3 — Deny-by-Default Security Posture

Every backend starts from a position of maximum restriction. Features are unlocked explicitly (via `SandboxConfig`) rather than locked down selectively. An unconfigured sandbox must be more secure than a configured one.

### SP-4 — Backend Portability via Uniform ABC

The `SandboxProvider` ABC defines a single execution contract. Application code that drives the sandbox interacts only with the abstract interface — not with backend-specific APIs. Switching backends requires only a configuration change, not code changes.

### SP-5 — Taint Propagation Through Execution

Every tool call made during sandboxed execution contributes to an audit trail. Taints accumulated during tool calls MUST flow back to the caller via `SandboxResult.taints_added`, allowing the host to make informed decisions about the trustworthiness of the sandbox output.

### SP-6 — Optional Dependencies, Zero Core Drag

All sandbox backends beyond the baseline `SubprocessSandbox` MUST be implemented as optional Python extras. Installing `kest` without any extra MUST NOT require Rust wheels, cloud SDKs, or Docker daemons.

---

## 2. Functional Requirements

Requirements are expressed in testable, unambiguous form. An implementation passes a requirement if and only if a test directly encoding the stated behaviour succeeds.

### 2.1 Core ABC

| ID | Requirement |
|---|---|
| **F-SB-01** | A `SandboxProvider` abstract base class MUST be provided with a single abstract method: `async execute(script: str, tool_proxy: ToolProxy, timeout_seconds: int = 30, config: SandboxConfig | None = None) → SandboxResult`. |
| **F-SB-02** | `execute()` MUST be asynchronous (`async def`). Backends that use synchronous underlying APIs (e.g. `boto3`) MUST offload to a thread executor internally. |
| **F-SB-03** | If the optional extra required by a backend is not installed, the backend class MUST raise `ImportError` at instantiation time (not at `execute()` time) with a message naming the exact `uv add` command to fix it. |
| **F-SB-04** | Every call to `execute()` MUST enforce `timeout_seconds`. Execution exceeding this limit MUST be terminated and a `SandboxTimeoutError` MUST be raised. |
| **F-SB-05** | `execute()` MUST be re-entrant — multiple concurrent calls on the same `SandboxProvider` instance MUST not interfere with each other. |

### 2.2 ToolProxy

| ID | Requirement |
|---|---|
| **F-TP-01** | A `ToolProxy` abstract base class MUST be provided with a single abstract method: `async call_tool(tool_name: str, args: dict) → Any`. |
| **F-TP-02** | Every concrete `ToolProxy` implementation MUST apply `@kest_verified` policy enforcement for each `call_tool()` invocation. Implementations that bypass `@kest_verified` are non-conformant. |
| **F-TP-03** | `ToolProxy` MUST expose an `accumulated_taints` property returning a `frozenset[str]` of all taints collected across all `call_tool()` invocations during the current `execute()` session. |
| **F-TP-04** | `ToolProxy.accumulated_taints` MUST be reset to an empty set at the start of each `execute()` call (i.e. before the first `call_tool()` of a new execution). |
| **F-TP-05** | `ToolProxy` MUST provide a synchronous bridge method `call_tool_sync(tool_name: str, args: dict) → Any`. The default implementation MUST delegate to `call_tool()` via `asyncio.run()`. Subclasses MAY override with a truly synchronous implementation. |

### 2.3 SandboxResult

| ID | Requirement |
|---|---|
| **F-SR-01** | `SandboxResult` MUST be a dataclass with fields: `stdout: str`, `stderr: str`, `return_value: Any`, `exit_code: int`, `taints_added: frozenset[str]`. |
| **F-SR-02** | `SandboxResult.taints_added` MUST be populated from `tool_proxy.accumulated_taints` at the conclusion of `execute()`. |
| **F-SR-03** | `SandboxResult.exit_code` MUST be `0` on success and non-zero on any error (including `SandboxTimeoutError`, import errors, and runtime exceptions in sandboxed code). |

### 2.4 SandboxConfig

| ID | Requirement |
|---|---|
| **F-SC-01** | A `SandboxConfig` dataclass MUST be provided. All fields MUST have safe defaults (deny-by-default posture). |
| **F-SC-02** | `SandboxConfig.blocked_builtins` MUST default to: `["eval", "exec", "compile", "open", "__import__", "breakpoint", "input"]`. |
| **F-SC-03** | `SandboxConfig.blocked_modules` MUST default to: `["subprocess", "socket", "http", "urllib", "ftplib", "telnetlib", "smtplib", "xmlrpc", "multiprocessing", "ctypes", "cffi"]`. |
| **F-SC-04** | `SandboxConfig.allowed_modules` defaults to `None` (no allowlist). When set, ONLY the listed modules MAY be imported. `blocked_modules` is still applied as a secondary filter. |
| **F-SC-05** | `SandboxConfig.allowed_packages` defaults to `None`. When set, each listed package MUST be installed into the execution environment before the script runs. |
| **F-SC-06** | `SandboxConfig.package_index_url` defaults to `None`. When set, all package installations MUST use the specified index URL exclusively. |
| **F-SC-07** | When a backend does not support a `SandboxConfig` field (e.g. `MontySandbox` ignoring `allowed_packages`), it MUST emit a `WARNING`-level log for each inapplicable non-None field and MUST NOT raise an error. |

### 2.5 Egress & Isolation

| ID | Requirement |
|---|---|
| **F-EG-01** | `SubprocessSandbox` MUST inject a `sys.meta_path` import blocker before user code executes. The blocker MUST honour both `blocked_modules` and `allowed_modules`. |
| **F-EG-02** | `SubprocessSandbox` MUST inject a `__builtins__` override replacing every entry in `blocked_builtins` with a stub that raises `SecurityError` on call. |
| **F-EG-03** | `AgentCoreSandbox` supports all three AWS network modes: `"vpc"`, `"sandbox"`, and `"public"`. When `network_mode` is `"sandbox"` or `"public"`, the implementation MUST emit a `WARNING`-level log at `execute()` time. The warning for `"sandbox"` MUST explain the unpatched DNS-tunnel vulnerability (BeyondTrust, 2025). The warning for `"public"` MUST flag that full internet access is active. Both warnings MUST contain the string `"DNS egress risk"` for CI greppability. |
| **F-EG-04** | `E2BSandbox` MUST default to no outbound network (empty CIDR allowlist). Operators who require network access MUST explicitly configure egress rules on the sandbox template. |
| **F-EG-05** | `MontySandbox` provides strong isolation by design (Rust interpreter with no filesystem/network stack). No additional egress controls are required or configurable. |

### 2.6 Package Installation

| ID | Requirement |
|---|---|
| **F-PI-01** | `SubprocessSandbox` MUST support `SandboxConfig.allowed_packages` by creating an ephemeral `uv venv` and running `uv pip install` before executing the script. |
| **F-PI-02** | `AgentCoreSandbox` MUST support `SandboxConfig.allowed_packages` by invoking `executeCommand pip install --quiet <pkg>` for each package in the stateful session before executing the script. |
| **F-PI-03** | `E2BSandbox` MUST support `SandboxConfig.allowed_packages` by calling `sandbox.commands.run("pip install ...")` before executing the script. |
| **F-PI-04** | `DockerSandbox` MUST support `SandboxConfig.allowed_packages` by pre-baking a custom Docker image or by running `pip install` inside the container at startup. |
| **F-PI-05** | `MontySandbox` MUST NOT support `SandboxConfig.allowed_packages`. If the field is non-None, it MUST log a `WARNING` and ignore the field. |
| **F-PI-06** | All package installations that use `package_index_url` MUST pass that URL as the exclusive index (no fallback to PyPI). |

---

## 3. Non-Functional Requirements

### 3.1 Performance

| ID | Requirement |
|---|---|
| **NF-SB-PERF-01** | `SubprocessSandbox` cold-start (including venv activation, preamble injection, and script launch) MUST complete within 100 ms for a script with no package installations. |
| **NF-SB-PERF-02** | `MontySandbox` cold-start MUST complete within 1 ms for a script with no tool calls. |
| **NF-SB-PERF-03** | `SandboxProvider.execute()` overhead (excluding user script execution time) MUST not exceed 5 ms at the 99th percentile for backends without cold-start (Monty). |

### 3.2 Security

| ID | Requirement |
|---|---|
| **NF-SB-SEC-01** | No sandbox backend MAY allow sandboxed code to read host environment variables not explicitly injected via `ToolProxy`. |
| **NF-SB-SEC-02** | No sandbox backend MAY allow sandboxed code to write to the host filesystem without an explicit `ToolProxy`-mediated call. |
| **NF-SB-SEC-03** | `AgentCoreSandbox` in `"sandbox"` mode has an **unpatched DNS-tunnelling vulnerability** (BeyondTrust Sep 2025; AWS closed as "by design"). `AgentCoreSandbox` in `"public"` mode provides unrestricted internet by design (no hidden flaw). Both modes MUST emit a `WARNING` containing `"DNS egress risk"`. Documentation MUST explain the distinction between the intentional openness of `"public"` and the structural limitation of `"sandbox"`. |
| **NF-SB-SEC-04** | `SubprocessSandbox` package installation MUST only allow pure-Python packages when `package_index_url` points to an internal index. When using default PyPI, native-extension packages SHOULD be logged as a security warning. |
| **NF-SB-SEC-05** | Sandboxed code MUST NOT be able to access the host `ToolProxy` object directly. The proxy is injected as an external function name (Monty) or via IPC (subprocess/Docker). |

### 3.3 Testability

| ID | Requirement |
|---|---|
| **NF-SB-TEST-01** | All sandbox backends MUST be independently unit-testable via the `SandboxProvider` ABC using a `MockToolProxy` that records tool calls without real `@kest_verified` enforcement. |
| **NF-SB-TEST-02** | `SubprocessSandbox` unit tests MUST NOT require Docker, E2B API keys, or AWS credentials. |
| **NF-SB-TEST-03** | A `MockSandboxProvider` MUST be provided that records script invocations and returns a configurable `SandboxResult` without any subprocess or network activity. |

---

## 4. Data Model Specification

### 4.1 `SandboxConfig`

```python
from __future__ import annotations
from dataclasses import dataclass, field

@dataclass
class SandboxConfig:
    """
    Unified configuration for all SandboxProvider backends.
    Backends that do not support a field MUST ignore it and emit a WARNING.
    """

    # ── Module-level control (CPython-based backends only) ──────────────────
    allowed_modules: list[str] | None = None
    """Explicit allowlist of importable top-level modules. None = no allowlist.
    When set, only these modules (plus builtins) may be imported.
    blocked_modules is still applied as a secondary deny-filter."""

    blocked_modules: list[str] = field(default_factory=lambda: [
        "subprocess", "socket", "http", "urllib", "ftplib",
        "telnetlib", "smtplib", "xmlrpc", "multiprocessing",
        "ctypes", "cffi",
    ])
    """Modules blocked even if present in the environment.
    Enforced via sys.meta_path hook injected before user code."""

    # ── Builtin-level control (CPython-based backends only) ─────────────────
    blocked_builtins: list[str] = field(default_factory=lambda: [
        "eval", "exec", "compile", "open",
        "__import__", "breakpoint", "input",
    ])
    """Builtins replaced with a SecurityError-raising stub."""

    # ── Package installation ─────────────────────────────────────────────────
    allowed_packages: list[str] | None = None
    """Packages to pre-install before script execution.
    Not supported by MontySandbox (logs WARNING, ignores).
    Pure-Python only recommended for SubprocessSandbox."""

    package_index_url: str | None = None
    """Exclusive PyPI index URL for package installation.
    None = use default PyPI. Set to internal Artifactory for air-gapped environments."""

    # ── Network isolation ────────────────────────────────────────────────────
    network_mode: str = "none"
    """Backend-specific network mode hint.
    SubprocessSandbox / MontySandbox: ignored (no network stack).
    AgentCoreSandbox: accepts 'vpc', 'public', or 'sandbox'. Using 'public' or 'sandbox'
      emits a WARNING about DNS-egress risk; 'vpc' is strongly recommended.
    E2BSandbox: template-level setting, passed at sandbox creation.
    DockerSandbox: maps to Docker --network flag."""
```

**Field applicability by backend:**

| Field | `SubprocessSandbox` | `MontySandbox` | `AgentCoreSandbox` | `E2BSandbox` | `DockerSandbox` |
|---|---|---|---|---|---|
| `allowed_modules` | ✅ | ⚠️ ignored | ✅ (preamble hook) | ✅ (preamble hook) | ✅ |
| `blocked_modules` | ✅ | ⚠️ ignored | ✅ (preamble hook) | ✅ (preamble hook) | ✅ |
| `blocked_builtins` | ✅ | ⚠️ ignored | ✅ (preamble hook) | ✅ (preamble hook) | ✅ |
| `allowed_packages` | ✅ | ❌ WARNING | ✅ | ✅ | ✅ |
| `package_index_url` | ✅ | ❌ WARNING | ❌ (AWS-managed) | ✅ | ✅ |
| `network_mode` | ⚠️ ignored | ⚠️ ignored | ✅ MUST be `'vpc'` | ✅ | ✅ |

### 4.2 `SandboxResult`

```python
from __future__ import annotations
from dataclasses import dataclass
from typing import Any

@dataclass(frozen=True)
class SandboxResult:
    """Immutable result of a sandboxed script execution."""
    stdout: str
    """Captured stdout from script execution."""
    stderr: str
    """Captured stderr from script execution (warnings, tracebacks)."""
    return_value: Any
    """The value returned by the script's last expression, or None."""
    exit_code: int
    """0 = success; non-zero = failure (including timeout)."""
    taints_added: frozenset[str]
    """Union of all taints accumulated across all tool_proxy.call_tool() calls
    during this execution. Populated from tool_proxy.accumulated_taints."""
```

### 4.3 `ToolProxy`

```python
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any

class ToolProxy(ABC):
    """
    Mediates all tool calls from sandboxed code to the host.
    Every call_tool() MUST be decorated with @kest_verified.
    Accumulates taints across the lifetime of one execute() session.
    """

    @abstractmethod
    async def call_tool(self, tool_name: str, args: dict) -> Any:
        """Async tool invocation — primary contract."""

    def call_tool_sync(self, tool_name: str, args: dict) -> Any:
        """Sync bridge. Default delegates to call_tool() via asyncio.run().
        Override for a truly synchronous implementation."""
        import asyncio
        return asyncio.run(self.call_tool(tool_name, args))

    @property
    @abstractmethod
    def accumulated_taints(self) -> frozenset[str]:
        """All taints accumulated since last reset."""

    @abstractmethod
    def reset(self) -> None:
        """Reset accumulated_taints to empty set. Called by SandboxProvider
        at the start of each execute() to prevent cross-execution taint leakage."""
```

---

## 5. Interface Specification

### 5.1 `SandboxProvider` ABC

```python
from __future__ import annotations
from abc import ABC, abstractmethod

class SandboxProvider(ABC):
    """
    Abstract base class for all Kest sandbox backends.
    Implementations:
      - SubprocessSandbox  (no extra; baseline CPython)
      - MontySandbox       ([monty]; in-process Rust interpreter)
      - AgentCoreSandbox   ([agentcore]; AWS Bedrock, VPC recommended, public/sandbox warns)
      - E2BSandbox         ([e2b]; Firecracker microVM)
      - DockerSandbox      ([docker]; OCI container)
      - WasmSandbox        (interface stub; future browser/WASM target)
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
            Python source code to execute. For MontySandbox, only a subset
            of Python is supported (no classes, no 3rd-party imports).
        tool_proxy:
            All tool calls from the script are routed through this proxy.
            The proxy MUST apply @kest_verified for every call_tool().
        timeout_seconds:
            Maximum wall-clock time. SandboxTimeoutError raised on breach.
        config:
            Security configuration. None = safe defaults (deny-by-default).

        Returns
        -------
        SandboxResult
            Immutable result including stdout, stderr, return_value,
            exit_code, and taints_added from the proxy.
        """
```

### 5.2 Exception Hierarchy

```
SandboxError                     # base for all sandbox errors
├── SandboxTimeoutError          # timeout_seconds exceeded
├── SandboxConfigurationError    # invalid / incompatible SandboxConfig
│   └── (e.g. AgentCore Sandbox-mode, missing VPC config)
├── SandboxExecutionError        # runtime error inside sandboxed code
│   ├── SandboxImportError       # blocked module import attempted
│   └── SandboxSecurityError     # blocked builtin called
└── SandboxNotAvailableError     # backend extra not installed (ImportError wrapper)
```

### 5.3 `MockSandboxProvider`

```python
class MockSandboxProvider(SandboxProvider):
    """
    Test double. Records calls; returns a configured result.
    Does NOT execute scripts. Does NOT enforce security controls.
    For unit tests only.
    """
    def __init__(self, result: SandboxResult | None = None): ...
    async def execute(self, script, tool_proxy, timeout_seconds=30, config=None) -> SandboxResult: ...
    @property
    def calls(self) -> list[dict]: ...  # [{script, timeout_seconds, config}, ...]
```

### 5.4 `MockToolProxy`

```python
class MockToolProxy(ToolProxy):
    """
    Test double. Records tool calls and returns configurable responses.
    Does NOT apply @kest_verified. Does NOT accumulate real taints.
    For unit tests only — allows testing sandbox execution logic in isolation.
    """
    def __init__(self, responses: dict[str, Any] | None = None): ...
    async def call_tool(self, tool_name: str, args: dict) -> Any: ...
    @property
    def accumulated_taints(self) -> frozenset[str]: ...
    def reset(self) -> None: ...
    @property
    def calls(self) -> list[dict]: ...  # [{tool_name, args}, ...]
```

### 5.5 Public API Surface

The following names MUST be exported from `kest.core.sandbox`:

```python
from kest.core.sandbox import (
    # ABCs
    SandboxProvider,
    ToolProxy,
    # Data classes
    SandboxConfig,
    SandboxResult,
    # Errors
    SandboxError,
    SandboxTimeoutError,
    SandboxConfigurationError,
    SandboxExecutionError,
    SandboxImportError,
    SandboxSecurityError,
    SandboxNotAvailableError,
    # Test doubles
    MockSandboxProvider,
    MockToolProxy,
    # Backends (always importable; extras checked at instantiation)
    SubprocessSandbox,
    MontySandbox,
    AgentCoreSandbox,
    E2BSandbox,
    DockerSandbox,
    WasmSandbox,
)
```


---

## 6. Backend-Specific Behaviour

### 6.1 `SubprocessSandbox` (baseline — no extra required)

| Property | Value |
|---|---|
| **Isolation** | OS process boundary + import hook + builtin replacement |
| **Python** | Full CPython (host version) |
| **Package install** | Ephemeral `uv venv` per execution |
| **Network** | Import hook (bypassable by native extensions) |
| **Snapshotting** | ❌ Not supported |
| **Extra** | None |

**Execution algorithm:**

```
1. Validate config (apply defaults if None)
2. If allowed_packages non-empty:
   a. Create temp dir
   b. uv venv <tmpdir>/.sandbox-venv
   c. uv pip install [--index-url <url>] <packages>
   d. python_bin = <tmpdir>/.sandbox-venv/bin/python
   else: python_bin = sys.executable
3. Build preamble script:
   - __builtins__ override (blocked_builtins → SecurityError stubs)
   - sys.meta_path blocker (blocked_modules + allowed_modules filter)
4. Write preamble + script to tmpfile
5. subprocess.run([python_bin, tmpfile], timeout=timeout_seconds,
                  env={}, capture_output=True)
6. Parse stdout/stderr; build SandboxResult
7. Cleanup temp dir
```

**Security note:** native-extension packages (`.so`/`.pyd`) can bypass Python-level import hooks. When using `SubprocessSandbox` with `allowed_packages`, prefer pure-Python packages only and supply a controlled `package_index_url`.

### 6.2 `MontySandbox` (optional extra: `[monty]`)

| Property | Value |
|---|---|
| **Isolation** | Rust interpreter — no filesystem, no network, no env vars |
| **Python subset** | No classes, no 3rd-party, limited stdlib |
| **Package install** | ❌ Not supported (architectural) |
| **Snapshotting** | ✅ `FunctionSnapshot.dump()` / `load_snapshot()` |
| **Cold-start** | < 1 µs |
| **Extra** | `pydantic-monty>=0.0.17` |

**Tool call bridge (pause-resume loop):**

```
1. tool_proxy.reset()
2. m = pydantic_monty.Monty(script, external_functions=["call_tool"])
3. state = m.start(inputs={})
4. while state is FunctionSnapshot:
   a. assert state.function_name == "call_tool"
   b. result = await tool_proxy.call_tool(*state.args)
   c. state = state.resume({"return_value": result})
5. return SandboxResult(stdout=state.stdout, ...,
                         taints_added=tool_proxy.accumulated_taints)
```

**Unsupported config fields** (log WARNING if non-None): `allowed_modules`, `blocked_modules`, `blocked_builtins`, `allowed_packages`, `package_index_url`.

### 6.3 `AgentCoreSandbox` (optional extra: `[agentcore]`)

| Property | Value |
|---|---|
| **Isolation** | AWS-managed microVM (kernel-level) |
| **Python** | Full CPython + pre-installed DS/ML stack |
| **Stateful sessions** | ✅ Up to `min(timeout_seconds, 900)` s |
| **Package install** | ✅ `executeCommand pip install` (per-session) |
| **Network** | **VPC mode mandatory** (Sandbox mode leaks DNS) |
| **IAM / Audit** | ✅ CloudTrail automatic |
| **Extra** | `boto3>=1.34`, `bedrock-agentcore` |

> [!WARNING]
> AgentCore `"public"` and `"sandbox"` network modes allow unconditional DNS queries, which can be exploited for data exfiltration via DNS tunnelling. When these modes are used, `AgentCoreSandbox.execute()` emits a `WARNING`-level log. Use `network_mode="vpc"` for production workloads handling sensitive data.

**Session lifecycle:**

```
1. validate config.network_mode == "vpc" (raise SandboxConfigurationError otherwise)
2. tool_proxy.reset()
3. client.start_code_interpreter_session(sessionTimeoutSeconds=min(timeout,900))
4. For each pkg in allowed_packages:
   invoke executeCommand: pip install --quiet <pkg>
5. preamble = build_preamble(config)  # blocked_builtins + blocked_modules hooks
6. invoke executeCode: preamble + script (streaming response)
7. Collect text/error events → stdout/stderr
8. client.stop_code_interpreter_session()
9. return SandboxResult(..., taints_added=tool_proxy.accumulated_taints)
```

**Required IAM permissions:**

```json
{
  "Action": [
    "bedrock-agentcore:StartCodeInterpreterSession",
    "bedrock-agentcore:InvokeCodeInterpreter",
    "bedrock-agentcore:StopCodeInterpreterSession"
  ],
  "Resource": "arn:aws:bedrock-agentcore:<region>:<account>:code-interpreter/aws.codeinterpreter.v1"
}
```

### 6.4 `E2BSandbox` (optional extra: `[e2b]`)

| Property | Value |
|---|---|
| **Isolation** | Firecracker microVM (per execution) |
| **Python** | Full CPython |
| **Package install** | ✅ Runtime `pip` or baked template |
| **Network** | Per-sandbox CIDR/domain allowlist |
| **Snapshotting** | ✅ `sandbox.create_snapshot()` |
| **Extra** | `e2b-code-interpreter>=1.0` |
| **Auth** | `E2B_API_KEY` environment variable |

**ToolProxy bridge:** E2B sandboxes run in a cloud VM isolated from the host. Tool calls are bridged via an injected HTTP gateway:

```
1. tool_proxy.reset()
2. sandbox = Sandbox(api_key=E2B_API_KEY, timeout=timeout_seconds)
3. Install allowed_packages via sandbox.commands.run("pip install ...")
4. Write kest_gateway_client.py to sandbox filesystem (HTTP client stub)
5. preamble = build_preamble(config) + "import kest_gateway_client as call_tool\n"
6. exec = sandbox.run_code(preamble + script)
7. return SandboxResult(stdout=exec.logs.stdout, ...,
                         taints_added=tool_proxy.accumulated_taints)
```

### 6.5 `DockerSandbox` (optional extra: `[docker]`)

| Property | Value |
|---|---|
| **Isolation** | OCI container (full process isolation) |
| **Python** | Full CPython + native extensions |
| **Network** | `--network none` default |
| **Extra** | `docker>=7.0` |

### 6.6 `WasmSandbox` (interface stub)

`WasmSandbox` is a future target for browser-side or WASM-based execution. The class MUST be importable and MUST raise `NotImplementedError` from `execute()`. It exists to reserve the interface slot in the public API.

---

## 7. Security Specification

### 7.1 Threat Model

| Threat | Affected Backends | Mitigation |
|---|---|---|
| Network exfiltration via HTTP | Subprocess, Docker | Import hook (Python-level); Docker `--network none` |
| Network exfiltration via DNS tunnel | AgentCore `"sandbox"` mode | WARNING logged; **vulnerability is unpatched** (AWS closed as by-design, Sep 2025); use VPC + Route 53 DNS Firewall |
| Unrestricted outbound traffic | AgentCore `"public"` mode | WARNING logged; intentionally open — dev/test only |
| Filesystem read of host secrets | All | No host paths mounted; `open()` blocked |
| Privilege escalation via native extension | Subprocess | Pure-Python package restriction |
| Supply chain attack via `allowed_packages` | Subprocess, AgentCore, E2B | `package_index_url` enforcement; minimal allowlist |
| Taint laundering (tool call bypasses `@kest_verified`) | All | `ToolProxy` is the sole channel; implementations audited |
| Long-running script evading timeout | All | Hard `timeout_seconds` enforcement per backend |

### 7.2 Preamble Injection Contract

For CPython-based backends (`SubprocessSandbox`, `AgentCoreSandbox` preamble, `E2BSandbox` preamble), the security preamble MUST be prepended to every script and MUST:

1. Override `__builtins__` to replace each entry in `blocked_builtins` with:
   ```python
   lambda *a, **k: (_ for _ in ()).throw(
       SecurityError(f"'{name}' is not available in this sandbox")
   )
   ```
2. Install a `sys.meta_path` finder at index 0 that:
   - Raises `ImportError` for any module whose top-level name is in `blocked_modules`.
   - If `allowed_modules` is not None, also raises `ImportError` for any module not in `allowed_modules`.

3. The preamble MUST be generated by a host-side function (`_build_preamble(config: SandboxConfig) -> str`) — sandboxed code MUST NOT be able to modify it.

---

## 8. Implementation Guidance & Test Strategy

### 8.1 Directory Layout

```
libs/kest-core/python/src/kest/core/sandbox/
├── __init__.py            # Public API exports (see §5.5)
├── _config.py             # SandboxConfig dataclass
├── _provider.py           # SandboxProvider ABC
├── _result.py             # SandboxResult dataclass
├── _tool_proxy.py         # ToolProxy ABC + KestToolProxy concrete
├── _errors.py             # Exception hierarchy
├── _preamble.py           # _build_preamble() — security preamble builder
├── _mocks.py              # MockSandboxProvider, MockToolProxy
├── subprocess_sandbox.py  # SubprocessSandbox
├── monty_sandbox.py       # MontySandbox (pydantic-monty optional)
├── agentcore_sandbox.py   # AgentCoreSandbox (boto3 optional)
├── e2b_sandbox.py         # E2BSandbox (e2b-code-interpreter optional)
├── docker_sandbox.py      # DockerSandbox (docker optional)
└── wasm_sandbox.py        # WasmSandbox (stub)
```

### 8.2 TDD Implementation Order

1. **Interfaces only** — `SandboxProvider`, `ToolProxy`, `SandboxConfig`, `SandboxResult`, error hierarchy, `MockSandboxProvider`, `MockToolProxy`. No logic — just ABCs and dataclasses. Tests: all public API names importable; `MockSandboxProvider.execute()` records calls; `MockToolProxy.call_tool()` returns configured responses.

2. **`_preamble.py`** — `_build_preamble(config)` returns a Python string that, when prepended to a script, blocks all default `blocked_builtins` and `blocked_modules`. Tests: execute preamble + `import socket` → `ImportError`; execute preamble + `eval("1")` → `SecurityError`.

3. **`SubprocessSandbox`** — uses `_build_preamble()`. Tests: hello-world script; blocked import raises; timeout enforced; tool calls via `MockToolProxy`; `taints_added` from proxy.

4. **`MontySandbox`** — pause-resume loop; warning on unsupported config fields. Tests: hello-world; tool call intercepted and forwarded to proxy; unrecognised external function raises.

5. **`AgentCoreSandbox`** — boto3 integration; network mode handling. Tests: `network_mode='public'` or `'sandbox'` emits WARNING containing `"DNS egress risk"` (assert on log output, no AWS calls needed); `network_mode='vpc'` emits no warning; full execution mocked via `moto`.

6. **`E2BSandbox`** — e2b SDK integration. Tests: mocked HTTP.

7. **`DockerSandbox`** — docker SDK integration. Integration tests only.

### 8.3 `pyproject.toml` Extras

```toml
[project.optional-dependencies]
monty     = ["pydantic-monty>=0.0.17"]
agentcore = ["boto3>=1.34", "bedrock-agentcore"]
e2b       = ["e2b-code-interpreter>=1.0"]
docker    = ["docker>=7.0"]
```

---

## 9. Backend Comparison Reference

| Dimension | `SubprocessSandbox` | `MontySandbox` | `AgentCoreSandbox` | `E2BSandbox` | `DockerSandbox` |
|---|---|---|---|---|---|
| **Extra** | None | `[monty]` | `[agentcore]` | `[e2b]` | `[docker]` |
| **Cold-start** | ~30 ms | < 1 µs | ~200–500 ms | ~100–200 ms | ~200 ms |
| **Python completeness** | Full CPython | Subset (no classes) | Full + DS/ML stack | Full CPython | Full CPython |
| **Isolation** | OS process | Rust interpreter | AWS microVM | Firecracker microVM | OCI container |
| **Network egress** | Import hook | None (by design) | VPC mode (mandatory) | CIDR allowlist | `--network none` |
| **Package install** | ✅ uv venv | ❌ | ✅ executeCommand | ✅ pip | ✅ pip/apt |
| **Stateful session** | ❌ | ❌ | ✅ (up to 900 s) | ⚠️ via snapshot | ❌ |
| **Snapshotting** | ❌ | ✅ dump/load | ❌ (session only) | ✅ create_snapshot | ❌ |
| **IAM / CloudTrail** | ❌ | ❌ | ✅ built-in | ❌ custom | ❌ custom |
| **Self-host** | ✅ | ✅ | ❌ AWS-only | ✅ Terraform | ✅ any Docker host |
| **Experimental risk** | 🟢 Low | 🔴 High (v0.0.17) | 🟢 Low (GA) | 🟢 Low (v2.19) | 🟢 Low |
| **Cost** | Free | Free | AWS consumption | Per-second billing | Docker infra |
| **Best for** | Baseline / CI | Fast in-process LLM orchestration | AWS-native, CloudTrail audit | Cloud-isolated full CPython | High-privilege self-hosted |

---

## 10. References

- [Issue #84](https://github.com/eterna2/kest/issues/84) — Original SandboxProvider specification
- [pydantic/monty](https://github.com/pydantic/monty) — Rust Python interpreter
- [pydantic-monty PyPI](https://pypi.org/project/pydantic-monty/)
- [AWS AgentCore Code Interpreter](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/code-interpreter-using-directly.html)
- [E2B GitHub](https://github.com/e2b-dev/e2b) — Firecracker microVM sandbox
- [E2B Documentation](https://e2b.dev/docs)
- [Anthropic Programmatic Tool Calling](https://platform.claude.com/docs/en/agents-and-tools/tool-use/programmatic-tool-calling)
- `spec/learnings/sandbox-v0.1.0/LEARNINGS.md` — runtime findings (create on first discovery)
- `libs/kest-core/python/SANDBOX.md` — user-facing documentation

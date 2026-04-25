# Kest Sandbox — User Guide

> **Specification**: [`spec/SPEC-sandbox-v0.1.0.md`](../../../spec/SPEC-sandbox-v0.1.0.md)  
> **Version**: kest-core `0.4.0+`

The Kest Sandbox subsystem lets you execute **LLM-generated Python code** in an isolated environment where every tool call back to the host is automatically verified, audited, and woven into the Kest lineage chain. No sandboxed code can reach the network or filesystem without going through a `@kest_verified` `ToolProxy`.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Installation](#2-installation)
3. [Quick Start](#3-quick-start)
4. [Choosing a Backend](#4-choosing-a-backend)
5. [Backend Reference](#5-backend-reference)
   - 5.1 [SubprocessSandbox](#51-subprocesssandbox--baseline)
   - 5.2 [MontySandbox](#52-montysandbox--in-process-rust-interpreter)
   - 5.3 [AgentCoreSandbox](#53-agentcoresandbox--aws-bedrock)
   - 5.4 [E2BSandbox](#54-e2bsandbox--firecracker-microvm)
   - 5.5 [DockerSandbox](#55-dockersandbox)
6. [SandboxConfig Reference](#6-sandboxconfig-reference)
7. [ToolProxy Pattern](#7-toolproxy-pattern)
8. [Security Guide](#8-security-guide)
9. [Testing](#9-testing)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                   Host Application                       │
│                                                          │
│  script (str) ──► SandboxProvider.execute()             │
│                         │                               │
│              ┌──────────▼──────────────────┐            │
│              │   Sandbox Backend            │            │
│              │  (Subprocess / Monty /       │            │
│              │   AgentCore / E2B / Docker)  │            │
│              │                              │            │
│              │  code calls call_tool(...)   │            │
│              └──────────┬───────────────────┘           │
│                         │ IPC / pause-resume loop        │
│                 ┌───────▼──────────────┐                │
│                 │   ToolProxy           │                │
│                 │  @kest_verified        │                │
│                 │  accumulate taints    │                │
│                 └───────┬──────────────┘                │
│                         │                               │
│                 Real tool / function                     │
│                                                          │
│  ◄── SandboxResult(stdout, stderr, return_value,         │
│                    exit_code, taints_added)               │
└─────────────────────────────────────────────────────────┘
```

Key invariants:
- **Zero egress by default** — all IO goes through `ToolProxy`.
- **Deny-by-default** — dangerous builtins and network modules blocked unless you explicitly allow them.
- **Taint propagation** — every tool call merges into `SandboxResult.taints_added`, letting you decide whether to trust the output.

---

## 2. Installation

```bash
# Baseline (no extra dependencies)
uv add kest-core

# In-process Rust interpreter (fast, no classes/3rd-party)
uv add 'kest-core[monty]'

# AWS Bedrock AgentCore (VPC mode, IAM + CloudTrail audit)
uv add 'kest-core[agentcore]'

# E2B Firecracker microVM (full CPython, cloud-isolated)
uv add 'kest-core[e2b]'

# Docker container (self-hosted full-privilege)
uv add 'kest-core[docker]'

# Multiple backends
uv add 'kest-core[monty,e2b]'
```

---

## 3. Quick Start

### Minimal example — SubprocessSandbox

```python
import asyncio
from kest.core.sandbox import SubprocessSandbox, SandboxConfig
from kest.core.sandbox import ToolProxy

# 1. Implement your ToolProxy
class MyToolProxy(ToolProxy):
    def __init__(self):
        self._taints: set[str] = set()

    @kest_verified   # mandatory — each call_tool must be @kest_verified
    async def call_tool(self, tool_name: str, args: dict):
        if tool_name == "add":
            return args["a"] + args["b"]
        raise ValueError(f"Unknown tool: {tool_name}")

    @property
    def accumulated_taints(self) -> frozenset[str]:
        return frozenset(self._taints)

    def reset(self):
        self._taints.clear()

# 2. Execute sandboxed code
async def main():
    sandbox = SubprocessSandbox()
    proxy = MyToolProxy()

    script = """
result = call_tool("add", {"a": 10, "b": 32})
print(f"Result: {result}")
"""

    result = await sandbox.execute(
        script=script,
        tool_proxy=proxy,
        timeout_seconds=10,
        config=SandboxConfig(),   # safe defaults
    )

    print(result.stdout)       # "Result: 42"
    print(result.exit_code)    # 0
    print(result.taints_added) # frozenset of any taints from tool calls

asyncio.run(main())
```

### With package installation

```python
config = SandboxConfig(
    allowed_packages=["httpx==0.27.0"],
    package_index_url="https://my-private-pypi.example.com/simple/",
)
result = await sandbox.execute(script, proxy, config=config)
```

---

## 4. Choosing a Backend

| I need… | Use |
|---|---|
| No extra dependencies, works everywhere | `SubprocessSandbox` |
| Ultra-low latency, in-process, LLM tool orchestration | `MontySandbox` |
| AWS-native, IAM + CloudTrail audit, stateful sessions | `AgentCoreSandbox` |
| Full CPython + pip, non-AWS cloud, network isolation | `E2BSandbox` |
| Maximum privilege, native extensions, self-hosted | `DockerSandbox` |

**Security tradeoffs at a glance:**

| Backend | Isolation strength | Egress enforcement | Experimental risk |
|---|---|---|---|
| `SubprocessSandbox` | Process boundary | Import hook (bypassable by `.so`) | 🟢 Low |
| `MontySandbox` | Rust interpreter | Architectural (no network stack) | 🔴 High (v0.0.x) |
| `AgentCoreSandbox` | AWS microVM | VPC mode (mandatory) | 🟢 Low (GA) |
| `E2BSandbox` | Firecracker microVM | CIDR allowlist | 🟢 Low |
| `DockerSandbox` | OCI container | `--network none` | 🟢 Low |

---

## 5. Backend Reference

### 5.1 `SubprocessSandbox` — Baseline

No extra dependencies. Uses `uv` (already part of the Kest toolchain) for ephemeral venvs.

```python
from kest.core.sandbox import SubprocessSandbox, SandboxConfig

sandbox = SubprocessSandbox()

config = SandboxConfig(
    # Block dangerous modules (defaults already include socket, subprocess, etc.)
    blocked_modules=["socket", "subprocess", "http", "urllib"],
    # Block dangerous builtins (defaults already include eval, exec, open, etc.)
    blocked_builtins=["eval", "exec", "compile", "open"],
    # Optionally install packages before execution
    allowed_packages=["arrow==1.3.0"],
)

result = await sandbox.execute(script, proxy, config=config)
```

**Limitations:**
- Import hook can be bypassed by native `.so` extensions.
- No stateful sessions; each `execute()` is a fresh process.

---

### 5.2 `MontySandbox` — In-Process Rust Interpreter

```bash
uv add 'kest-core[monty]'
```

```python
from kest.core.sandbox import MontySandbox, SandboxConfig

sandbox = MontySandbox()

# SandboxConfig fields are mostly ignored (Monty handles security natively).
# Setting blocked_modules/allowed_packages will log a WARNING — not an error.
config = SandboxConfig()

script = """
# Monty's only external interaction is via call_tool()
data = call_tool("fetch_record", {"id": 42})
result = data["value"] * 2
"""

result = await sandbox.execute(script, proxy, timeout_seconds=5, config=config)
```

**Supported Python subset:**
- ✅ Variables, arithmetic, string formatting, list/dict operations
- ✅ `for`/`while` loops, `if`/`elif`/`else`
- ✅ Standard library: `sys`, `os`, `re`, `json`, `datetime`, `typing`, `pathlib`
- ❌ Class definitions (`class Foo:`)
- ❌ Third-party packages (`import requests`, `import pydantic`)
- ❌ `match` statements

> [!CAUTION]
> `pydantic-monty` is at `v0.0.x` and has an active security bounty. Do NOT use `MontySandbox` for high-privilege production workloads. Use `DockerSandbox` or `AgentCoreSandbox` instead.

---

### 5.3 `AgentCoreSandbox` — AWS Bedrock

```bash
uv add 'kest-core[agentcore]'
```

#### Architecture

The AgentCore Code Interpreter has two distinct lifecycle layers:

| Layer | Managed by | When |
|---|---|---|
| **Code Interpreter resource** | IaC / AWS CLI | Provisioning time — once per environment |
| **Session** | SDK (`start_code_interpreter_session`) | Runtime — per execution context |

The `AgentCoreSandbox` SDK only manages **sessions**. The Code Interpreter resource (the compute pool and network policy) is provisioned via IaC and identified by a `codeInterpreterIdentifier`.

#### Provisioning a Code Interpreter (IaC)

For most environments, use the **AWS-managed default** (`"aws.codeinterpreter.v1"`) — it requires no provisioning:

```python
# Default — AWS-managed interpreter, no IaC required
AgentCoreSandbox()  # uses "aws.codeinterpreter.v1"
```

For custom network configuration (VPC, private subnet), provision a custom interpreter via the AWS CLI or IaC, then pass its identifier:

```bash
# AWS CLI — provision a custom interpreter with VPC networking
aws bedrock-agentcore create-code-interpreter \
    --name my-kest-interpreter \
    --network-configuration '{"networkMode": "vpc"}' \
    --region us-east-1
# → Returns: {"codeInterpreterIdentifier": "arn:aws:bedrock-agentcore:us-east-1:123456789012:code-interpreter/my-kest-interpreter"}
```

Equivalent Terraform:
```hcl
resource "aws_bedrock_agentcore_code_interpreter" "kest" {
  name = "kest-interpreter"
  network_configuration {
    network_mode = "vpc"
    subnet_ids        = var.private_subnet_ids
    security_group_ids = [aws_security_group.kest_ci.id]
  }
}
```

#### Basic usage

```python
import boto3
from kest.core.sandbox import AgentCoreSandbox, SandboxConfig

# AWS-managed default (no IaC needed)
sandbox = AgentCoreSandbox()

# Custom IaC-provisioned interpreter
sandbox = AgentCoreSandbox(
    code_interpreter_id="arn:aws:bedrock-agentcore:us-east-1:123456789012:code-interpreter/my-kest-interpreter",
)

# Pass the network mode that matches how the interpreter was provisioned.
# This controls which warning (if any) the SDK emits — it does NOT change
# the actual network policy (that is fixed at provisioning time).
config_vpc = SandboxConfig(network_mode="vpc")     # ✅ No warning
config_public = SandboxConfig(network_mode="public") # ⚠️ WARNING logged
config_sandbox = SandboxConfig(network_mode="sandbox") # ⚠️ WARNING logged (DNS-tunnel vuln)

result = await sandbox.execute(script, proxy, timeout_seconds=120, config=config_vpc)
```

#### Stateful sessions

For sequential executions (e.g. a multi-step analysis), share one session:

```python
async with sandbox.session() as s:
    r1 = await s.execute("x = 10", proxy)    # starts ONE session
    r2 = await s.execute("print(x + 5)", proxy)  # reuses same session
# session automatically stopped on exit
```

#### Injected sessions (cost / quota optimisation)

For testing and notebooks, inject a **pre-existing session ID** to skip
`Start`/`Stop` API calls entirely:

```python
import os

sandbox = AgentCoreSandbox(
    code_interpreter_id=os.environ["AGENTCORE_CODE_INTERPRETER_ID"],
    session_id=os.environ["AGENTCORE_SESSION_ID"],  # pre-existing session
)
# No StartCodeInterpreterSession call — session is used as-is
result = await sandbox.execute(script, proxy)
```

> [!WARNING]
> **`network_mode="sandbox"`** — AWS's limited-isolation mode allows DNS queries (A/AAAA) that cannot be blocked at the infrastructure level. Research by BeyondTrust (Sep 2025) demonstrated this enables DNS-tunnelling-based data exfiltration and C2 channels. AWS closed the report as "intended functionality". A `WARNING` containing `"DNS egress risk"` is logged on every `execute()` call in this mode.
>
> **`network_mode="public"`** — Full unrestricted internet access by design. A `WARNING` is logged to flag this to operators.
>
> For production workloads handling secrets, PII, or credentials: provision a custom interpreter with `networkMode: "vpc"` via IaC and add an Amazon Route 53 Resolver DNS Firewall.

**IAM policy (minimum required):**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "bedrock-agentcore:StartCodeInterpreterSession",
      "bedrock-agentcore:InvokeCodeInterpreter",
      "bedrock-agentcore:StopCodeInterpreterSession"
    ],
    "Resource": "arn:aws:bedrock-agentcore:<region>:<account>:code-interpreter/*"
  }]
}
```

To also provision/destroy interpreters via IaC (Terraform, CloudFormation), add:
```json
"bedrock-agentcore:CreateCodeInterpreter",
"bedrock-agentcore:DeleteCodeInterpreter",
"bedrock-agentcore:GetCodeInterpreter",
"bedrock-agentcore:ListCodeInterpreters"
```

---

### 5.4 `E2BSandbox` — Firecracker microVM

```bash
uv add 'kest-core[e2b]'
```

```python
import os
from kest.core.sandbox import E2BSandbox, SandboxConfig

sandbox = E2BSandbox(api_key=os.environ["E2B_API_KEY"])

config = SandboxConfig(
    allowed_packages=["scipy", "numpy"],
    # network_mode="none"  # default — no outbound
)

result = await sandbox.execute(script, proxy, timeout_seconds=60, config=config)
```

**Using a custom template:**
```python
sandbox = E2BSandbox(
    api_key=os.environ["E2B_API_KEY"],
    template_id="my-kest-template",  # pre-baked packages
)
```

**Network rules** (set on template, not at runtime):
```python
# In E2B template definition (Dockerfile-style)
# No network by default. To allow specific domains:
# e2b.Sandbox(allowed_domains=["api.my-service.internal"])
```

---

### 5.5 `DockerSandbox`

```bash
uv add 'kest-core[docker]'
# Requires Docker daemon running on the host
```

```python
from kest.core.sandbox import DockerSandbox, SandboxConfig

sandbox = DockerSandbox(
    image="python:3.12-slim",
    network_mode="none",    # default
)

config = SandboxConfig(
    allowed_packages=["numpy"],
)

result = await sandbox.execute(script, proxy, timeout_seconds=30, config=config)
```

---

## 6. `SandboxConfig` Reference

```python
@dataclass
class SandboxConfig:
    allowed_modules: list[str] | None = None
    blocked_modules: list[str] = [
        "subprocess", "socket", "http", "urllib", "ftplib",
        "telnetlib", "smtplib", "xmlrpc", "multiprocessing",
        "ctypes", "cffi",
    ]
    blocked_builtins: list[str] = [
        "eval", "exec", "compile", "open",
        "__import__", "breakpoint", "input",
    ]
    allowed_packages: list[str] | None = None
    package_index_url: str | None = None
    network_mode: str = "none"
```

| Field | Description | Backends |
|---|---|---|
| `allowed_modules` | Explicit allowlist. `None` = no allowlist. | Subprocess, AgentCore (hook), E2B (hook), Docker |
| `blocked_modules` | Always-blocked modules regardless of allowlist. | Subprocess, AgentCore (hook), E2B (hook), Docker |
| `blocked_builtins` | Replaced with `SecurityError` stubs. | Subprocess, AgentCore (hook), E2B (hook), Docker |
| `allowed_packages` | Pre-installed before execution. | Subprocess, AgentCore, E2B, Docker |
| `package_index_url` | Exclusive package index (e.g. internal Artifactory). | Subprocess, E2B, Docker |
| `network_mode` | Backend network isolation mode. **AgentCore requires `"vpc"`**. | AgentCore (required), E2B, Docker |

> [!TIP]
> Pass `config=None` to use safe defaults (equivalent to `SandboxConfig()` with no arguments). The deny-by-default posture means you only need to configure what you want to **allow**, not what you want to block.

---

## 7. `ToolProxy` Pattern

The `ToolProxy` is the bridge between sandboxed code and the host. Every tool call is:
1. Routed through `ToolProxy.call_tool()`.
2. Enforced by `@kest_verified` — subject to policy evaluation, identity attestation, and lineage recording.
3. Contributes taints to `accumulated_taints`, which flow into `SandboxResult.taints_added`.

### Implementing a `ToolProxy`

```python
from kest.core.sandbox import ToolProxy
from kest.core import kest_verified

class MyToolProxy(ToolProxy):
    def __init__(self, tools: dict):
        self._tools = tools
        self._taints: set[str] = set()

    @kest_verified
    async def call_tool(self, tool_name: str, args: dict):
        fn = self._tools.get(tool_name)
        if fn is None:
            raise ValueError(f"Unknown tool: {tool_name}")
        result = await fn(**args)
        # Merge taints from tool result if applicable
        if hasattr(result, "taints"):
            self._taints.update(result.taints)
        return result.value if hasattr(result, "value") else result

    @property
    def accumulated_taints(self) -> frozenset[str]:
        return frozenset(self._taints)

    def reset(self):
        self._taints.clear()
```

### Using `accumulated_taints` for policy decisions

```python
result = await sandbox.execute(script, proxy, config=config)

if "pii" in result.taints_added:
    # Sandboxed code touched PII data — apply extra scrutiny
    raise PolicyViolation("Sandbox output is tainted with PII")

# Safe to proceed
process(result.return_value)
```

---

## 8. Security Guide

### Choosing `SandboxConfig` for your threat model

| Threat | Config |
|---|---|
| Script tries `import socket` | Default `blocked_modules` covers this |
| Script tries `eval("__import__('os').system('rm -rf /')")` | Default `blocked_builtins` blocks `eval` |
| Script tries to import a custom module that is not allowlisted | Set `allowed_modules` to an explicit list |
| Script installs a malicious package | Use `package_index_url` to restrict to internal index |
| AWS AgentCore DNS exfiltration | Always use `network_mode="vpc"` |

### Package installation security

- For `SubprocessSandbox`: **prefer pure-Python packages only** from an internal `package_index_url`. Native extensions can bypass Python-level import hooks.
- For `AgentCoreSandbox` and `E2BSandbox`: native extensions are containerised and cannot escape the microVM, so they are safer.
- Never set `allowed_packages` to a wildcard or untrusted list — treat it like an allowlist for production dependencies.

### `MontySandbox` security notice

`MontySandbox` is backed by `pydantic-monty` which is in `v0.0.x` with an active security bounty. Treat it as **experimental**:
- ✅ Safe for: low-privilege LLM tool orchestration, summarisation pipelines, math/data transformation.
- ❌ Unsafe for: code that processes secrets, PII, or cryptographic material.

---

## 9. Testing

### Unit testing with `MockSandboxProvider`

```python
from kest.core.sandbox import MockSandboxProvider, MockToolProxy, SandboxResult

async def test_my_workflow():
    mock_sandbox = MockSandboxProvider(
        result=SandboxResult(
            stdout="done\n",
            stderr="",
            return_value={"answer": 42},
            exit_code=0,
            taints_added=frozenset(["pii"]),
        )
    )
    mock_proxy = MockToolProxy(responses={"add": 42})

    result = await mock_sandbox.execute(
        script="result = call_tool('add', {'a': 10, 'b': 32})",
        tool_proxy=mock_proxy,
    )

    assert result.exit_code == 0
    assert "pii" in result.taints_added
    assert mock_sandbox.calls[0]["script"].startswith("result =")
```

### Integration testing — `SubprocessSandbox`

```python
import pytest
from kest.core.sandbox import SubprocessSandbox, SandboxConfig, MockToolProxy

@pytest.mark.asyncio
async def test_subprocess_sandbox_blocks_socket():
    sandbox = SubprocessSandbox()
    proxy = MockToolProxy()
    result = await sandbox.execute(
        script="import socket",
        tool_proxy=proxy,
        config=SandboxConfig(),
    )
    assert result.exit_code != 0
    assert "not allowed" in result.stderr
```

---

## 9. Running Live Tests Locally

> [!IMPORTANT]
> **`sandbox_live` tests are intentionally excluded from CI.** E2B (Firecracker microVM) and
> AgentCore (AWS Bedrock) both incur real cloud costs per execution. These tests should be run
> locally by developers with credentials, on demand — not in every PR.
>
> CI runs only the zero-cost tests: `SubprocessSandbox` unit tests and all mock-based
> `AgentCoreSandbox` / `E2BSandbox` tests (no real cloud calls).

### Running all zero-cost tests (CI-safe)

```bash
# Runs everything EXCEPT tests marked sandbox_live
uv run pytest src/kest/core/sandbox/ -v
# Expected: SubprocessSandbox (19 tests) + AgentCore mock tests (5) pass; live tests skip
```

### E2BSandbox — Firecracker microVM

**Prerequisites**: `E2B_API_KEY` from [e2b.dev](https://e2b.dev)

```bash
uv add 'kest-core[e2b]'

export E2B_API_KEY="e2b_..."
uv run pytest -m sandbox_live -v src/kest/core/sandbox/e2b_sandbox_test.py
```

### AgentCoreSandbox — AWS Bedrock

**Prerequisites**: IAM credentials with `bedrock-agentcore:*` permissions.

```bash
uv add 'kest-core[agentcore]'

# Standard IAM profile (auto-resolved by boto3)
# OR — SSO / credential-process profiles:
eval "$(aws configure export-credentials --format env)"

# Cost-saving: inject a pre-existing session to avoid per-test Start/Stop calls.
# (Creates one session; all test scenarios reuse it.)
export AGENTCORE_CODE_INTERPRETER_ID="aws.codeinterpreter.v1"
export AGENTCORE_REGION="ap-southeast-1"
export AGENTCORE_SESSION_ID=$(aws bedrock-agentcore start-code-interpreter-session \
    --code-interpreter-identifier "$AGENTCORE_CODE_INTERPRETER_ID" \
    --name kest-test-session \
    --session-timeout-seconds 3600 \
    --region "$AGENTCORE_REGION" \
    --query sessionId --output text)

uv run pytest -m sandbox_live -v src/kest/core/sandbox/agentcore_sandbox_test.py

# Clean up after testing
aws bedrock-agentcore stop-code-interpreter-session \
    --code-interpreter-identifier "$AGENTCORE_CODE_INTERPRETER_ID" \
    --session-id "$AGENTCORE_SESSION_ID" \
    --region "$AGENTCORE_REGION"
```

> [!NOTE]
> `AWS_BEARER_TOKEN` (ABSK) is an intra-AgentCore runtime credential used by agents running
> *inside* the AgentCore environment. It is **not** valid for direct boto3 API access.
> Use standard IAM credentials only.

---

## 10. Troubleshooting

### `SandboxNotAvailableError: MontySandbox requires pydantic-monty`

```bash
uv add 'kest-core[monty]'
```

### `AgentCoreSandbox` — understanding network mode warnings

All three AgentCore network modes are accepted. The network mode is a property of the
**Code Interpreter resource** set at provisioning time (IaC / CLI). Pass it in
`SandboxConfig.network_mode` so the SDK emits the appropriate operator warning:

| Mode | Internet access | Risk | Production safe? |
|---|---|---|---|
| `vpc` | Private network only | Lowest | ✅ Yes (add Route 53 DNS Firewall) |
| `sandbox` | S3 + DNS only | **Unpatched DNS-tunnel vuln** (AWS won't fix) | ⚠️ Mitigate with Route 53 DNS Firewall |
| `public` | Full internet | Intentionally open (by design) | ❌ Dev/test only |

### `AgentCoreSandbox` — cost-optimised testing with an injected session

The SDK supports an **injected session ID** that bypasses `Start`/`Stop` entirely:

```bash
# Start a session once (e.g. at the beginning of a test run / notebook)
export AGENTCORE_SESSION_ID=$(aws bedrock-agentcore start-code-interpreter-session \
    --code-interpreter-identifier aws.codeinterpreter.v1 \
    --name kest-test-session \
    --session-timeout-seconds 3600 \
    --query sessionId --output text)

export AGENTCORE_CODE_INTERPRETER_ID="aws.codeinterpreter.v1"
export AGENTCORE_REGION="us-east-1"

uv run pytest -m sandbox_live -v src/kest/core/sandbox/agentcore_sandbox_test.py
```

The test suite reuses `AGENTCORE_SESSION_ID` for all scenarios — zero additional
`StartCodeInterpreterSession` calls.

### `SandboxTimeoutError` on a script that should be fast

- Check whether the script is blocked waiting for a tool call that never returns.
- Check whether `uv pip install` for `allowed_packages` is slow (first run downloads packages; subsequent runs are cached).
- Increase `timeout_seconds` or pre-bake packages into a custom E2B template or Docker image.

### Import blocked that I need

Add the module to `SandboxConfig.allowed_modules`:
```python
config = SandboxConfig(
    allowed_modules=["json", "re", "datetime", "my_safe_module"],
)
```
Note: `blocked_modules` acts as a secondary deny-filter and overrides `allowed_modules`. Remove the module from `blocked_modules` too if it appears in both.

### Tool calls inside `MontySandbox` fail with `Unknown external function`

Monty requires every external function to be declared at interpreter creation time. `kest-core` pre-declares `"call_tool"`. If your script calls any other external function, it will fail. Route all calls through `call_tool(tool_name, args)`.

### Why isn't there a `WasmSandbox`?

A WebAssembly-based sandbox was initially considered for edge-compute scenarios. However, it was dropped for several reasons:
1. **Pyodide is heavy:** Running Python in WASM requires Pyodide (CPython compiled to WASM). Loading the Pyodide environment and libraries like `pandas` takes a few seconds of cold start and >100MB of memory, making it unsuitable for ultra-fast, lightweight execution.
2. **MontySandbox covers the niche:** For fast, in-process, network-free execution, `MontySandbox` provides sub-microsecond cold starts via Rust-native isolation.
3. **Async bridging:** Bridging the asynchronous `ToolProxy.call_tool` across the WASM boundary requires complex workarounds because WASI syscalls are synchronous.

If you need offline execution with C-extension libraries like `pandas`, use `SubprocessSandbox` (or a local Docker-based setup). If you need cloud execution, `E2BSandbox` and `AgentCoreSandbox` both natively support data science libraries.

---

*For the complete normative specification — including testable requirements (F-SB-*), security contract, and implementation ordering — see [`spec/SPEC-sandbox-v0.1.0.md`](../../../spec/SPEC-sandbox-v0.1.0.md).*

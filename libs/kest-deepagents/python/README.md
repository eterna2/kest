# kest-deepagents

[![PyPI version](https://img.shields.io/pypi/v/kest-deepagents.svg)](https://pypi.org/project/kest-deepagents/)
[![License: PolyForm Shield 1.0.0](https://img.shields.io/badge/License-PolyForm%20Shield%201.0.0-blue.svg)](https://polyformproject.org/licenses/shield/1.0.0/)
![PyPI - Downloads](https://img.shields.io/pypi/dm/kest-deepagents)

Zero-trust, policy-enforced agents for any [fsspec](https://filesystem-spec.readthedocs.io/)-compatible filesystem.  
Every tool invocation is a Kest-signed Merkle entry; policy decisions are logged in real time.

---

## Overview

`kest-deepagents` wraps filesystem operations in a **Kest zero-trust pipeline**:

```
User / LLM → @kest_verified tool → Policy engine → fsspec driver → Filesystem
                                         ↕
                                  OTel Merkle audit trail
```

All read, write, delete, mount, and shell operations are individually:

- **Sandboxed** — paths resolve inside a configured `root`; traversal attacks are rejected before the policy engine fires.
- **Policy-gated** — every tool carries a named policy (`fs_read_policy`, `fs_write_policy`, …) evaluated at call time.
- **Audited** — each allowed invocation extends the Merkle chain, visible in the TUI audit trail.

---

## Installation

```bash
pip install kest-deepagents                   # core
pip install "kest-deepagents[tui]"            # + Textual TUI
pip install "kest-deepagents[tui,s3]"         # + S3 / RustFS / MinIO
pip install "kest-deepagents[all]"            # everything
```

---

## Quick Start

```python
from kest.core import configure
from kest.core.identity import MockIdentityProvider
from kest.deepagents import FsspecAgent

configure(identity=MockIdentityProvider())

agent = FsspecAgent(root="/tmp/sandbox")

agent.get_tee_tool().invoke({"path": "hello.txt", "content": "Hello, Kest!"})
print(agent.get_cat_tool().invoke({"path": "hello.txt"}))
print(agent.get_ls_tool().invoke({"path": "."}))
```

---

## Components

### `KestAgent` — Multi-Agent Orchestrator

Composable host for an extensible registry of **subagents**. Any class implementing
`SubagentProtocol` (`name`, `description`, `get_tools()`) can be registered:

```python
from kest.deepagents import KestAgent, KestAdminSubagent, BrowserSubagent, FsspecAgent
from kest.deepagents.tui import KestAgentApp

agent = KestAgent(subagents=[
    FsspecAgent(root="/tmp/sandbox"),
    KestAdminSubagent(trace_backend=my_backend),
    BrowserSubagent(allowed_domains=["github.com"]),
])

# Flat tool list for any LangChain agent executor
tools = agent.get_tools()

# Or launch the TUI directly
KestAgentApp(agent=agent).run()
```

Pluggable by design. Register your own subagent in one line:

```python
agent.register(MyCustomSubagent())
```

### `KestAdminSubagent` — Policy Management

Built-in admin subagent with 5 zero-trust–enforced tools:

| Tool | Description |
|------|-------------|
| `explain_limits` | Inspect OTel trace to explain policy decisions |
| `create_policy` | Store a new policy definition |
| `list_policies` | List all stored policies |
| `apply_policy` | Bind a stored policy to a tool or agent (store-only, not engine-wired) |
| `delete_policy` | Remove a policy definition |

> **Note:** `apply_policy` updates the `PolicyStore` only. To make a policy effective,
> call `kest.core.configure(engine=...)` after wiring the store to your policy engine.
> This preserves the DI discipline and avoids hidden side effects.

Use a custom `PolicyStore` backend:

```python
from kest.deepagents import KestAdminSubagent, PolicyStore

class MyPolicyStore:  # implements PolicyStore protocol
    ...

KestAdminSubagent(trace_backend=backend, policy_store=MyPolicyStore())
```

### `SubagentProtocol` — Extension Contract

Implement this protocol to add your own subagent:

```python
from kest.deepagents import SubagentBase
from langchain_core.tools import BaseTool, tool

class MySubagent(SubagentBase):
    name = "my-tool"
    description = "Does something cool"

    def get_tools(self) -> list[BaseTool]:
        @tool
        def do_thing(param: str) -> str:
            """Does the thing."""
            return f"Done: {param}"
        return [do_thing]

agent.register(MySubagent())
```

### `FsspecAgent`

Protocol-agnostic filesystem agent. Supports any [fsspec](https://filesystem-spec.readthedocs.io/) driver — local, S3, GCS, FTP, SFTP, and more — with a unified zero-trust toolset.

| Tool | Policy | Trust |
|------|--------|-------|
| `ls`, `cat`, `grep` | `fs_read_policy` | 85–95 |
| `tee` | `fs_write_policy` | 70 |
| `rm` | `fs_delete_policy` | 50 |
| `exec` (local only, opt-in) | `fs_exec_policy` | 60 |
| `mount_fs` (interactive HITL) | `fs_mount_policy` | 70 |

The `mount_fs` tool uses a **3-step credential collection protocol** — the agent requests missing credentials from the user at runtime rather than requiring them at startup. Password fields are always masked and never logged.

### Plugins

- **`kest.deepagents.plugins.langchain`** — LangChain adapter; stack `@kest_verified` on any `@tool`.

---

## Examples

### Kest Agent TUI (`kest-agent`)

Full multi-agent TUI with one panel per subagent:

```bash
# Default demo with fs + admin + browser subagents
kest-agent
# or: moon run kest-deepagents-python:run-terminal
```

**TUI commands:**

```
@admin list_policies           # route to admin subagent
@admin create_policy id=p1 definition_json={...}
@browser navigate url=https://github.com
@fs ls path=/tmp
agents                         # list registered subagents and tools
help                           # full command reference
```

### FsspecAgent Terminal Demo

An interactive Textual TUI that demonstrates zero-trust enforcement against local and
remote filesystems, including interactive credential collection via `mount`.

→ **[Full setup guide and usage](examples/e2e/README.md)**

**Quick start:**

```bash
# Local filesystem (no extras needed)
moon run kest-deepagents-python:run-terminal

# With S3 / RustFS support (starts RustFS automatically)
moon run kest-deepagents-python:run-terminal-s3
```

---

## Security Model

1. **Root sandbox** — `_resolve(path)` rejects any path that escapes `root` using POSIX traversal checks.
2. **Policy gate** — `@kest_verified` evaluates the named policy; a denied result raises `PermissionError`.
3. **Shell isolation** — `exec` is only available when `allow_shell=True` **and** `fs` is `LocalFileSystem`.
4. **Credential safety** — mount credentials are never logged; confirmation summaries redact passwords as `****`.
5. **Merkle chain** — every allowed invocation appends to the Kest audit chain via OTel baggage.
6. **Policy store isolation** — `apply_policy` modifies only the `PolicyStore`, never the live engine. Engine wiring is always explicit.

---

## Further Reading

- [`CHANGELOG.md`](CHANGELOG.md) — Release history
- [`DESIGN.md`](DESIGN.md) — Architecture decisions
- [`examples/e2e/README.md`](examples/e2e/README.md) — Terminal demo setup, RustFS lab, interactive mount guide
- [Kest core docs](https://eterna2.github.io/kest/stable)

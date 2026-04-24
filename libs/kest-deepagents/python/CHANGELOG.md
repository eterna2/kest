# CHANGELOG — kest-deepagents

All notable changes to `kest-deepagents` are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased]

### Added

- **`KestAgent`** (`kest/deepagents/agent.py`) — composable multi-agent orchestrator.
  Manages a named registry of subagents; raises `TypeError` on non-conformant registrations
  and `ValueError` on duplicate names. Method-chaining: `agent.register(sa)` returns `self`.

- **`SubagentProtocol`** (`kest/deepagents/subagent.py`) — `runtime_checkable` structural
  protocol (`name: str`, `description: str`, `get_tools() → list[BaseTool]`).  
  All built-in agents now satisfy this protocol.

- **`SubagentBase`** — optional convenience base class; overriding `get_tools()` is
  all that's needed for custom subagents.

- **`PolicyStore` / `InMemoryPolicyStore`** (`kest/deepagents/admin.py`) — pluggable
  protocol for storing policy definitions. `InMemoryPolicyStore` is the default backend.

- **`KestAdminSubagent` — expanded** with 4 new `@kest_verified` policy CRUD tools:
  `create_policy`, `list_policies`, `apply_policy`, `delete_policy`.  
  `apply_policy` is store-only — callers must wire `kest.core.configure(engine=…)` themselves
  (documented with a `logging.warning` at call time).

- **`BrowserSubagent`** — aligned to `SubagentProtocol` (`name = "browser"`,
  `description`, `get_tools()`).

- **`FsspecAgent`** — aligned to `SubagentProtocol` (`name = "fs"`, `description`).

- **`kest.deepagents.tui`** — new optional sub-package (`pip install kest-deepagents[tui]`):
  - `KestAgentApp` — reusable `textual.App` with dynamic per-subagent panels,
    `@<name>` command routing, backward-compatible fs commands, and `_dispatch_custom` hook.
  - `SubagentPanel` — Textual widget (one log column per subagent).

- **`kest-agent` CLI** — new `kest-agent` script entry point that launches the full
  multi-subagent TUI with `fs`, `admin`, and `browser` subagents pre-registered.

- **`examples/e2e/terminal_demo.py`** — refactored from 760-line monolith to an
  ~80-line thin wrapper that constructs a `KestAgent` and delegates to `KestAgentApp`.

### Changed

- `__init__.py` — new exports: `KestAgent`, `SubagentProtocol`, `SubagentBase`,
  `PolicyStore`, `InMemoryPolicyStore`.

### Internal

- 50 new unit tests (Phase 1+2: protocol conformance, orchestrator logic, PolicyStore CRUD,
  all admin CRUD tools). Total: 267 tests.

# FsspecAgent — Terminal Demo

Interactive zero-trust terminal powered by [Kest](https://github.com/eterna2/kest) and
[Textual](https://textual.textualize.io/). Every command is a Kest-signed Merkle entry;
policy decisions and the audit trail are displayed live in a three-panel TUI.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Running the Demo](#running-the-demo)
3. [TUI Layout](#tui-layout)
4. [Commands](#commands)
5. [Interactive Mount Flow](#interactive-mount-flow)
6. [SQLite Personal Filesystem](#sqlite-personal-filesystem)
7. [Shell Execution (Security)](#shell-execution-security)
8. [RustFS Lab Setup (S3 target)](#rustfs-lab-setup-s3-target)
   - [Start RustFS](#start-rustfs)
   - [Connect to RustFS](#connect-to-rustfs)
   - [Tear Down](#tear-down)
9. [Demo Policy Engine](#demo-policy-engine)
10. [Extending the Demo](#extending-the-demo)

---

## Prerequisites

| Requirement | Minimum version |
|-------------|-----------------|
| Python | 3.11 |
| `uv` | latest |
| `moon` | latest |
| Docker + Compose | (S3 demo only) |

Install TUI dependencies:

```bash
# TUI only (local filesystem)
uv add "kest-deepagents[tui]"

# TUI + S3 / RustFS driver
uv add "kest-deepagents[tui,s3]"
```

---

## Running the Demo

**Quickest path — moon (from anywhere in the monorepo):**

```bash
# Local filesystem sandbox
moon run kest-deepagents-python:run-terminal

# Local filesystem + specific working directory
uv run --extra tui kest-terminal --workdir /tmp/my-sandbox

# With S3 / RustFS support (also starts RustFS automatically)
moon run kest-deepagents-python:run-terminal-s3
```

---

## TUI Layout

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│  🔒 Kest FsspecAgent — Zero-Trust Filesystem Demo    12:34:56                   │
├────────────────────────────┬──────────────────────┬─────────────────────────────┤
│ 📟 Output                  │ 🔒 Policy decisions  │ ⛓  Merkle audit trail       │
│                            │                      │                             │
│ 📂 Active FS: file::/tmp   │ ✅ ALLOW  ls         │ ls   a1b2c3d4…              │
│                            │ ✅ ALLOW  cat        │ cat  e5f6g7h8…              │
│ > ls .                     │ ❌ DENY   rm         │ rm   BLOCKED                │
│ notes.txt                  │                      │                             │
│ config.toml                │                      │                             │
│                            │                      │                             │
├────────────────────────────┴──────────────────────┴─────────────────────────────┤
│ > _                                                                             │
└─────────────────────────────────────────────────────────────────────────────────┘
```

The **Active FS banner** (top-left of the Output panel) updates every time you mount
a new filesystem.

---

## Commands

| Command | Example | Policy | Trust |
|---------|---------|--------|-------|
| `ls [path]` | `ls src/` | `fs_read_policy` | 95 |
| `cat <path> [head=N] [tail=N] [enc=ENC]` | `cat notes.txt head=5` | `fs_read_policy` | 90 |
| `head <path> [N] [enc=ENC]` | `head log.txt 20` | `fs_read_policy` | 90 |
| `tail <path> [N] [enc=ENC]` | `tail log.txt 10` | `fs_read_policy` | 90 |
| `info <path>` | `info report.pdf` | — | — |
| `grep <pattern> [path]` | `grep TODO .` | `fs_read_policy` | 85 |
| `tee <path> <content>` | `tee out.txt Hello world` | `fs_write_policy` | 70 |
| `mkdir <path>` | `mkdir logs/2026` | `fs_write_policy` | 70 |
| `rm <path>` | `rm tmp.txt` ⚠ | `fs_delete_policy` | 50 |
| `exec <cmd> [argv]` | `exec git status` | `fs_exec_policy` | 60 |
| `mount [scheme]` | `mount s3`, `mount sqlite` | `fs_mount_policy` | 70 |
| `shell on` / `shell off` | — | — | — |
| `shell status` | — | — | — |
| `help` | — | — | — |
| `quit` / `exit` | — | — | — |

> **Demo policy**: `rm` is **blocked** by the demo engine. See [Demo Policy Engine](#demo-policy-engine) to adjust.

### Progressive disclosure

For large files, avoid reading everything at once:

```
> cat notes.txt head=10           # first 10 lines (decoded as utf-8 by default)
> cat notes.txt tail=5            # last 5 lines
> cat notes.txt head=20 enc=utf-8 # first 20 lines, explicit encoding

> head report.txt 30              # shorthand: first 30 lines
> tail access.log 50              # shorthand: last 50 lines
```

Use `info` to see a file's `mime_type`, `size`, and timestamps before deciding whether
to read it:

```
> info document.pdf
info: document.pdf
  name = /workspace/document.pdf
  type = file
  size = 204800
  mime_type = application/pdf
  created = 1713484800.0
  modified = 1713484900.0
```

---

## Interactive Mount Flow

Type `mount` (scheme selector appears) or `mount <scheme>` to skip straight to the
credential form.

```
> mount s3
⚙  Probing s3 driver…

╔══════════════════════════════════════╗
║  🔗 Mount: S3 / RustFS (s3)         ║
║                                      ║
║  Endpoint URL                        ║
║  [ http://localhost:9000         ]   ║
║                                      ║
║  Access key                          ║
║  [ minioadmin                    ]   ║
║                                      ║
║  Secret key             [masked]     ║
║  [ ••••••••              ]           ║
║                                      ║
║  Root  (bucket name / prefix)        ║
║  [ kest-demo                     ]   ║
║                                      ║
║  [ Cancel ]         [ Connect →  ]   ║
╚══════════════════════════════════════╝

⚠ Confirm filesystem switch:
  Mount: scheme=s3, root=kest-demo, endpoint_url=http://localhost:9000,
         key=minioadmin, secret=****
  Type y to confirm or n to cancel.

> y
✅ Mounted: s3::kest-demo

📂 Active FS: s3::kest-demo
```

Password fields are **always masked** during input and **always redacted** (`****`) in
the confirmation summary — they never appear in logs or the Merkle audit trail.

The underlying protocol is a **3-step HITL tool conversation**:

| Step | Tool call | Tool returns |
|------|-----------|-------------|
| 1 | `scheme="s3"` | `ParamRequest` — which fields are missing |
| 2 | all params, no `confirmed` | `ConfirmRequest` — sanitised summary |
| 3 | all params + `"confirmed":"true"` | `MountResult` — FS switched |

---

## SQLite Personal Filesystem

`SqliteFileSystem` is a lightweight, zero-dependency fsspec extension that
stores entire directory trees inside a single SQLite `.db` file.  It
behaves as a conventional filesystem but is fully portable — copy the file
anywhere and your data travels with it.

### Mount in the TUI

```
> mount sqlite

╔══════════════════════════════════════╗
║  🔗 SQLite personal filesystem      ║
║                                      ║
║  Database file path                  ║
║  [ ~/.kest/personal.db           ]   ║
║                                      ║
║  [ Cancel ]         [ Connect →  ]   ║
╚══════════════════════════════════════╝

> y
✅ Mounted: sqlite::~/.kest/personal.db
```

### Use from Python

```python
from kest.deepagents import SqliteFileSystem, FsspecAgent

# Create (or open existing) personal filesystem
fs = SqliteFileSystem(db_path="~/personal.db")

# Basic operations
fs.pipe_file("/notes/diary.txt", b"Today I used a SQLite filesystem!")
print(fs.cat_file("/notes/diary.txt"))                         # full bytes
print(fs.cat_file("/notes/diary.txt", encoding="utf-8"))       # decoded string
print(fs.cat_file("/notes/diary.txt", start=0, end=5))         # byte-range slice
print(fs.ls("/notes"))

# Rich metadata — including MIME type for AI agents
meta = fs.info("/notes/diary.txt")
print(meta["mime_type"])               # text/plain
print(fs.created("/notes/diary.txt"))  # datetime object
print(fs.modified("/notes/diary.txt")) # datetime object

# Wrap in FsspecAgent for zero-trust tool use
agent = FsspecAgent(fs=fs, root="/workspace")
tools = agent.get_tools()  # ls, cat, head, tail, grep, tee, rm, mkdir, mount_fs
```

### SQLite and shell execution

SQLite is a **local** filesystem — `shell on` is permitted after mounting it:

```
> mount sqlite
# fill ~/.kest/personal.db in the dialog
✅ Mounted: sqlite::~/.kest/personal.db

> shell on
✅ Shell execution enabled.

> exec echo Hello from the SQLite sandbox
```

> **Note**: `exec` still runs in the `FsspecAgent.root` directory; the sandbox
> restriction applies regardless of shell state.

---

## Shell Execution (Security)

The `exec` tool (shell command execution) is **disabled by default** for
remote filesystems to uphold zero-trust principles.

### Auto-disable on remote mount

When you mount any **remote** filesystem (e.g., S3, FTP, SFTP), the TUI
automatically turns off shell execution and displays a warning:

```
⚠ WARNING: Shell execution has been automatically disabled because you
mounted a remote filesystem (scheme=s3). This protects against command
injection from potentially untrusted remote paths.

To re-enable shell, first mount a local filesystem:
  mount file   or   mount sqlite

Then use:  shell on
```

The banner updates to show the current shell state:

```
🔒 Kest FsspecAgent — 🔒 shell:off    ← shell disabled (amber color)
🔒 Kest FsspecAgent — 🖥 shell:on     ← shell enabled
```

### Toggle shell manually

```
> shell on       # enable exec tool
> shell off      # disable exec tool
> shell status   # print current state
```

> **Security note**: `shell on` is only permitted when `LocalFileSystem` or
> `SqliteFileSystem` is active. Mounting any remote scheme automatically
> sets `allow_shell = False`.

---

## RustFS Lab Setup (S3 target)

[RustFS](https://rustfs.com) is an S3-compatible object store written in Rust,
included in `kest-lab` as a realistic remote storage target.

### Start RustFS

```bash
# From anywhere in the monorepo (recommended):
moon run kest-deepagents-python:rustfs-up

# Or directly from kest-lab:
cd showcase/kest-lab
docker compose up -d rustfs rustfs-init
```

Wait for the bucket to be ready:

```bash
moon run kest-lab:rustfs-logs
# Look for: "Bucket kest-demo ready."
```

**Endpoints once running:**

| Endpoint | Purpose |
|----------|---------|
| `http://localhost:9000` | S3 API — connect the TUI here |
| `http://localhost:9001` | RustFS web console |

**Default credentials (local dev only):**

| Field | Value |
|-------|-------|
| Access key | `minioadmin` |
| Secret key | `minioadmin` |

### Connect to RustFS

**One command:**

```bash
moon run kest-deepagents-python:run-terminal-s3
```

This starts RustFS (if not already running) and launches the TUI with `s3fs` installed.

**In the TUI:**

```
> mount s3
# Fill the modal:
#   Endpoint URL : http://localhost:9000
#   Access key   : minioadmin
#   Secret key   : minioadmin       ← masked during input
#   Root         : kest-demo
# Confirm with y

> tee hello.txt Hello from RustFS via Kest!
> cat hello.txt
> ls .
> grep Hello .
```

### Tear Down

```bash
# Stop containers (volume preserved):
moon run kest-deepagents-python:rustfs-down

# Full teardown including data volume:
cd showcase/kest-lab && docker compose down -v rustfs rustfs-init
```

---

## Demo Policy Engine

`terminal_demo.py` uses `HardcodedRuleEngine` from `kest.deepagents._test_helpers`:

```python
DEMO_ENGINE = HardcodedRuleEngine(
    blocked_policies=frozenset({"fs_delete_policy"}),
    min_trust=60,
)
```

| Result | Condition |
|--------|-----------|
| ❌ DENY | policy name is in `blocked_policies` |
| ❌ DENY | tool trust level < `min_trust` (60) |
| ✅ ALLOW | everything else |

To use a real OPA or Cedar policy engine, replace `DEMO_ENGINE` with your engine
instance and pass it to `configure(engine=..., identity=...)`.

---

## Extending the Demo

### Add a new filesystem

Add an entry to `FILESYSTEM_REGISTRY` in `fsspec_agent.py`:

```python
from kest.deepagents.fsspec_agent import FILESYSTEM_REGISTRY, FilesystemSpec, ParamSpec

FILESYSTEM_REGISTRY["myproto"] = FilesystemSpec(
    label="My Custom Protocol",
    import_check="my_fsspec_driver",   # package name, or "" if built in
    params=[
        ParamSpec("host",     "Hostname"),
        ParamSpec("token",    "API token", password=True),
    ],
)
```

The `mount` command in the TUI and the `SchemeSelectDialog` will automatically pick it up.

### Change the sandbox root at startup

```bash
uv run --extra tui kest-terminal --workdir /path/to/your/sandbox
```

### Run without the TUI (programmatic)

```python
import json
from kest.deepagents.fsspec_agent import FsspecAgent

agent = FsspecAgent(root="/tmp/sandbox")
tool  = agent.get_mount_tool()

# Probe
print(json.loads(tool.invoke({"scheme": "memory"})))
# → ConfirmRequest (memory has no required params)

# Mount
print(json.loads(tool.invoke({
    "scheme": "memory",
    "params": json.dumps({"root": "/workspace", "confirmed": "true"}),
})))
# → MountResult {"protocol": "memory", "root": "/workspace", ...}
```

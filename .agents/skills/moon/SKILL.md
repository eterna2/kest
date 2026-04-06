---
name: moon
description: This skill should be used when the user asks to "configure moon", "set up moonrepo", "create moon tasks", "run moon commands", "configure moon workspace", "add moon project", "moon ci setup", "moon docker", "moon query", "migrate to moon v2", or mentions moon.yml, .moon/workspace.yml, .moon/toolchains.yml, moon run, moon ci, or moonrepo in general.
---

# moon - Polyglot Monorepo Build System

moon is a Rust-based repository management, task orchestration, and build system for polyglot monorepos. It provides smart caching, dependency-aware task execution, and unified toolchain management.

## When to Use moon

- Managing monorepos with multiple projects/packages
- Orchestrating tasks across projects with dependencies
- Caching build outputs for faster CI/local builds
- Managing toolchain versions (Node.js, Rust, Python, Go, etc.)
- Generating project and action graphs

## Quick Reference

### Core Commands

```bash
moon run <target>          # Run task(s)
moon run :lint             # Run in all projects
moon run '#tag:test'       # Run by tag
moon ci                    # CI-optimized execution
moon check --all           # Run all build/test tasks
moon query projects        # List projects
moon project-graph         # Visualize dependencies
moon exec <target> -- <cmd> # Execute arbitrary command in project
```

### Target Syntax

| Pattern        | Description                     |
| -------------- | ------------------------------- |
| `project:task` | Specific project and task       |
| `:task`        | All projects with this task     |
| `#tag:task`    | Projects with tag               |
| `^:task`       | Upstream dependencies (in deps) |
| `~:task`       | Current project (in configs)    |

### Configuration Files

| File                   | Purpose                               |
| ---------------------- | ------------------------------------- |
| `.moon/workspace.yml`  | Workspace settings, project discovery |
| `.moon/toolchains.yml` | Language versions, package managers   |
| `.moon/tasks/*.yml`    | Global inherited tasks                |
| `moon.yml`             | Project-level config and tasks        |

## Workspace Configuration

```yaml
# .moon/workspace.yml
$schema: "https://moonrepo.dev/schemas/workspace.json"

projects:
  - "apps/*"
  - "packages/*"

vcs:
  client: "git"
  defaultBranch: "main"

pipeline:
  cacheLifetime: "7 days"
  autoCleanCache: true
```

## Project Configuration

```yaml
# moon.yml
$schema: "https://moonrepo.dev/schemas/project.json"

language: "typescript"
layer: "application"
stack: "frontend"
tags: ["react", "graphql"]

dependsOn:
  - "shared-utils"
  - id: "api-client"
    scope: "production"

fileGroups:
  sources:
    - "src/**/*"
  tests:
    - "tests/**/*"

tasks:
  build:
    command: "vite build"
    inputs:
      - "@group(sources)"
    outputs:
      - "dist"
    deps:
      - "^:build"

  dev:
    command: "vite dev"
    preset: "server"

  # Use 'script' for shell features (pipes, redirects, chaining)
  lint:
    script: "eslint . && prettier --check ."

  test:
    command: "vitest run"
    inputs:
      - "@group(sources)"
      - "@group(tests)"
```

### Project Layers

| Layer           | Description           |
| --------------- | --------------------- |
| `application`   | Apps, services        |
| `library`       | Shareable code        |
| `tool`          | CLIs, scripts         |
| `automation`    | E2E/integration tests |
| `scaffolding`   | Templates, generators |
| `configuration` | Infra, config         |

## Task Configuration

### Task Fields

| Field        | Description                          |
| ------------ | ------------------------------------ |
| `command`    | Simple command to execute            |
| `script`     | Shell script (supports shell syntax) |
| `args`       | Additional arguments                 |
| `deps`       | Task dependencies                    |
| `inputs`     | Files for cache hashing              |
| `outputs`    | Files to cache                       |
| `env`        | Environment variables                |
| `extends`    | Inherit from another task            |
| `preset`     | `server` or `utility`                |
| `toolchains` | Toolchain overrides                  |

### Task Inheritance

Tasks can be inherited globally via `.moon/tasks/*.yml`:

```yaml
# .moon/tasks/node.yml
inheritedBy:
  toolchains: ["javascript", "typescript"]

fileGroups:
  sources: ["src/**/*"]

tasks:
  lint:
    command: "eslint ."
    inputs: ["@group(sources)"]
```

## Toolchain Configuration

```yaml
# .moon/toolchains.yml
$schema: "https://moonrepo.dev/schemas/toolchains.json"

# JavaScript ecosystem (required for node/bun/deno)
javascript:
  packageManager: "pnpm"
  inferTasksFromScripts: false
  installDependencies: true
  inheritAliases: true

node:
  version: "20.10.0"

pnpm:
  version: "8.12.0"

rust:
  version: "1.75.0"
  bins: ["cargo-nextest"]

python:
  version: "3.12.0"
```

## CI Integration

```yaml
# GitHub Actions
- uses: actions/checkout@v4
  with:
    fetch-depth: 0

- uses: moonrepo/setup-toolchain@v0
  with:
    auto-install: true

- run: moon ci :build :test
```

### Affected Detection

```bash
moon run :test --affected             # Only affected projects
moon run :lint --affected --status staged  # Only staged files
moon ci :test --base origin/main      # Compare against base
moon query changed-files              # List files changed since base
```

## Docker Support

```bash
moon docker scaffold <project>     # Generate Docker layers
moon docker setup                  # Install toolchain in Docker
moon docker prune                  # Prune for production
```

## Additional Resources

For detailed configuration options, consult:

- **`resources/workspace-config.md`** - Complete workspace.yml reference
- **`resources/task-config.md`** - Task configuration and inheritance patterns
- **`resources/v2-migration.md`** - Legacy v1 to v2 migration guide
- **`resources/cli-reference.md`** - Full CLI command reference

### Examples

- **`examples/workspace.yml`** - Complete workspace configuration
- **`examples/toolchains.yml`** - Toolchain configuration
- **`examples/moon.yml`** - Full project configuration
- **`examples/ci-workflow.yml`** - GitHub Actions CI workflow

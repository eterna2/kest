# Moon Task Configuration Reference

Complete reference for task configuration in moon.yml and .moon/tasks/*.yml.

## Global Task Inheritance

### Configuration Hierarchy

```
.moon/tasks/all.yml          # Inherited by ALL projects
.moon/tasks/*.yml            # Conditional inheritance based on conditions
└── moon.yml                 # Project-level tasks (override/merge)
```

### Global Tasks File Structure

```yaml
# .moon/tasks/node.yml
$schema: "https://moonrepo.dev/schemas/tasks.json"

# Conditions for which projects inherit these tasks
inheritedBy:
  toolchains:
    or: ["javascript", "typescript"]
  stacks: ["frontend", "backend"]
  layers: ["application", "library"]

# File groups inherited by matching projects
fileGroups:
  sources:
    - "src/**/*"
  tests:
    - "tests/**/*"

# Default options for all tasks in this file
taskOptions:
  cache: true
  runInCI: "affected"

# Implicit dependencies added to ALL tasks
implicitDeps:
  - "^:build"

# Implicit inputs added to ALL tasks
implicitInputs:
  - "package.json"
  - "/.moon/toolchains.yml"

# Tasks inherited by matching projects
tasks:
  lint:
    command: "eslint ."
    inputs:
      - "@group(sources)"
```

### Inheritance Conditions

| Condition    | Description                 | Example                              |
| ------------ | --------------------------- | ------------------------------------ |
| `toolchains` | Project toolchain           | `['javascript', 'typescript']`       |
| `stacks`     | Project stack               | `['frontend', 'backend']`            |
| `layers`     | Project layer               | `['application', 'library', 'tool']` |
| `tags`       | Project tags                | `['react', 'graphql']`               |
| `languages`  | Project language            | `['python', 'go']`                   |
| `files`      | Files that exist in project | `['Cargo.toml']`                     |

## Task Definition

```yaml
tasks:
  build:
    # Simple command (no shell features)
    command: 'webpack build --mode production'

    # Shell script (supports pipes, redirects, chaining)
    script: 'rm -rf dist && webpack build > build.log'

    # Environment variables
    env:
      NODE_ENV: 'production'

    # Task dependencies
    deps:
      - 'shared:build'        # Specific project
      - '~:codegen'           # Same project
      - '^:build'             # All upstream deps

    # Input files for hash calculation
    inputs:
      - 'src/**/*'
      - '@group(sources)'

    # Output files to cache
    outputs:
      - 'dist'

    # Inherit from another task
    extends: 'base-build'

    # Task preset (server, utility)
    preset: 'server'

    # Toolchain override
    toolchain: 'node'

    # Task options
    options:
      cache: true
      runInCI: 'affected'
```

## Task Options Reference

### Caching

| Option          | Type                             | Default | Description           |
| --------------- | -------------------------------- | ------- | --------------------- |
| `cache`         | `boolean \| 'local' \| 'remote'` | `true`  | Enable caching        |
| `cacheKey`      | `string`                         | -       | Custom invalidation   |
| `cacheLifetime` | `string`                         | -       | Expiration (e.g. '7d') |

### Execution

| Option                 | Type                                        | Default      | Description                   |
| ---------------------- | ------------------------------------------- | ------------ | ----------------------------- |
| `persistent`           | `boolean`                                   | `false`      | Long-running (servers)        |
| `runInCI`              | `'affected' \| 'always' \| 'only' \| false` | `'affected'` | CI behavior                   |
| `runFromWorkspaceRoot` | `boolean`                                   | `false`      | Execute from root             |
| `runDepsInParallel`    | `boolean`                                   | `true`       | Parallel deps                 |
| `timeout`              | `number`                                    | -            | Max runtime (sec)             |
| `retryCount`           | `number`                                    | `0`          | Retries                       |
| `priority`             | `'critical' \| 'high' \| 'normal' \| 'low'` | `'normal'`   | Queue priority                |
| `interactive`          | `boolean`                                   | `false`      | Requires stdin                |
| `allowFailure`         | `boolean`                                   | `false`      | Soft failure                  |

### Affected Files (v2.1)

```yaml
tasks:
  test:
    command: "vitest"
    options:
      affectedFiles:
        filter: "src/**/*.test.ts"
        ignoreProjectBoundary: false
        passDotWhenNoResults: true
```

### Shell

| Option      | Type      | Default | Description   |
| ----------- | --------- | ------- | ------------- |
| `shell`     | `boolean` | `true`  | Run in shell  |
| `unixShell` | `string`  | -       | Specify shell |

### Merge Strategies

| Option         | Values                                          | Default    |
| -------------- | ----------------------------------------------- | ---------- |
| `mergeArgs`    | `'append' \| 'prepend' \| 'replace'`            | `'append'` |
| `mergeDeps`    | `'append' \| 'prepend' \| 'replace'`            | `'append'` |
| `mergeEnv`     | `'append' \| 'prepend' \| 'replace' \| 'union'` | `'append'` |
| `mergeInputs`  | `'append' \| 'prepend' \| 'replace'`            | `'append'` |
| `mergeOutputs` | `'append' \| 'prepend' \| 'replace'`            | `'append'` |

## Token Variables

### Project Variables

| Variable         | Description                  |
| ---------------- | ---------------------------- |
| `$project`       | Project ID                   |
| `$projectRoot`   | Absolute path to project     |
| `$projectSource` | Relative path from workspace |
| `$projectTitle`  | Human-readable title         |
| `$projectLayer`  | Project layer (v2)           |
| `$language`      | Project language             |

## File Groups

File groups organize related files for reuse.

```yaml
fileGroups:
  sources:
    - "src/**/*"
  tests:
    - "tests/**/*"
  configs:
    - "*.config.{js,ts}"
    - "tsconfig.json"
```

### Token Functions

| Token          | Description         |
| -------------- | ------------------- |
| `@group(name)` | All items in group  |
| `@globs(name)` | Glob patterns       |
| `@files(name)` | Expanded file paths |

## Task Presets

| Preset    | cache   | outputStyle | persistent | interactive | runInCI |
| --------- | ------- | ----------- | ---------- | ----------- | ------- |
| `server`  | `false` | `stream`    | `true`     | -           | `false` |
| `utility` | `false` | `stream`    | `false`    | `true`      | `skip`  |

Tasks named `dev`, `start`, or `serve` automatically get the `server` preset.

## Common Patterns

### Build with Dependencies

```yaml
tasks:
  build:
    command: "tsc"
    deps:
      - "^:build" # Build upstream first
    inputs:
      - "@group(sources)"
    outputs:
      - "dist"
```

### Serial Execution

```yaml
tasks:
  deploy:
    command: "./deploy.sh"
    deps:
      - "build"
      - "test"
    options:
      runDepsInParallel: false
```

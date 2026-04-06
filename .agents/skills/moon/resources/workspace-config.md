# Moon Workspace Configuration Reference

Complete reference for `.moon/workspace.yml` configuration.

## Schema

```yaml
$schema: "https://moonrepo.dev/schemas/workspace.json"
```

## Projects

### Glob Patterns

```yaml
projects:
  - "apps/*"
  - "packages/*"
  - "tools/*"
  - "!packages/deprecated-*" # Exclusion
```

### Explicit Mapping

```yaml
projects:
  sources:
    app: "apps/web"
    api: "apps/api"
  globs:
    - "packages/*"
```

## VCS Configuration

```yaml
vcs:
  client: "git"
  provider: "github" # github, gitlab, bitbucket, other
  defaultBranch: "main"
  remoteCandidates:
    - "origin"
    - "upstream"
  sync: true # Synchronize VCS hooks on run
  hooks:
    pre-commit:
      - "moon run :lint --affected --status staged"
    pre-push:
      - "moon run :test --affected"
```

> Note: VCS hooks write to `.moon/hooks` instead of `.git/hooks`.

## Pipeline Configuration

```yaml
pipeline:
  # Targets to archive for caching
  archivableTargets:
    - ":build"
    - ":test"

  # Cache settings
  cacheLifetime: "7 days"
  autoCleanCache: true

  # Output settings
  inheritColorsForPipedTasks: true
  logRunningCommand: true

  # Execution
  concurrency: 8 # Parallel task limit

  # Dependency management
  installDependencies: true
  syncProjects: true
  syncWorkspace: true

  # Process control
  killProcessThreshold: 3
```

## Default Project

```yaml
# When running :task without project scope, use this project
defaultProject: "website"
```

## Hasher Configuration

```yaml
hasher:
  # Optimization mode
  optimization: "performance" # accuracy, performance

  # Walk strategy
  walkStrategy: "vcs" # glob, vcs

  # Ignore patterns
  ignoredPatterns:
    - "**/.git/**"
    - "**/node_modules/**"
```

## Code Owners

```yaml
codeowners:
  globalPaths:
    "/*": ["@platform-team"]
    "/apps/*": ["@product-team"]
    "/packages/*": ["@library-team"]
  orderBy: "project-source"
  sync: true
```

## Constraints

```yaml
constraints:
  # Enforce layer relationships
  enforceProjectTypeRelationships: true

  # Tag-based dependency rules
  tagRelationships:
    frontend:
      requires: ["shared"]
      conflicts: ["backend-only"]
    backend:
      requires: ["shared"]
```

## Generator

```yaml
generator:
  templates:
    - "./templates"
    - "npm:@company/templates"
```

## Remote Caching

```yaml
remote:
  host: "grpcs://cache.example.com"
  auth:
    token: "CACHE_TOKEN"
    headers:
      "X-Custom-Header": "value"
  cache:
    compression: "zstd"
    verifyIntegrity: true
    localReadOnly: false # Download only, no uploads (for dev)
```

## Notifier

```yaml
notifier:
  webhookUrl: "https://hooks.slack.com/..."
```

## Telemetry

```yaml
telemetry: true # Enable usage telemetry
```

## Complete Example

```yaml
$schema: "https://moonrepo.dev/schemas/workspace.json"

projects:
  - "apps/*"
  - "packages/*"
  - "tools/*"

vcs:
  client: "git"
  provider: "github"
  defaultBranch: "main"
  sync: true
  hooks:
    pre-commit:
      - "moon run :lint --affected --status staged"

pipeline:
  archivableTargets:
    - ":build"
  cacheLifetime: "7 days"
  inheritColorsForPipedTasks: true
  logRunningCommand: true
  autoCleanCache: true

hasher:
  optimization: "performance"
  walkStrategy: "vcs"

codeowners:
  globalPaths:
    "/*": ["@platform-team"]
  sync: true

constraints:
  enforceProjectTypeRelationships: true
  tagRelationships:
    frontend:
      requires: ["shared"]
    backend:
      requires: ["shared"]

generator:
  templates:
    - "./templates"

telemetry: true
```

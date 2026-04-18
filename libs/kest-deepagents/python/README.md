# kest-deepagents

[![PyPI version](https://img.shields.io/pypi/v/kest-deepagents.svg)](https://pypi.org/project/kest-deepagents/)
[![License: PolyForm Shield 1.0.0](https://img.shields.io/badge/License-PolyForm%20Shield%201.0.0-blue.svg)](https://polyformproject.org/licenses/shield/1.0.0/)
![PyPI - Downloads](https://img.shields.io/pypi/dm/kest-deepagents)

The `kest-deepagents` library provides the specific bridging abstractions required to mount `kest` capabilities securely onto `deepagents`. It allows terminal and browser agents to operate securely with robust, policy-backed guardrails.

## Overview

This adapter implements zero-trust components natively for multi-agent ecosystems by:
1. Wrapping existing `deepagents` tools via the `kest_tool` decorator.
2. Providing out-of-the-box subagents to enforce admin policies and browser orchestration securely.

## Components

### `kest_tool` Adapter
The `@kest_tool` decorator is applied to any `deepagents` tool. It automatically intersects the execution request, parses the agent's Passport from context, and evaluates the `kest` policy before allowing tool execution.

```python
from kest.deepagents import kest_tool

@kest_tool("AdminAccessPolicy")
def restart_server(server_id: str) -> bool:
    # Logic to restart a server
    return True
```

### Pre-configured Subagents
- **`kest_admin_subagent`**: Designed for evaluating execution metrics, looking up traces, and enforcing overarching system policies dynamically.
- **`browser_subagent`**: Capable of using MCP to surf securely under constraint policies.

## Usage

Please refer to the `showcase/kest-terminal-agent` code for a complete end-to-end example of bridging configuration wizards, keyring setups, and agent limits in action.

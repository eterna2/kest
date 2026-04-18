# Kest Terminal Agent Showcase

An interactive `Textual`-based application demonstrating the orchestration of multi-agent systems via `kest-deepagents`.

## Overview
This showcase provides a setup wizard designed to:
- Generate constraint policies using an LLM integration (e.g. OpenAI/Anthropic/Gemini).
- Store API keys natively into your Operating System's Keyring instead of keeping them in plaintext configuration files.
- Launch a `terminal_subagent` and `browser_subagent` securely locked down by the policies generated.

## Setup Requirements

Be sure you have deployed the full local moon toolchain.

1. Ensure the `kest-deepagents` module is built and available locally.
2. Ensure you have `keyring` backed by your OS credential manager.

```bash
uv sync
```

## Running the Dashboard

```bash
uv run python hello.py
```

## Architecture

This application simulates an enterprise "Zero-Trust" jump host.
When an Admin accesses it, the `keyring` fetches the API keys implicitly. Agents are spun up under `OAuthCliProvider` deterministic keys and their actions are recorded as `kest` verifiable trace lineages natively.

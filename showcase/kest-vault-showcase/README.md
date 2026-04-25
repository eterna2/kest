# Kest Vault Showcase — MCP-based Medical Records Agent

Demonstrates the **HandleVault + OpaqueHandle** pattern in a realistic multi-agent scenario with two
MCP servers and an orchestrating agent.

## Scenario

A **Medical Records Agent** is asked to summarise a patient's treatment plan. The agent calls two
MCP tools:

| Tool (MCP Server) | Data sensitivity | Vault-protected? |
|---|---|---|
| `patient_records` MCP | Patient PII (name, SSN, DOB, diagnosis) | ✅ Returns opaque handles only |
| `pharmacy` MCP | Drug info & interactions (non-sensitive) | ❌ Plain data |

The agent **never sees** raw PII. It receives opaque handle IDs and non-sensitive `safe_view`
summaries, composes its response using those, and returns the handle IDs to the caller.

A privileged **gateway** later resolves the handles with ACL enforcement.

```
┌──────────────────────────────────────────────────────────────┐
│                       Agent process                          │
│                                                              │
│  1. call patient_records MCP  ──► HandleVault.seal(PII)      │
│     receives  hdl_xxx + "Patient record for P-001" ◄──┘      │
│                                                              │
│  2. call pharmacy MCP  ──► plain drug lookup result          │
│                                                              │
│  3. compose summary using safe_views + drug info             │
│     (no raw PII ever in agent memory)                        │
│                                                              │
│  4. return {handle_id, safe_view, drug_summary}              │
└──────────────────────────────────────────────────────────────┘
          │
          ▼
┌──────────────────────────────────────────────────────────────┐
│   Gateway (privileged principal)                             │
│   HandleVault.unseal(handle_id, requesting_principal=self)   │
│   → raw PII for audit / downstream system                    │
└──────────────────────────────────────────────────────────────┘
```

## File Layout

```
kest-vault-showcase/
├── README.md
├── pyproject.toml
├── server_patient_records.py   # MCP Server 1: patient PII (vault-protected)
├── server_pharmacy.py          # MCP Server 2: drug lookup (plain)
├── agent.py                    # Orchestrating agent (MCP client)
└── gateway.py                  # Privileged gateway — unseals handles for audit
```

## Running

```bash
# Install deps
uv sync

# Run the full demo in one command
uv run python agent.py
```

Or step-by-step (three terminals):

```bash
# Terminal 1 — Patient Records MCP server
uv run python server_patient_records.py

# Terminal 2 — Pharmacy MCP server
uv run python server_pharmacy.py

# Terminal 3 — Agent + Gateway demo
uv run python agent.py
```

## Key Concepts Illustrated

1. **Vault sealing at the data boundary** — PII is sealed the instant it leaves the database; the
   MCP tool never returns raw data.
2. **safe_view for LLM context** — The agent composes its summary from safe_views, never touching
   the underlying PII.
3. **ACL enforcement at unseal** — The gateway, not the agent, holds the principal that can unseal.
   Any other principal attempting to unseal receives `HandleAccessDeniedError`.
4. **VaultCodec (optional)** — `AES256GCMEncryptor` encrypts payloads at rest in the vault so even
   a memory dump of the server process cannot expose raw PII.
5. **Codec pipeline** — `ZlibCompressor → AES256GCMEncryptor` compresses before encrypting.

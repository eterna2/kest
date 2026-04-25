"""
gateway.py — Privileged Gateway: Resolves Opaque Handles for Audit

The gateway is the ONLY principal (besides the server itself) that is
authorised to unseal vault handles.  It calls the patient-records MCP
server's ``resolve_handle`` tool using the gateway SPIFFE identity.

Usage (standalone):

    # First run the demo agent to get handle IDs, or pipe a JSON file:
    uv run python agent.py | tee run.log

    # Or run the gateway directly with a handle ID from a previous seal:
    uv run python gateway.py hdl_<handle_id>

What this module demonstrates:

  1. The gateway is the ONLY process that touches raw PII.
  2. Any other principal (including the agent itself) receives
     ``HandleAccessDeniedError`` when attempting to unseal.
  3. The vault enforces TTL — a handle that has expired raises
     ``HandleExpiredError`` even for authorised principals.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from rich.console import Console
from rich.panel import Panel

console = Console()

# ---------------------------------------------------------------------------
# Principals
# ---------------------------------------------------------------------------

GATEWAY_PRINCIPAL = "spiffe://hospital.internal/services/gateway"
AGENT_PRINCIPAL = "spiffe://hospital.internal/services/agent"
ATTACKER_PRINCIPAL = "spiffe://attacker.example/services/exfil"

# ---------------------------------------------------------------------------
# MCP server params
# ---------------------------------------------------------------------------

_HERE = Path(__file__).parent
_PYTHON = sys.executable

PATIENT_RECORDS_SERVER = StdioServerParameters(
    command=_PYTHON,
    args=[str(_HERE / "server_patient_records.py")],
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def call(session: ClientSession, tool: str, **kwargs: Any) -> str:
    result = await session.call_tool(tool, arguments=kwargs)
    return "\n".join(c.text for c in result.content if hasattr(c, "text"))


# ---------------------------------------------------------------------------
# Gateway operations
# ---------------------------------------------------------------------------


async def resolve(session: ClientSession, handle_id: str, principal: str) -> str:
    """Unseal a handle as ``principal`` and return the raw response text."""
    return await call(
        session,
        "resolve_handle",
        handle_id=handle_id,
        requesting_principal=principal,
    )


async def run_gateway_audit(session: ClientSession, agent_result: dict) -> None:
    """
    Resolve all vault handles from *agent_result* as the gateway principal.

    *agent_result* is the dict returned by ``agent.run_agent()``::

        {
          "patient_handle_id": "hdl_...",
          "prescription_handles": ["hdl_...", ...],
          ...
        }

    After a successful gateway audit, also demonstrates ACL rejection for
    the unprivileged agent principal and an external attacker.
    """
    patient_handle_id: str = agent_result["patient_handle_id"]
    prescription_handles: list[str] = agent_result["prescription_handles"]
    all_handles = [patient_handle_id] + prescription_handles
    await _audit_handles(session, all_handles, patient_handle_id)


async def _audit_handles(
    session: ClientSession,
    handle_ids: list[str],
    acl_demo_handle_id: str,
) -> None:
    """Core audit logic — resolve a list of handles and run the ACL demo."""
    console.rule("[bold magenta]Gateway Audit")
    console.print(
        f"[dim]Gateway principal: [bold]{GATEWAY_PRINCIPAL}[/bold]\n"
        "Resolving opaque handles — raw PII will appear here only.\n"
    )

    for handle_id in handle_ids:
        console.print(f"[yellow]→ Resolving handle: {handle_id}")
        raw = await resolve(session, handle_id, GATEWAY_PRINCIPAL)

        if raw.startswith("ERROR"):
            console.print(Panel(raw, title="[red]Error", border_style="red"))
        else:
            console.print(
                Panel(
                    raw,
                    title=f"[bold green]Raw Data — {handle_id[:20]}…",
                    border_style="green",
                )
            )

    # ------------------------------------------------------------------
    # ACL enforcement demo — agent principal cannot unseal
    # ------------------------------------------------------------------
    console.rule("[bold red]ACL Enforcement: Agent tries to unseal")
    console.print(
        f"[dim]The agent principal ([bold]{AGENT_PRINCIPAL}[/bold]) "
        "was NOT granted unseal access.\n"
    )
    denied_agent = await resolve(session, acl_demo_handle_id, AGENT_PRINCIPAL)
    console.print(
        Panel(denied_agent, title="[bold red]Agent → Access Denied", border_style="red")
    )

    # ------------------------------------------------------------------
    # Attacker — not even close
    # ------------------------------------------------------------------
    console.rule("[bold red]ACL Enforcement: External attacker")
    denied_attacker = await resolve(session, acl_demo_handle_id, ATTACKER_PRINCIPAL)
    console.print(
        Panel(
            denied_attacker,
            title="[bold red]Attacker → Access Denied",
            border_style="red",
        )
    )

    console.rule()
    console.print("[bold green]✓ Gateway audit complete.")


# ---------------------------------------------------------------------------
# Standalone entrypoint
# ---------------------------------------------------------------------------


async def main(handle_ids: list[str]) -> None:
    console.print(
        Panel.fit(
            "[bold magenta]Kest Vault Gateway[/bold magenta]\n"
            "[dim]Privileged handle resolution with ACL enforcement[/dim]\n\n"
            f"Principal: [bold]{GATEWAY_PRINCIPAL}[/bold]\n"
            f"Handles to resolve: {len(handle_ids)}",
            border_style="magenta",
        )
    )

    if not handle_ids:
        console.print(
            "[yellow]No handle IDs provided.\n"
            "[dim]Usage:  uv run python gateway.py hdl_<id> [hdl_<id> ...]\n\n"
            "Alternatively, import and call run_gateway_audit() from agent.py."
        )
        return

    async with stdio_client(PATIENT_RECORDS_SERVER) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            # Standalone: treat first handle as the ACL demo handle
            await _audit_handles(session, handle_ids, handle_ids[0])


if __name__ == "__main__":
    _handle_ids = sys.argv[1:]
    asyncio.run(main(_handle_ids))

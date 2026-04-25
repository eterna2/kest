"""
agent.py — Medical Records Agent (MCP client + gateway)

Demonstrates the HandleVault + OpaqueHandle zero-trust pattern:

  - The agent calls the patient-records MCP server and receives only opaque
    handles (PII never touches the agent process).
  - The agent calls the pharmacy MCP server to enrich with drug info.
  - The agent composes its treatment summary using only safe_views.
  - A privileged gateway then resolves the handles to access the raw PII for
    the final audit log.

Run:
    uv run python agent.py
"""

from __future__ import annotations

import asyncio
import re
import sys
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table

console = Console()

# ---------------------------------------------------------------------------
# MCP server paths
# ---------------------------------------------------------------------------

_HERE = Path(__file__).parent
_PYTHON = sys.executable  # reuse the current venv interpreter

PATIENT_RECORDS_SERVER = StdioServerParameters(
    command=_PYTHON,
    args=[str(_HERE / "server_patient_records.py")],
)

PHARMACY_SERVER = StdioServerParameters(
    command=_PYTHON,
    args=[str(_HERE / "server_pharmacy.py")],
)

# ---------------------------------------------------------------------------
# Principals
# ---------------------------------------------------------------------------

AGENT_PRINCIPAL = "spiffe://hospital.internal/services/agent"
GATEWAY_PRINCIPAL = "spiffe://hospital.internal/services/gateway"
ATTACKER_PRINCIPAL = "spiffe://attacker.example/services/exfil"


# ---------------------------------------------------------------------------
# Helper: call a single tool and return the text result
# ---------------------------------------------------------------------------


async def call(session: ClientSession, tool: str, **kwargs: Any) -> str:
    result = await session.call_tool(tool, arguments=kwargs)
    return "\n".join(c.text for c in result.content if hasattr(c, "text"))


# ---------------------------------------------------------------------------
# Agent logic — builds a treatment plan using only safe_views
# ---------------------------------------------------------------------------


async def run_agent(
    patient_session: ClientSession,
    pharmacy_session: ClientSession,
    patient_id: str,
) -> dict:
    """
    Return a dict containing:
      - patient_handle_id: opaque handle for the patient record
      - patient_safe_view: non-sensitive summary used in the report
      - prescription_handles: list of opaque handles for each prescription
      - prescription_safe_views: non-sensitive descriptions
      - drug_details: pharmacological info (non-sensitive, from pharmacy MCP)
      - interaction_warnings: interaction check results
      - allergy_warnings: allergy-contraindication check results
    """
    console.rule(f"[bold cyan]Agent: processing patient {patient_id}")

    # ------------------------------------------------------------------
    # Step 1: Fetch patient record — receives only handle + safe_view
    # ------------------------------------------------------------------
    console.print(f"\n[yellow]→ Calling patient-records MCP: lookup_patient('{patient_id}')")
    patient_raw = await call(patient_session, "lookup_patient", patient_id=patient_id)

    # Parse the returned handle_id and safe_view from the text response
    patient_handle_id = _parse_field(patient_raw, "handle_id")
    patient_safe_view = _parse_field(patient_raw, "safe_view")

    console.print(f"[green]  ✓ handle_id  : {patient_handle_id}")
    console.print(f"[green]  ✓ safe_view  : {patient_safe_view}")
    console.print("[dim]  (raw PII sealed in vault — agent never received it)")

    # ------------------------------------------------------------------
    # Step 2: Fetch prescriptions — each is a separate vault handle
    # ------------------------------------------------------------------
    console.print(f"\n[yellow]→ Calling patient-records MCP: list_patient_prescriptions('{patient_id}')")
    prescriptions_raw = await call(patient_session, "list_patient_prescriptions", patient_id=patient_id)

    # Each prescription block is separated by "---"
    blocks = [b.strip() for b in prescriptions_raw.split("---") if b.strip()]
    prescription_handles = []
    prescription_safe_views = []
    drug_names = []

    for block in blocks:
        hdl = _parse_field(block, "handle_id")
        sv = _parse_field(block, "safe_view")
        prescription_handles.append(hdl)
        prescription_safe_views.append(sv)
        drug_names.append(_extract_drug_name(sv))

    console.print(f"[green]  ✓ {len(prescription_handles)} prescription handles sealed")
    for sv in prescription_safe_views:
        console.print(f"[green]    · {sv}")

    # ------------------------------------------------------------------
    # Step 3: Drug info + interactions from pharmacy MCP (non-sensitive)
    # ------------------------------------------------------------------
    console.print("\n[yellow]→ Calling pharmacy MCP: drug info + interaction checks")
    drug_details = {}
    for drug in drug_names:
        info = await call(pharmacy_session, "get_drug_info", drug_name=drug)
        drug_details[drug] = info
        console.print(f"[green]  ✓ Drug info for '{drug}' received")

    interaction_warnings = []
    allergy_warnings = []

    # Check interactions between all prescription pairs
    for i, a in enumerate(drug_names):
        for b in drug_names[i + 1 :]:
            result = await call(pharmacy_session, "check_interactions", drug_a=a, drug_b=b)
            interaction_warnings.append(result)

    # Extract allergies from safe_view (non-sensitive, already in the summary)
    allergies = _extract_allergies(patient_safe_view)
    console.print(f"\n[yellow]→ Checking allergy contraindications for: {allergies}")
    for drug in drug_names:
        if allergies:
            warn = await call(
                pharmacy_session,
                "get_allergy_contraindications",
                drug_name=drug,
                allergies=allergies,
            )
            if "CAUTION" in warn:
                allergy_warnings.append(warn)
                console.print(f"[red bold]  ⚠ {warn}")
            else:
                console.print(f"[green]  ✓ No allergy issue for '{drug}'")

    return {
        "patient_id": patient_id,
        "patient_handle_id": patient_handle_id,
        "patient_safe_view": patient_safe_view,
        "prescription_handles": prescription_handles,
        "prescription_safe_views": prescription_safe_views,
        "drug_names": drug_names,
        "drug_details": drug_details,
        "interaction_warnings": interaction_warnings,
        "allergy_warnings": allergy_warnings,
    }


# ---------------------------------------------------------------------------
# Gateway — privileged principal that resolves handles for audit
# ---------------------------------------------------------------------------


async def run_gateway_audit(patient_session: ClientSession, agent_result: dict) -> None:
    console.rule("[bold magenta]Gateway Audit — resolving sealed handles")
    console.print(
        "[dim]The gateway holds the privileged principal identity. "
        "It now resolves the opaque handles to access raw PII for the audit log.\n"
    )

    # Resolve the patient handle
    console.print(f"[yellow]→ Resolving patient handle: {agent_result['patient_handle_id']}")
    raw_patient = await call(
        patient_session,
        "resolve_handle",
        handle_id=agent_result["patient_handle_id"],
        requesting_principal=GATEWAY_PRINCIPAL,
    )
    console.print(Panel(raw_patient, title="[bold green]Raw Patient Record (gateway only)", border_style="green"))

    # Resolve prescription handles
    for i, hdl in enumerate(agent_result["prescription_handles"], start=1):
        console.print(f"[yellow]→ Resolving prescription handle #{i}: {hdl}")
        raw_rx = await call(
            patient_session,
            "resolve_handle",
            handle_id=hdl,
            requesting_principal=GATEWAY_PRINCIPAL,
        )
        console.print(f"[green]  ✓ Rx #{i}: {raw_rx}")

    # Demonstrate ACL enforcement — attacker cannot unseal
    console.rule("[bold red]ACL Enforcement Demo")
    console.print(f"[yellow]→ Attacker ({ATTACKER_PRINCIPAL}) attempts to resolve handle…")
    denied = await call(
        patient_session,
        "resolve_handle",
        handle_id=agent_result["patient_handle_id"],
        requesting_principal=ATTACKER_PRINCIPAL,
    )
    console.print(Panel(denied, title="[bold red]Attacker Response (access denied)", border_style="red"))


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------


def _render_agent_report(result: dict) -> None:
    console.rule("[bold blue]Agent Treatment Summary Report")
    console.print(
        Panel(
            f"[bold]Patient:[/bold] {result['patient_id']}\n"
            f"[bold]Handle:[/bold] {result['patient_handle_id']}\n\n"
            f"[bold]Clinical Summary (safe_view):[/bold]\n{result['patient_safe_view']}\n\n"
            "[dim]⚠ Raw PII (name, SSN, DOB) is NOT present in this report.\n"
            "  The agent operated entirely on safe_views and non-sensitive drug data.",
            title="Treatment Plan Summary",
            border_style="blue",
        )
    )

    # Prescription table
    table = Table(title="Active Prescriptions (Opaque Handles)", show_lines=True)
    table.add_column("Handle ID", style="dim", max_width=20, overflow="fold")
    table.add_column("Safe View", style="white")
    for hdl, sv in zip(result["prescription_handles"], result["prescription_safe_views"]):
        table.add_row(hdl, sv)
    console.print(table)

    # Interaction warnings
    if result["interaction_warnings"]:
        console.print("\n[bold yellow]Drug Interaction Checks:")
        for w in result["interaction_warnings"]:
            console.print(f"  • {w}")

    # Allergy warnings
    if result["allergy_warnings"]:
        console.print("\n[bold red]Allergy Contraindication Warnings:")
        for w in result["allergy_warnings"]:
            console.print(f"  ⚠ {w}")
    else:
        console.print("\n[green]✓ No allergy-based contraindications detected.")


# ---------------------------------------------------------------------------
# Text parsing helpers
# ---------------------------------------------------------------------------


def _parse_field(text: str, field: str) -> str:
    """Extract 'field: value' from multi-line text."""
    for line in text.splitlines():
        if line.startswith(f"{field}:"):
            return line[len(field) + 1 :].strip()
    return ""


def _extract_drug_name(safe_view: str) -> str:
    """Extract the first drug name mentioned in a prescription safe_view."""
    m = re.search(r"Prescription #\d+ for \S+: (\S+)", safe_view)
    return m.group(1).lower() if m else safe_view.split()[0].lower()


def _extract_allergies(patient_safe_view: str) -> list[str]:
    """Extract known allergies from patient safe_view string."""
    m = re.search(r"Known allergies: ([^.]+)\.", patient_safe_view)
    if not m or m.group(1).strip().lower() == "none":
        return []
    return [a.strip() for a in m.group(1).split(",")]


# ---------------------------------------------------------------------------
# Main entrypoint
# ---------------------------------------------------------------------------


async def main() -> None:
    console.print(
        Panel.fit(
            "[bold cyan]Kest Vault Showcase[/bold cyan]\n"
            "[dim]HandleVault + OpaqueHandle — Medical Records Agent[/dim]\n\n"
            "This demo shows how sensitive PII (name, SSN, DOB, diagnosis)\n"
            "is sealed into a HandleVault at the data boundary. The agent\n"
            "operates on opaque handles and non-sensitive safe_views only.\n"
            "A privileged gateway resolves the handles for audit.",
            border_style="cyan",
        )
    )

    async with stdio_client(PATIENT_RECORDS_SERVER) as (pr_read, pr_write):
        async with ClientSession(pr_read, pr_write) as patient_session:
            await patient_session.initialize()

            async with stdio_client(PHARMACY_SERVER) as (ph_read, ph_write):
                async with ClientSession(ph_read, ph_write) as pharmacy_session:
                    await pharmacy_session.initialize()

                    # Run agent for two patients
                    for patient_id in ("P-001", "P-002"):
                        result = await run_agent(patient_session, pharmacy_session, patient_id)
                        _render_agent_report(result)
                        console.print()
                        await run_gateway_audit(patient_session, result)
                        console.print(Rule())

    console.print("\n[bold green]✓ Showcase complete.")
    console.print(
        "[dim]Throughout the demo the agent never accessed any PII directly.\n"
        "All sensitive data was sealed in the vault and only resolved by\n"
        "the gateway principal with explicit ACL authorisation."
    )


if __name__ == "__main__":
    asyncio.run(main())

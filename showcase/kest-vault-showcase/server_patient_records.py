"""
server_patient_records.py — MCP Server: Patient Records (Vault-Protected)

This MCP server simulates a hospital patient-records system. All patient PII
(name, SSN, date of birth, diagnosis) is sealed into a HandleVault before
being returned to the caller.

The MCP tools return only:
  - handle.id        (opaque pointer, safe to pass between agents)
  - handle.safe_view (non-sensitive description, safe for LLM context)

The raw PII never leaves this server process.  The vault is encrypted at rest
using AES-256-GCM, so even an in-memory inspection of the vault cache would
not expose plaintext PII.

Tools exposed:
  - lookup_patient(patient_id)     -> {handle_id, safe_view}
  - list_patient_prescriptions(patient_id) -> [{handle_id, safe_view}, ...]
  - get_safe_view(handle_id)       -> str  (ACL-free, non-sensitive)
  - resolve_handle(handle_id, requesting_principal) -> dict  (privileged!)
"""

from __future__ import annotations

import os

import mcp.server.stdio
import mcp.types as types
from mcp.server import Server

from kest.core import (
    AES256GCMEncryptor,
    HandleVault,
    VaultCodec,
    ZlibCompressor,
)
from kest.core.vault.errors import (
    HandleAccessDeniedError,
    HandleExpiredError,
    HandleNotFoundError,
)

# ---------------------------------------------------------------------------
# Vault setup — AES-256-GCM encryption + zlib compression at rest.
# In production this key would come from KMS / HashiCorp Vault / AWS Secrets.
# ---------------------------------------------------------------------------

_VAULT_KEY = os.environ.get("VAULT_KEY", "").encode() or os.urandom(32)

vault = HandleVault(
    codec=VaultCodec(
        compressor=ZlibCompressor(),
        encryptor=AES256GCMEncryptor(_VAULT_KEY),
    )
)

# The principal identity of this server process.  In production this would be
# a SPIFFE SVID attested by SPIRE.
SERVER_PRINCIPAL = "spiffe://hospital.internal/services/patient-records"

# The gateway principal that is authorised to unseal handles for audit.
GATEWAY_PRINCIPAL = "spiffe://hospital.internal/services/gateway"

# ---------------------------------------------------------------------------
# Simulated patient database (no real DB — keeps the showcase self-contained)
# ---------------------------------------------------------------------------

_PATIENTS: dict[str, dict] = {
    "P-001": {
        "name": "Alice Johnson",
        "dob": "1985-03-12",
        "ssn": "123-45-6789",
        "blood_type": "A+",
        "diagnosis": "Type 2 Diabetes, Hypertension",
        "allergies": ["penicillin", "sulfonamides"],
        "primary_physician": "Dr. Chen",
    },
    "P-002": {
        "name": "Bob Martinez",
        "dob": "1972-11-08",
        "ssn": "987-65-4321",
        "blood_type": "O-",
        "diagnosis": "Chronic Kidney Disease Stage 3",
        "allergies": ["aspirin"],
        "primary_physician": "Dr. Patel",
    },
    "P-003": {
        "name": "Carol Smith",
        "dob": "1990-07-25",
        "ssn": "555-12-3456",
        "blood_type": "B+",
        "diagnosis": "Asthma, Seasonal Allergies",
        "allergies": [],
        "primary_physician": "Dr. Rivera",
    },
}

_PRESCRIPTIONS: dict[str, list[dict]] = {
    "P-001": [
        {"drug": "metformin", "dose": "500mg", "frequency": "twice daily", "prescriber": "Dr. Chen"},
        {"drug": "lisinopril", "dose": "10mg", "frequency": "once daily", "prescriber": "Dr. Chen"},
    ],
    "P-002": [
        {"drug": "amlodipine", "dose": "5mg", "frequency": "once daily", "prescriber": "Dr. Patel"},
        {"drug": "epoetin alfa", "dose": "4000 IU", "frequency": "three times weekly", "prescriber": "Dr. Patel"},
    ],
    "P-003": [
        {"drug": "albuterol", "dose": "90mcg", "frequency": "as needed", "prescriber": "Dr. Rivera"},
        {"drug": "fluticasone", "dose": "110mcg", "frequency": "twice daily", "prescriber": "Dr. Rivera"},
    ],
}

# ---------------------------------------------------------------------------
# MCP server
# ---------------------------------------------------------------------------

app = Server("patient-records-mcp")


@app.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="lookup_patient",
            description=(
                "Look up a patient record by ID. Returns an opaque handle — the handle ID and "
                "a non-sensitive safe_view description. The raw PII (name, SSN, DOB, diagnosis) "
                "is sealed in a vault and never returned to the caller."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "patient_id": {
                        "type": "string",
                        "description": "Patient identifier (e.g. 'P-001')",
                    }
                },
                "required": ["patient_id"],
            },
        ),
        types.Tool(
            name="list_patient_prescriptions",
            description=(
                "List all active prescriptions for a patient. Each prescription is sealed "
                "as a separate vault handle; only safe_views are returned."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "patient_id": {
                        "type": "string",
                        "description": "Patient identifier",
                    }
                },
                "required": ["patient_id"],
            },
        ),
        types.Tool(
            name="get_safe_view",
            description=(
                "Return the non-sensitive safe_view string for a handle. "
                "No ACL check — safe_views are intentionally non-sensitive."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "handle_id": {"type": "string", "description": "Opaque handle ID (hdl_...)"}
                },
                "required": ["handle_id"],
            },
        ),
        types.Tool(
            name="resolve_handle",
            description=(
                "PRIVILEGED: Unseal a vault handle and return the raw data. "
                "Only the gateway principal may call this. Attempting to resolve "
                "with an unauthorised principal raises an access-denied error."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "handle_id": {"type": "string", "description": "Opaque handle ID"},
                    "requesting_principal": {
                        "type": "string",
                        "description": "SPIFFE ID of the caller requesting resolution",
                    },
                },
                "required": ["handle_id", "requesting_principal"],
            },
        ),
    ]


@app.call_tool()
async def call_tool(
    name: str, arguments: dict
) -> list[types.TextContent]:
    if name == "lookup_patient":
        patient_id = arguments["patient_id"]
        record = _PATIENTS.get(patient_id)
        if record is None:
            return [types.TextContent(type="text", text=f"ERROR: Patient '{patient_id}' not found.")]

        # Seal PII — raw data never leaves the server
        handle = vault.seal(
            data=record,
            owner_principal=SERVER_PRINCIPAL,
            safe_view=(
                f"Patient record for {patient_id}: "
                f"Diagnosis: {record['diagnosis']}. "
                f"Primary physician: {record['primary_physician']}. "
                f"Blood type: {record['blood_type']}. "
                f"Known allergies: {', '.join(record['allergies']) or 'none'}."
            ),
            ttl_seconds=600,
            granted_principals=[GATEWAY_PRINCIPAL],
        )
        return [
            types.TextContent(
                type="text",
                text=(
                    f"handle_id: {handle.id}\n"
                    f"safe_view: {handle.safe_view}"
                ),
            )
        ]

    if name == "list_patient_prescriptions":
        patient_id = arguments["patient_id"]
        prescriptions = _PRESCRIPTIONS.get(patient_id, [])
        if not prescriptions:
            return [types.TextContent(type="text", text=f"No prescriptions found for '{patient_id}'.")]

        results = []
        for i, rx in enumerate(prescriptions, start=1):
            handle = vault.seal(
                data=rx,
                owner_principal=SERVER_PRINCIPAL,
                safe_view=(
                    f"Prescription #{i} for {patient_id}: "
                    f"{rx['drug']} {rx['dose']} {rx['frequency']} "
                    f"(prescribed by {rx['prescriber']})"
                ),
                ttl_seconds=600,
                granted_principals=[GATEWAY_PRINCIPAL],
            )
            results.append(f"handle_id: {handle.id}\nsafe_view: {handle.safe_view}")

        return [types.TextContent(type="text", text="\n---\n".join(results))]

    if name == "get_safe_view":
        handle_id = arguments["handle_id"]
        try:
            return [types.TextContent(type="text", text=vault.get_safe_view(handle_id))]
        except (HandleNotFoundError, HandleExpiredError) as exc:
            return [types.TextContent(type="text", text=f"ERROR: {exc}")]

    if name == "resolve_handle":
        handle_id = arguments["handle_id"]
        requesting_principal = arguments["requesting_principal"]
        try:
            data = vault.unseal(handle_id, requesting_principal=requesting_principal)
            return [types.TextContent(type="text", text=str(data))]
        except HandleNotFoundError as exc:
            return [types.TextContent(type="text", text=f"ERROR (not found): {exc}")]
        except HandleExpiredError as exc:
            return [types.TextContent(type="text", text=f"ERROR (expired): {exc}")]
        except HandleAccessDeniedError as exc:
            return [types.TextContent(type="text", text=f"ERROR (access denied): {exc}")]

    return [types.TextContent(type="text", text=f"ERROR: Unknown tool '{name}'.")]


async def main() -> None:
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options(),
        )


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())

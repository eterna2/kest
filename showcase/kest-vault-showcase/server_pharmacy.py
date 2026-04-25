"""
server_pharmacy.py — MCP Server: Pharmacy Drug Lookup (Non-sensitive)

This MCP server provides drug information and interaction checking.
Data here is NOT sensitive — it is freely returned to the caller.
This server demonstrates the contrast with patient-records-mcp:
non-sensitive data needs no vault protection.

Tools exposed:
  - get_drug_info(drug_name)                  -> dict  (mechanism, class, warnings)
  - check_interactions(drug_a, drug_b)        -> str   (interaction description)
  - get_allergy_contraindications(drug, allergies) -> list[str]
"""

from __future__ import annotations

import mcp.server.stdio
import mcp.types as types
from mcp.server import Server

# ---------------------------------------------------------------------------
# Simulated drug database
# ---------------------------------------------------------------------------

_DRUGS: dict[str, dict] = {
    "metformin": {
        "class": "Biguanide",
        "mechanism": "Decreases hepatic glucose production and increases insulin sensitivity.",
        "common_side_effects": ["nausea", "diarrhea", "abdominal discomfort"],
        "contraindications": ["severe renal impairment (eGFR <30)", "lactic acidosis history"],
        "renal_caution": True,
    },
    "lisinopril": {
        "class": "ACE Inhibitor",
        "mechanism": "Inhibits angiotensin-converting enzyme, reducing vasoconstriction.",
        "common_side_effects": ["dry cough", "hyperkalemia", "angioedema (rare)"],
        "contraindications": ["pregnancy", "bilateral renal artery stenosis"],
        "renal_caution": True,
    },
    "amlodipine": {
        "class": "Calcium Channel Blocker",
        "mechanism": "Inhibits L-type calcium channels, causing vasodilation.",
        "common_side_effects": ["peripheral edema", "flushing", "headache"],
        "contraindications": ["cardiogenic shock", "severe aortic stenosis"],
        "renal_caution": False,
    },
    "epoetin alfa": {
        "class": "Erythropoiesis-Stimulating Agent",
        "mechanism": "Stimulates erythroid progenitor cell differentiation.",
        "common_side_effects": ["hypertension", "thrombosis", "flu-like symptoms"],
        "contraindications": ["uncontrolled hypertension", "pure red cell aplasia"],
        "renal_caution": False,
    },
    "albuterol": {
        "class": "Short-Acting Beta-2 Agonist (SABA)",
        "mechanism": "Selectively activates beta-2 receptors causing bronchodilation.",
        "common_side_effects": ["tachycardia", "tremor", "hypokalemia (high dose)"],
        "contraindications": [],
        "renal_caution": False,
    },
    "fluticasone": {
        "class": "Inhaled Corticosteroid (ICS)",
        "mechanism": "Anti-inflammatory; suppresses cytokine release in airways.",
        "common_side_effects": ["oral candidiasis", "hoarseness"],
        "contraindications": ["untreated fungal infection (systemic)"],
        "renal_caution": False,
    },
}

_INTERACTIONS: dict[tuple[str, str], str] = {
    ("metformin", "lisinopril"): (
        "LOW RISK — ACE inhibitors may improve insulin sensitivity, potentially enhancing "
        "metformin efficacy. Monitor renal function (both are renally cleared)."
    ),
    ("lisinopril", "metformin"): (
        "LOW RISK — ACE inhibitors may improve insulin sensitivity, potentially enhancing "
        "metformin efficacy. Monitor renal function (both are renally cleared)."
    ),
    ("metformin", "amlodipine"): (
        "MINIMAL — No clinically significant pharmacokinetic interaction. "
        "Both well-tolerated in combination for DM + HTN."
    ),
    ("albuterol", "fluticasone"): (
        "BENEFICIAL — Standard asthma step-up therapy. Fluticasone reduces airway "
        "inflammation; albuterol provides rescue bronchodilation. Use together as prescribed."
    ),
    ("fluticasone", "albuterol"): (
        "BENEFICIAL — Standard asthma step-up therapy. Fluticasone reduces airway "
        "inflammation; albuterol provides rescue bronchodilation. Use together as prescribed."
    ),
}

_ALLERGY_CONTRAINDICATIONS: dict[str, list[str]] = {
    "penicillin": [],  # no listed drugs are penicillins
    "sulfonamides": ["metformin"],  # rare cross-reaction reported
    "aspirin": ["aspirin"],  # trivial — aspirin itself
}

# ---------------------------------------------------------------------------
# MCP server
# ---------------------------------------------------------------------------

app = Server("pharmacy-mcp")


@app.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="get_drug_info",
            description=(
                "Return pharmacological information about a drug: mechanism of action, "
                "drug class, common side effects, and contraindications."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "drug_name": {
                        "type": "string",
                        "description": "Generic drug name (lowercase)",
                    }
                },
                "required": ["drug_name"],
            },
        ),
        types.Tool(
            name="check_interactions",
            description="Check for known interactions between two drugs.",
            inputSchema={
                "type": "object",
                "properties": {
                    "drug_a": {"type": "string"},
                    "drug_b": {"type": "string"},
                },
                "required": ["drug_a", "drug_b"],
            },
        ),
        types.Tool(
            name="get_allergy_contraindications",
            description=(
                "Given a drug and a list of known patient allergies, "
                "return any allergy-based contraindications."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "drug_name": {"type": "string"},
                    "allergies": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of known allergies (e.g. ['penicillin'])",
                    },
                },
                "required": ["drug_name", "allergies"],
            },
        ),
    ]


@app.call_tool()
async def call_tool(
    name: str, arguments: dict
) -> list[types.TextContent]:
    if name == "get_drug_info":
        drug = arguments["drug_name"].lower()
        info = _DRUGS.get(drug)
        if info is None:
            return [types.TextContent(type="text", text=f"Drug '{drug}' not found in database.")]
        lines = [
            f"Drug: {drug}",
            f"Class: {info['class']}",
            f"Mechanism: {info['mechanism']}",
            f"Common side effects: {', '.join(info['common_side_effects'])}",
            f"Contraindications: {', '.join(info['contraindications']) or 'none listed'}",
            f"Renal caution required: {'Yes' if info['renal_caution'] else 'No'}",
        ]
        return [types.TextContent(type="text", text="\n".join(lines))]

    if name == "check_interactions":
        a = arguments["drug_a"].lower()
        b = arguments["drug_b"].lower()
        interaction = _INTERACTIONS.get((a, b)) or _INTERACTIONS.get((b, a))
        if interaction is None:
            return [
                types.TextContent(
                    type="text",
                    text=(
                        f"No known interaction data between '{a}' and '{b}'. "
                        f"Consult a clinical pharmacist for definitive guidance."
                    ),
                )
            ]
        return [types.TextContent(type="text", text=f"Interaction ({a} ↔ {b}): {interaction}")]

    if name == "get_allergy_contraindications":
        drug = arguments["drug_name"].lower()
        allergies = [a.lower() for a in arguments.get("allergies", [])]
        warnings = []
        for allergy in allergies:
            contraindicated = _ALLERGY_CONTRAINDICATIONS.get(allergy, [])
            if drug in contraindicated:
                warnings.append(
                    f"CAUTION: Patient allergy to '{allergy}' may contraindicate '{drug}'."
                )
        if not warnings:
            return [
                types.TextContent(
                    type="text",
                    text=f"No allergy-based contraindications found for '{drug}'.",
                )
            ]
        return [types.TextContent(type="text", text="\n".join(warnings))]

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

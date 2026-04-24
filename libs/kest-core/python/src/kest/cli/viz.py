import argparse
import base64
import hashlib
import json
import os
import sqlite3


def parse_spans_from_file(path: str):
    with open(path, "r") as f:
        return json.load(f)


def parse_spans_from_sqlite(path: str):
    data = []
    with sqlite3.connect(path) as conn:
        cursor = conn.execute("SELECT attributes FROM spans")
        for row in cursor:
            data.append({"attributes": json.loads(row[0])})
    return data


def generate_mermaid(spans) -> str:
    """Generate a Mermaid graph from a list of OTel spans or raw JWS signature strings.

    Supports two input formats:
    - Dict spans with an ``attributes`` key (OTel JSON export / SQLite).
    - Raw JWS compact strings (lab fallback file exporter).
    """
    nodes: dict[str, str] = {}
    edges: list[tuple[str, str]] = []

    for span in spans:
        if isinstance(span, str):
            _process_raw_signature(span, nodes, edges)
        elif isinstance(span, dict) and "attributes" in span:
            _process_span_dict(span["attributes"], nodes, edges)

    out = ["graph TD;"]
    for node_id, label in nodes.items():
        out.append(f"    {node_id}[{label}];")
    for parent, child in edges:
        out.append(f"    {parent} --> {child};")

    return "\n".join(out)


def _process_raw_signature(
    sig_str: str,
    nodes: dict[str, str],
    edges: list[tuple[str, str]],
) -> None:
    """Process a raw JWS compact string (header.payload.signature)."""
    try:
        parts = sig_str.split(".")
        if len(parts) < 2:
            return
        payload_b64 = parts[1]
        padding = "=" * (4 - len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + padding).decode())

        # Node ID = SHA-256 of the full signature string (so children can reference us)
        my_hash = hashlib.sha256(sig_str.encode()).hexdigest()

        # Label: extract from labels.principal (e.g. "service/hop1" → "hop1")
        principal = payload.get("labels", {}).get("principal", "")
        label = principal.split("/")[-1] if principal else "Unknown"
        nodes[my_hash] = label

        # Parent: parent_ids[0] per SPEC §5 (sentinel "0" = root)
        parent_ids = payload.get("parent_ids", ["0"])
        parent_hash = parent_ids[0] if parent_ids else "0"
        if parent_hash and parent_hash != "0":
            edges.append((parent_hash, my_hash))

    except Exception:
        pass


def _process_span_dict(
    attrs: dict,
    nodes: dict[str, str],
    edges: list[tuple[str, str]],
) -> None:
    """Process an OTel span's attributes dict."""
    passport_raw = attrs.get("kest.passport", attrs.get("kest_passport", ""))
    # kest.chain_tip holds the SHA-256 of the parent's JWS (spec §8.4)
    parent_hash = attrs.get("kest.chain_tip", attrs.get("kest_chain_tip", ""))
    service_name = attrs.get("service.name", "Unknown Service")

    if not passport_raw:
        return

    try:
        passport = (
            json.loads(passport_raw) if isinstance(passport_raw, str) else passport_raw
        )
        entries = passport.get("entries", [])
        if not entries:
            return

        # Latest entry = the one recorded by this span
        latest = entries[-1]
        # Node ID = last segment of the JWS (the signature tail) for brevity
        sig = latest.split(".")[-1]
        nodes[sig] = service_name

        if parent_hash and parent_hash != "0":
            edges.append((parent_hash, sig))

    except Exception:
        pass


def main():
    parser = argparse.ArgumentParser(description="Kest Lineage Visualizer")
    parser.add_argument("path", help="Path to kest_audit.json or kest_audit.db")
    args = parser.parse_args()

    if not os.path.exists(args.path):
        print(f"Error: File {args.path} not found.")
        exit(1)

    if args.path.endswith(".db") or args.path.endswith(".sqlite"):
        spans = parse_spans_from_sqlite(args.path)
    else:
        spans = parse_spans_from_file(args.path)

    mermaid = generate_mermaid(spans)
    print(mermaid)


if __name__ == "__main__":
    main()

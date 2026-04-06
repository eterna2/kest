import argparse
import json
import sqlite3
import os
import base64


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
    nodes = {}
    edges = []

    for span in spans:
        if isinstance(span, dict) and "attributes" in span:
            attrs = span.get("attributes", {})
        elif isinstance(span, dict):
            # Try to handle flat JSON list of strings (if fallback file exporter just dumped raw passports)
            pass
        else:
            attrs = getattr(span, "attributes", {})

        if isinstance(span, str):
            # It's just a raw signature string from the basic file exporter fallback
            passport_raw = None
            parent_hash = None
            # The test actually dumps a flat list of strings into lab_audit.json
            entries = spans

            # Since the fallback lab just dumps raw string signatures directly:
            latest = span
            sig = latest.split(".")[-1]
            # Try to extract parent hash from the payload if possible
            try:
                parts = span.split(".")
                if len(parts) >= 2:
                    # JWT payload is the 2nd part (index 1)
                    payload_b64 = parts[1]
                    padding = "=" * (4 - len(payload_b64) % 4)
                    payload = json.loads(
                        base64.urlsafe_b64decode(payload_b64 + padding).decode()
                    )
                    parent_hashes = payload.get("parent_entry_ids", ["0"])
                    parent_hash = parent_hashes[0] if parent_hashes else "0"

                    import hashlib

                    # The parent_hash stored is the sha256 of the parent's full signature string.
                    # So our node ID should be the sha256 of our OWN signature string so children can link to us.
                    my_hash = hashlib.sha256(span.encode()).hexdigest()

                    workload = payload.get("labels", {}).get("workload_id", "Unknown")
                    nodes[my_hash] = workload.split("/")[-1]

                    if parent_hash and parent_hash != "0":
                        edges.append((parent_hash, my_hash))
            except Exception as e:
                nodes[sig] = f"Unknown: {e}"
            continue

        # Look for kest.passport or kest.lineage_root
        passport_raw = attrs.get("kest.passport", attrs.get("kest_passport", ""))
        parent_hash = attrs.get("kest.lineage_root", attrs.get("kest_lineage_root", ""))

        if not passport_raw and not parent_hash:
            continue

        try:
            if passport_raw:
                if isinstance(passport_raw, str):
                    passport = json.loads(passport_raw)
                else:
                    passport = passport_raw
                entries = passport.get("entries", [])

                # Assume the last entry in the passport is the one for this span
                if entries:
                    latest = entries[-1]
                    sig = latest.split(".")[-1]  # use the signature tail as ID
                    nodes[sig] = attrs.get("service.name", "Unknown Service")

                    if parent_hash and parent_hash != "0":
                        # We don't necessarily have the parent's full sig, just the hash
                        # In the real system, lineage root IS the parent's hash
                        edges.append((parent_hash, sig))
        except Exception:
            pass

    out = ["graph TD;"]

    for k, v in nodes.items():
        out.append(f"    {k}[{v}];")

    for p, c in edges:
        out.append(f"    {p} --> {c};")

    return "\n".join(out)


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

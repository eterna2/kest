import argparse
import json
import os
import sys
from typing import Any, Dict, Optional, Union


def render_passport(
    passport_input: Union[str, Dict[str, Any]],
    output_target: Optional[str] = None,
) -> str:
    """
    Renders a Kest passport DAG as a text-based ASCII tree.

    Args:
        passport_input: A JSON string, a path to a JSON file, or a dict.
        output_target: Optional file to save the ASCII tree. If None, it just prints it.

    Returns:
        A string representing the ASCII tree visualization.
    """
    if isinstance(passport_input, dict):
        data = passport_input
    elif isinstance(passport_input, str):
        try:
            data = json.loads(passport_input)
        except json.JSONDecodeError:
            if os.path.exists(passport_input):
                with open(passport_input, "r") as f:
                    data = json.load(f)
            else:
                raise ValueError(
                    f"Invalid passport input: provided string is neither valid JSON nor a valid file path: {passport_input[:100]}..."
                )
    else:
        raise TypeError(
            "passport_input must be a dict or a string (JSON or file path)."
        )

    history = data.get("history", {})
    if not history:
        return "[Empty Lineage History]"

    # Identify leaf nodes (nodes that are not parents of any other node)
    all_parents = set()
    for entry in history.values():
        all_parents.update(entry.get("parent_entry_ids", []))

    leaf_nodes = [node_id for node_id in history.keys() if node_id not in all_parents]

    # Recursive ascii tree builder
    def build_tree(entry_id: str, prefix: str = "", is_last: bool = True) -> str:
        if entry_id not in history:
            return ""

        entry = history[entry_id]
        node_name = entry.get("node_id", "Unknown")
        taints = entry.get("accumulated_taint", [])

        # Build the current node line
        marker = "└── " if is_last else "├── "
        taint_str = f" [Taints: {', '.join(taints)}]" if taints else " [Safe]"

        tree_str = f"{prefix}{marker}{node_name}{taint_str}\n"

        # Process parents recursively (backwards up the DAG)
        parents = entry.get("parent_entry_ids", [])
        child_prefix = prefix + ("    " if is_last else "│   ")

        for i, parent_id in enumerate(parents):
            tree_str += build_tree(parent_id, child_prefix, i == len(parents) - 1)

        return tree_str

    # Build full tree starting from leaves
    full_tree = "Kest Lineage DAG (Leaf-to-Root):\n"
    for i, leaf_id in enumerate(leaf_nodes):
        full_tree += build_tree(leaf_id, "", i == len(leaf_nodes) - 1)
        if i < len(leaf_nodes) - 1:
            full_tree += "│\n"

    # Save or print
    if output_target:
        with open(output_target, "w") as f:
            f.write(full_tree)
        print(f"Text DAG successfully written to: {output_target}")
    else:
        print(full_tree)

    return full_tree


def main():
    parser = argparse.ArgumentParser(description="Visualize Kest Passport DAG context.")
    parser.add_argument(
        "passport_json", help="Path to the Kest JSON passport file or raw JSON string."
    )
    parser.add_argument(
        "--out",
        default=None,
        help="Optional text file to output the tree visualization.",
    )
    args = parser.parse_args()

    try:
        render_passport(args.passport_json, args.out)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

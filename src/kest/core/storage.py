import json
import time
from abc import ABC, abstractmethod
from typing import Optional

import fsspec

from kest.core.crypto import compute_dag_hash
from kest.core.models import KestEntry, KestNodeType, KestPassport


class PassportStore(ABC):
    """Abstract interface for storing and retrieving Passports from Tier 2/Tier 3 storage."""

    @abstractmethod
    def save(self, passport_id: str, passport: KestPassport) -> str:
        """Saves the passport to storage and returns the URI."""
        pass

    @abstractmethod
    def load(self, passport_id: str) -> Optional[KestPassport]:
        """Loads a passport from storage by ID."""
        pass


class FsspecStore(PassportStore):
    """Tiered storage implementation utilizing fsspec for agnostic filesystem mapping."""

    def __init__(self, base_uri: str):
        self.base_uri = base_uri.rstrip("/")

    def _get_path(self, passport_id: str) -> str:
        return f"{self.base_uri}/{passport_id}.json"

    def save(self, passport_id: str, passport: KestPassport) -> str:
        path = self._get_path(passport_id)
        data = passport.model_dump(mode="json")
        with fsspec.open(path, "w") as f:
            json.dump(data, f)  # type: ignore
        return path

    def load(self, passport_id: str) -> Optional[KestPassport]:
        path = self._get_path(passport_id)
        try:
            with fsspec.open(path, "r") as f:
                data = json.load(f)  # type: ignore
            return KestPassport.model_validate(data)
        except Exception:
            return None


def compact_passport(
    passport: KestPassport, store: PassportStore, max_active_nodes: int = 10
) -> KestPassport:
    """
    Evaluates the lineage length. If the active nodes exceed the threshold,
    the history is persisted to Deep Storage and returned as a single Snapshot node.
    """
    if len(passport.history) <= max_active_nodes:
        return passport

    # Identify terminal nodes (leafs)
    all_parents = {
        p for node in passport.history.values() for p in node.parent_entry_ids
    }
    leaf_nodes = [
        node for node_id, node in passport.history.items() if node_id not in all_parents
    ]

    if not leaf_nodes:
        # Fallback if cyclic or empty
        passport_id = list(passport.history.keys())[-1] if passport.history else "empty"
    else:
        passport_id = leaf_nodes[0].entry_id

    # Append to Deep Storage
    tier3_uri = store.save(passport_id, passport)

    # Calculate Merkle root hash linking the previous leaf nodes
    root_hash = compute_dag_hash(
        [n.entry_id for n in leaf_nodes],
        payload_hash="snapshot_compaction",
        annotations={"compacted_nodes": len(passport.history)},
    )

    # Accumulate the total taints to maintain security integrity post-compaction
    accumulated = set()
    for leaf in leaf_nodes:
        accumulated.update(leaf.accumulated_taint)

    min_trust = min((n.trust_score for n in leaf_nodes), default=1.0)

    snapshot_node = KestEntry(
        parent_entry_ids=[],
        node_id="system.compactor",
        node_type=KestNodeType.SNAPSHOT,
        timestamp_ms=int(time.time() * 1000),
        input_state_hash="",
        content_hash=root_hash,
        environment={"tier3_uri": tier3_uri},
        accumulated_taint=sorted(list(accumulated)),
        trust_score=min_trust,
    )

    # Purge the unneeded history
    compacted_passport = passport.model_copy()
    compacted_passport.history = {snapshot_node.entry_id: snapshot_node}

    return compacted_passport

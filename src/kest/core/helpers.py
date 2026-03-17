import time
import uuid
from typing import Dict, List, Optional, TypeVar

from kest.core.models import (
    KestData,
    KestEntry,
    KestPassport,
    PassportOrigin,
    PassportOriginPolicies,
)

T = TypeVar("T")


def originate(
    data: T,
    user_id: str = "anonymous",
    session_id: str = "local",
    policy_refs: Optional[List[str]] = None,
    taint: Optional[List[str]] = None,
    labels: Optional[Dict[str, str]] = None,
    trust_score: float = 1.0,
) -> KestData[T]:
    """
    Wraps raw data in a KestData struct and initializes the Passport DAG lineage.
    Designed for trust boundaries where data enters the tracked system.
    Creates a genesis node in the DAG to carry initial taints and labels.
    """
    origin = PassportOrigin(
        user_id=user_id,
        session_id=session_id,
        policies=PassportOriginPolicies(curated_refs=policy_refs or []),
    )
    passport = KestPassport(origin=origin, signature="", public_key_id="")

    # Create a genesis entry
    entry_id = str(uuid.uuid4())
    initial_taint = taint or []
    entry = KestEntry(
        entry_id=entry_id,
        parent_entry_ids=[],
        node_id="originate",
        timestamp_ms=int(time.time() * 1000),
        input_state_hash="genesis",
        content_hash="genesis",
        environment={},
        labels=labels or {},
        added_taint=initial_taint.copy(),
        accumulated_taint=initial_taint.copy(),
        trust_score=trust_score,
    )
    passport.history[entry_id] = entry

    return KestData(data=data, passport=passport)

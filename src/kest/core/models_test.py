import pytest
from pydantic import ValidationError

from kest.core.models import (
    KestEntry,
    KestNodeType,
    KestPassport,
    PassportOrigin,
    PassportOriginPolicies,
)


def test_kest_entry_serialization():
    """Verify that a KestEntry valid model builds and serializes correctly."""
    entry = KestEntry(
        entry_id="test-uuid",
        parent_entry_ids=["parent-1", "parent-2"],
        node_id="agent:worker-1",
        timestamp_ms=1710685938000,
        input_state_hash="a1b2",
        content_hash="e5f6",
        environment={"python_version": "3.11"},
        labels={"pii": "true"},
        added_taint=["user_input"],
        accumulated_taint=["user_input", "external_api"],
        node_type=KestNodeType.CRITIC,
        cognition={"confidence_score": 0.85},
    )
    data = entry.model_dump(mode="json")

    assert data["entry_id"] == "test-uuid"
    assert data["timestamp_ms"] == 1710685938000
    assert data["accumulated_taint"] == ["user_input", "external_api"]
    assert data["node_type"] == KestNodeType.CRITIC.value
    assert data["cognition"]["confidence_score"] == 0.85


def test_kest_entry_validation_failure():
    """Ensure KestEntry strictly enforces its schema requirements."""
    with pytest.raises(ValidationError):
        # Missing required fields like timestamp_ms and content_hash
        KestEntry(entry_id="test-uuid")  # type: ignore


def test_kest_passport_build():
    """Verify KestPassport aggregates history and origin correctly."""
    entry = KestEntry(
        entry_id="node-1",
        parent_entry_ids=[],
        node_id="root",
        timestamp_ms=1000,
        input_state_hash="hash_a",
        content_hash="hash_b",
        environment={},
        labels={},
        added_taint=[],
        accumulated_taint=[],
    )

    origin = PassportOrigin(
        user_id="user-456",
        session_id="sess-789",
        policies=PassportOriginPolicies(curated_refs=["policy://strict"]),
    )

    passport = KestPassport(
        origin=origin,
        history={"node-1": entry},
    )

    dump = passport.model_dump(mode="json")
    assert dump["history"]["node-1"]["node_id"] == "root"
    assert dump["origin"]["policies"]["curated_refs"] == ["policy://strict"]

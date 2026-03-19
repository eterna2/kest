from kest.core.models import (
    KestEntry,
    KestNodeType,
    KestPassport,
    PassportOrigin,
    PassportOriginPolicies,
)
from kest.core.storage import FsspecStore, compact_passport


def test_fsspec_store_save_and_load(tmp_path):
    """Verifies that the FsspecStore can save and hydrate a KestPassport correctly."""
    store = FsspecStore(base_uri=f"file://{tmp_path}")

    passport = KestPassport(
        origin=PassportOrigin(
            user_id="test_user",
            session_id="session_1",
            policies=PassportOriginPolicies(),
        ),
        history={},
    )

    pid = "test_passport_123"
    uri = store.save(pid, passport)

    assert uri == f"file://{tmp_path}/{pid}.json"

    loaded = store.load(pid)
    assert loaded is not None
    assert loaded.origin.user_id == "test_user"


def test_fsspec_store_load_missing(tmp_path):
    store = FsspecStore(base_uri=str(tmp_path))
    assert store.load("does_not_exist") is None


def test_compact_passport_under_limit(tmp_path):
    store = FsspecStore(base_uri=str(tmp_path))
    passport = KestPassport(
        origin=PassportOrigin(
            user_id="test", session_id="test", policies=PassportOriginPolicies()
        ),
        history={},
    )

    # 5 nodes < limit of 10
    for i in range(5):
        entry = KestEntry(
            node_id=f"node-{i}",
            timestamp_ms=1000,
            input_state_hash="",
            content_hash="",
            accumulated_taint=[],
        )
        passport.history[entry.entry_id] = entry

    compacted = compact_passport(passport, store, max_active_nodes=10)

    # Since it's under the limit, histories should be strictly identical
    assert len(compacted.history) == 5
    assert compacted is passport


def test_compact_passport_over_limit(tmp_path):
    store = FsspecStore(base_uri=str(tmp_path))
    passport = KestPassport(
        origin=PassportOrigin(
            user_id="test", session_id="test", policies=PassportOriginPolicies()
        ),
        history={},
    )

    # Generate 15 nodes > limit of 10
    parent_id = None
    for i in range(15):
        entry = KestEntry(
            parent_entry_ids=[parent_id] if parent_id else [],
            node_id=f"node-{i}",
            timestamp_ms=1000,
            input_state_hash="",
            content_hash="",
            accumulated_taint=["pii"] if i >= 5 else [],
            trust_score=0.9 if i == 14 else 1.0,
        )
        passport.history[entry.entry_id] = entry
        parent_id = entry.entry_id

    compacted = compact_passport(passport, store, max_active_nodes=10)

    # Must be compacted
    assert len(compacted.history) == 1

    snapshot_node = list(compacted.history.values())[0]

    # Must retain essential trust and security characteristics
    assert snapshot_node.node_type == KestNodeType.SNAPSHOT
    assert snapshot_node.trust_score == 0.9
    assert snapshot_node.accumulated_taint == ["pii"]
    assert "tier3_uri" in snapshot_node.environment

    # Assert Tier 3 backup occurred
    assert parent_id is not None
    hydrated = store.load(parent_id)
    assert hydrated is not None
    assert len(hydrated.history) == 15

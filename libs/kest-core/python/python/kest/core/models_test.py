from kest.core._core import KestEntry


def test_kest_entry_init():
    entry = KestEntry(
        entry_id="uuid", operation="node-1", classification="system", trust_score=100
    )
    assert entry.operation == "node-1"

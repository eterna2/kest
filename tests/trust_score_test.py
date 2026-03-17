import pytest

from kest import config, originate, verified
from kest.core.policy import _HAS_REGORUS, LocalOpaEngine

# Setup the Global Policy Engine for testing
if _HAS_REGORUS:
    config.policy_engine = LocalOpaEngine()
    policy = """
package kest.trust
default allow = false

allow {
    input.trust_score >= 0.5
}
"""
    config.policy_engine.add_policy("trust_access", policy)


@verified()
def process_data(data: dict) -> dict:
    return data


@verified(
    node_trust_score=0.9,
    trust_score_updater=lambda node_score, parent_scores: (
        max([node_score] + parent_scores) + 0.2 if parent_scores else node_score
    ),
)
def upgrade_trust(data: dict) -> dict:
    return data


@verified(enforce_rules=["data.kest.trust.allow"])
def high_trust_sink(data: dict) -> dict:
    return data


@pytest.mark.skipif(not _HAS_REGORUS, reason="lakera-regorus requires Python 3.11")
def test_trust_score_blocks_low_quality():
    # Originate data with a low trust score
    low_trust_data = originate({"content": "suspicious"}, trust_score=0.2)

    # Process it normally, score should propagate as 0.2 (min of parents)
    processed = process_data(low_trust_data)
    assert processed.passport is not None
    leaf_entry_id = list(processed.passport.history.keys())[-1]
    assert processed.passport.history[leaf_entry_id].trust_score == 0.2

    # Attempt to sink it (should fail because 0.2 < 0.5)
    with pytest.raises(
        PermissionError,
        match="Kest Policy Violation: Execution blocked by rule 'data.kest.trust.allow'",
    ):
        high_trust_sink(processed)


@pytest.mark.skipif(not _HAS_REGORUS, reason="lakera-regorus requires Python 3.11")
def test_trust_score_upgrades():
    # Originate data with a low trust score
    low_trust_data = originate({"content": "suspicious"}, trust_score=0.4)

    # Upgrade the trust score
    upgraded = upgrade_trust(low_trust_data)

    # max([0.9, 0.4]) + 0.2 = 1.1
    assert upgraded.passport is not None
    leaf_entry_id = list(upgraded.passport.history.keys())[-1]
    # Use pytest.approx due to float math
    assert upgraded.passport.history[leaf_entry_id].trust_score == pytest.approx(1.1)

    # Attempt to sink it (should succeed because 0.6 >= 0.5)
    result = high_trust_sink(upgraded)
    assert result.data["content"] == "suspicious"


def test_trust_score_default_propagation_multiple_parents():
    # Test min logic without OPA enforcement
    d1 = originate({"a": 1}, trust_score=0.9)
    d2 = originate({"b": 2}, trust_score=0.3)

    @verified(node_trust_score=0.8)
    def merge(a: dict, b: dict) -> dict:
        return {"merged": True}

    res = merge(d1, d2)
    assert res.passport is not None
    leaf_entry_id = list(res.passport.history.keys())[-1]

    # Needs to be min([0.8, 0.9, 0.3]) = 0.3
    assert res.passport.history[leaf_entry_id].trust_score == 0.3

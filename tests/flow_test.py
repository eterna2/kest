import pytest

from kest import config, originate, verified
from kest.core.policy import _HAS_REGORUS, LocalOpaEngine


@pytest.fixture(autouse=True, scope="module")
def setup_policy():
    if _HAS_REGORUS:
        engine = LocalOpaEngine()
        config.policy_engine = engine

        policy = """
package kest.policy
default allow = false

allow {
    not unsafe_mix
}

unsafe_mix {
    has_pii
    has_internet
    not has_stripped
}

has_pii { input.taints[_] == "pii_data" }
has_internet { input.taints[_] == "internet_data" }
has_stripped { input.taints[_] == "pii_stripped" }
"""
        engine.add_policy("data_access", policy)


# Shared Mock verified functions
@verified(added_taint=["internet_data"])
def fetch_from_internet(query: str) -> dict:
    return {"source": "internet", "query": query, "data": "public"}


@verified(added_taint=["pii_stripped"])
def strip_pii(data: dict) -> dict:
    safe_data = data.copy()
    if "social_security" in safe_data:
        safe_data["social_security"] = "***-**-****"
    return safe_data


@verified(enforce_rules=["data.kest.policy.allow"])
def merge_data(packet_a: dict, packet_b: dict) -> dict:
    return {"merged": True, "dataset_a": packet_a, "dataset_b": packet_b}


@pytest.mark.skipif(not _HAS_REGORUS, reason="lakera-regorus requires Python 3.11")
def test_unhappy_path_pii_and_internet_merging_blocked():
    """
    Tests that merging PII data with Internet data natively fails
    due to OPA policy constraints combining multiple tainted DAG lineages.
    """
    # 1. Originate PII directly with taint
    raw_pii = originate(
        {"user": "Alice", "social_security": "123-45-678"},
        user_id="test-user",
        taint=["pii_data"],
    )

    # 2. Fetch Internet Payload from raw untracked string
    internet_payload = fetch_from_internet("weather")

    # 3. Attempt to merge (should fail)
    with pytest.raises(
        PermissionError,
        match="Kest Policy Violation: Execution blocked by rule 'data.kest.policy.allow'",
    ):
        merge_data(raw_pii, internet_payload)


@pytest.mark.skipif(not _HAS_REGORUS, reason="lakera-regorus requires Python 3.11")
def test_happy_path_pii_stripped_and_internet_merging_allowed():
    """
    Tests that tracking PII data through a stripping function validates the operation
    based on appending the `pii_stripped` taint dynamically.
    """
    # 1. Originate PII directly with taint
    raw_pii = originate(
        {"user": "Bob", "social_security": "987-65-432"},
        user_id="test-user",
        taint=["pii_data"],
    )

    # 2. Fetch Internet Payload from raw untracked string
    internet_payload = fetch_from_internet("weather")

    # 3. Strip the PII
    safe_pii = strip_pii(raw_pii)

    # 4. Attempt to merge (should succeed)
    result = merge_data(safe_pii, internet_payload)

    assert result.data["merged"] is True
    assert result.data["dataset_a"]["social_security"] == "***-**-****"
    assert result.data["dataset_b"]["source"] == "internet"

    # 5. Assert Passport Structure correctly aggregated BOTH lineages
    assert result.passport is not None
    leaf_entry_id = list(result.passport.history.keys())[-1]
    leaf_node = result.passport.history[leaf_entry_id]

    # Verify that the final leaf node accumulated all three unique taints during its ingress assessment
    final_taints = set(leaf_node.accumulated_taint)
    assert "pii_data" in final_taints
    assert "internet_data" in final_taints
    assert "pii_stripped" in final_taints

    # Verify parent hashes exist simulating the multi-parent join
    assert len(leaf_node.parent_entry_ids) == 2

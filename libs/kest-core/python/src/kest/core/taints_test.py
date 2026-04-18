"""
Unit tests covering Taint Lifecycle (F-TT-*) constraints.
"""

import base64
import json

from opentelemetry import baggage

from kest.core import MockIdentityProvider, MockPolicyEngine, configure, kest_verified


def test_taint_accumulation_and_removal():
    """
    F-TT-01, F-TT-02: Taints MUST accumulate down the lineage chain and be removable.

    This test executes a 3-hop chain:
    - Hop 1: Adds 'taint_A'
    - Hop 2: Inherits 'taint_A', adds 'taint_B'
    - Hop 3: Inherits 'taint_A' and 'taint_B', removes 'taint_A', adds 'taint_C'

    Asserts that the final entry's 'taints' array correctly reflects this lifecycle sum.
    """
    configure(engine=MockPolicyEngine(), identity=MockIdentityProvider(), clear=True)

    @kest_verified(policy="hop1", added_taints=["taint_A"])
    def hop1():
        return hop2()

    @kest_verified(policy="hop2", added_taints=["taint_B"])
    def hop2():
        return hop3()

    @kest_verified(policy="hop3", removed_taints=["taint_A"], added_taints=["taint_C"])
    def hop3():
        return baggage.get_baggage("kest.passport")

    final_baggage = hop1()
    entries = json.loads(str(final_baggage))
    assert len(entries) == 3

    # helper
    def get_payload(jws):
        parts = jws.split(".")
        return json.loads(
            base64.urlsafe_b64decode(parts[1] + "=" * (4 - len(parts[1]) % 4))
        )

    # Entry 1 matches Hop1
    p1 = get_payload(entries[0])
    assert p1["operation"] == "hop1"
    assert p1["added_taints"] == ["taint_A"]
    assert p1["removed_taints"] == []
    # Currently taints array is [] for root... Wait, the logic in decorators adds it if accumulated_taints else []
    assert set(p1["taints"]) == {"taint_A"}

    # Entry 2 matches Hop2
    p2 = get_payload(entries[1])
    assert p2["operation"] == "hop2"
    assert p2["added_taints"] == ["taint_B"]
    assert set(p2["taints"]) == {"taint_A", "taint_B"}

    # Entry 3 matches Hop3
    p3 = get_payload(entries[2])
    assert p3["operation"] == "hop3"
    assert p3["added_taints"] == ["taint_C"]
    assert p3["removed_taints"] == ["taint_A"]
    assert set(p3["taints"]) == {"taint_B", "taint_C"}

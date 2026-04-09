"""
Tests for Policy Evaluation Deduplication constraint (F-PE-07).
"""

import json
from opentelemetry import baggage
import pytest

from kest.core import kest_verified, configure, PolicyEngine, MockIdentityProvider

class TrackingPolicyEngine(PolicyEngine):
    """
    Mock engine that counts the number of times each policy string is evaluated.
    """
    def __init__(self, allow=True):
        self.allow = allow
        self.evaluations = {}

    def evaluate(self, entry_id, policy_names, context):
        for policy in policy_names:
            self.evaluations[policy] = self.evaluations.get(policy, 0) + 1
        return self.allow

def test_policy_deduplication():
    """
    F-PE-07: The Policy Engine MUST deduplicate policies preventing multiple
    evaluations of the same policy and ensuring strict logical AND logic.
    """
    engine = TrackingPolicyEngine()
    configure(engine=engine, identity=MockIdentityProvider(), clear=True)

    # Provide a policy list with duplicated entries
    policies = ["pol_A", "pol_B", "pol_A", "pol_C", "pol_B"]

    @kest_verified(policy=policies)
    def my_func():
        return baggage.get_baggage("kest.passport")

    passport = my_func()
    
    # Assert deduplication applied on the engine evaluations
    assert engine.evaluations.get("pol_A") == 1
    assert engine.evaluations.get("pol_B") == 1
    assert engine.evaluations.get("pol_C") == 1
    assert len(engine.evaluations) == 3

    # Assert the generated JWS records the deduplicated policies in its policy_context
    entries = json.loads(passport)
    import base64
    parts = entries[0].split(".")
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (4 - len(parts[1]) % 4)))

    assert payload["policy_context"]["function_policies"] == ["pol_A", "pol_B", "pol_C"]

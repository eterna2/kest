"""
Shared test helpers for kest-deepagents tests.

Placing reusable fixtures and engines here avoids duplication across test modules.
"""

import pytest

from kest.core import configure, invalidate_policy_cache, MockPolicyEngine
from kest.core.identity import MockIdentityProvider


class HardcodedRuleEngine(MockPolicyEngine):
    """
    A simple rule-based policy engine with deterministic, hardcoded rules.

    Rules (evaluated in priority order, first match wins):

    1. Any policy name in ``blocked_policies``
       → DENY regardless of trust or caller.
       Use in tests by decorating with a matching policy name.

    2. ``trust_score < min_trust``
       → DENY; the operation's trust is too low for this engine.
       Use in tests by setting ``trust_override`` below the threshold.

    3. All other combinations → ALLOW.

    Args:
        blocked_policies: Set of policy names that are always denied.
                          Defaults to ``{"blocked_policy"}``.
        min_trust:        Minimum trust score required to allow an operation.
                          Defaults to ``50``.
    """

    def __init__(
        self,
        blocked_policies: frozenset[str] = frozenset({"blocked_policy"}),
        min_trust: int = 50,
    ) -> None:
        self.blocked_policies = blocked_policies
        self.min_trust = min_trust

    def evaluate(self, entry_id: str, policy_names: list, context: dict) -> bool:
        # Rule 1: explicitly blocked policy name
        if any(p in self.blocked_policies for p in policy_names):
            return False

        # Rule 2: insufficient trust score
        trust = int(context.get("trust_score", 100))
        if trust < self.min_trust:
            return False

        # Rule 3: allow everything else
        return True


@pytest.fixture(autouse=False)
def kest_env():
    """Provide a clean kest environment for each test."""
    invalidate_policy_cache()
    configure(
        engine=HardcodedRuleEngine(
            blocked_policies=frozenset({"blocked_policy"}),
            min_trust=50,
        ),
        identity=MockIdentityProvider(),
    )
    yield
    configure(clear=True)
    invalidate_policy_cache()

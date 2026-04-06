from typing import List
from kest.core import (
    kest_verified,
    configure,
    MockIdentityProvider,
    MockPolicyEngine,
    TrustEvaluator,
    DefaultTrustEvaluator,
)


def test_default_trust_evaluator_logic():
    evaluator = DefaultTrustEvaluator()

    # 1. Root node (no parents)
    assert evaluator.calculate(80, []) == 80

    # 2. Sequential degradation
    # parent score 90, current node confidence 50 -> 45
    assert evaluator.calculate(50, [90]) == 45

    # 3. Fan-in (pessimistic minimum)
    # parents: 90, 40. current node: 100 -> 40
    assert evaluator.calculate(100, [90, 40]) == 40


class CustomWeightedEvaluator(TrustEvaluator):
    def calculate(self, self_score: int, parent_scores: List[int]) -> int:
        if not parent_scores:
            return self_score
        # Weighted average: 80% parent, 20% self
        avg_parent = sum(parent_scores) // len(parent_scores)
        return (avg_parent * 80 + self_score * 20) // 100


def test_custom_trust_evaluator_injection():
    # Setup
    engine = MockPolicyEngine()
    configure(engine=engine, identity=MockIdentityProvider(), clear=True)

    # Use custom evaluator
    evaluator = CustomWeightedEvaluator()

    @kest_verified(policy="test", trust_evaluator=evaluator, origin="internet")
    def root_node():
        return "root"

    # For a root node, Default/Custom both usually just return self_score
    # based on the origin bootstrap.
    # Note: kest_verified currently uses ORIGIN_TRUST_MAP[origin] as self_score.
    assert root_node() == "root"


def test_trust_propagation_to_policy_engine():
    """
    Verify that the calculated trust score is actually passed to the Policy Engine.
    """

    class ScoreCapturingEngine(MockPolicyEngine):
        def __init__(self):
            super().__init__()
            self.captured_score = None

        def evaluate(self, entry_id, policy_names, context):
            self.captured_score = context.get("trust_score")
            return True

    engine = ScoreCapturingEngine()
    configure(engine=engine, identity=MockIdentityProvider(), clear=True)

    @kest_verified(policy="test", origin="verified_rag")
    def trust_func():
        return "ok"

    trust_func()
    # verified_rag bootstrap score is 0.9 → passed to engine as int (0.9 * 100 = 90)
    assert engine.captured_score == 90

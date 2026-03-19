import asyncio
import json
from typing import Any, Dict

from kest.config import config
from kest.core.helpers import originate
from kest.core.policy import LocalOpaEngine, OpaEngine
from kest.presentation.decorators import kest_verified


class MockWorkaroundEngine(OpaEngine):
    """Local workaround for OPA evaluation when lakera-regorus or OPA server is unavailable."""

    def evaluate(self, payload: Dict[str, Any], rule_path: str) -> bool:
        print(f"   [MockEngine] Evaluating rule: {rule_path}")
        # In a real local workaround, you'd map simple python rules
        if rule_path.endswith("allow"):
            return payload.get("trust_score", 0) >= 0.70
        return False


# Setup the Local OPA Engine
try:
    config.policy_engine = LocalOpaEngine()
    # Simple policy blocking extremely untrusted models
    policy = """
package kest.trust
default allow = false

allow {
    input.trust_score >= 0.70
}
"""
    config.policy_engine.add_policy("trust_access", policy)
except Exception as e:
    print(f"Warning: LocalOpaEngine unavailable ({e}). Using MockWorkaroundEngine.")
    config.policy_engine = MockWorkaroundEngine()


async def run_demo():
    print("==================================================")
    print("Running Advanced Kest v0.3.0 Trust Decay Demo")
    print("==================================================")

    # Define our processing nodes
    @kest_verified(
        node_trust_score=0.9,
    )
    async def fetch_data(source: str) -> dict:
        print(f" -> Fetching raw data from {source}...")
        return {"source": source, "content": "raw_user_data"}

    # Define a clean up node that actually Boosts trust score iteratively
    @kest_verified(
        node_trust_score=0.8,
        trust_score_updater=lambda node, parents: (
            max([node] + parents) + 0.3 if parents else node
        ),
    )
    async def validate_and_clean(data: dict) -> dict:
        print(" -> Cleaning and validating data. Trust score upgrading...")
        cleaned = data.copy()
        cleaned["validated"] = True
        return cleaned

    @kest_verified(enforce_rules=["data.kest.trust.allow"])
    async def generate_report(data: dict) -> dict:
        print(" -> Successfully generated report from high-trust data!")
        return {"report_generated": True, "data": data}

    print("\n--- Scenario 1: Insufficient Trust Blocked ---")
    try:
        raw_data = originate(
            {"source": "website", "content": "raw_user_data"}, trust_score=0.5
        )
        # raw_data has a score of 0.5, which < 0.70. This prevents the report endpoint
        # from ever seeing the data.
        await generate_report(raw_data)
        print(" [!] ERROR: This should have been blocked!")
    except PermissionError as e:
        print(f" -> [BLOCKED] Expected PermissionError: {e}")

    print("\n--- Scenario 2: Validated Trust Upgraded & Allowed ---")
    try:
        raw_data = originate(
            {"source": "website", "content": "raw_user_data"}, trust_score=0.5
        )
        clean_data = await validate_and_clean(raw_data)

        # Current Trust Score should be max(0.8, 0.5) + 0.3 = 1.1!
        report = await generate_report(clean_data)

        assert report.passport is not None
        leaf_id = list(report.passport.history.keys())[-1]
        final_score = report.passport.history[leaf_id].trust_score
        print(f" -> [SUCCESS] Final Report Trust Score: {final_score}")
        print(
            json.dumps(
                report.passport.history[leaf_id].model_dump(mode="json"), indent=2
            )
        )

    except Exception as e:
        print(f"Unexpected Exception: {e}")


if __name__ == "__main__":
    asyncio.run(run_demo())

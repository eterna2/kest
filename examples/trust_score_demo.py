from kest import config, originate, verified
from kest.core.policy import _HAS_REGORUS, LocalOpaEngine


def run_demo():
    if not _HAS_REGORUS:
        print("Skipping demo since `lakera_regorus` is not installed.")
        return

    # Setup the Local OPA Engine
    config.policy_engine = LocalOpaEngine()
    policy = """
package kest.trust
default allow = false

allow {
    input.trust_score >= 0.70
}
"""
    config.policy_engine.add_policy("trust_access", policy)

    # Define our processing nodes
    @verified(
        node_trust_score=0.9,
        trust_score_updater=lambda node, parents: (
            min([node] + parents) if parents else node
        ),
    )
    def fetch_data(source: str) -> dict:
        print(f"-> Fetching raw data from {source}...")
        return {"source": source, "content": "raw_user_data"}

    @verified(
        node_trust_score=0.8,
        trust_score_updater=lambda node, parents: (
            max([node] + parents) + 0.3 if parents else node
        ),
    )
    def validate_and_clean(data: dict) -> dict:
        print("-> Cleaning and validating data. Trust score upgrading...")
        cleaned = data.copy()
        cleaned["validated"] = True
        return cleaned

    @verified(enforce_rules=["data.kest.trust.allow"])
    def generate_report(data: dict) -> dict:
        print(f"-> Successfully generated report from high-trust data: {data}")
        return {"report_generated": True, "data": data}

    print("--- Scenario 1: Insufficient Trust Blocked ---")
    try:
        raw_data = originate(
            {"source": "website", "content": "raw_user_data"}, trust_score=0.5
        )
        # raw_data has a score of 0.5, which < 0.70.
        generate_report(raw_data)
    except PermissionError as e:
        print(f"Expected PermissionError: {e}")

    print("\n--- Scenario 2: Validated Trust Allowed ---")
    try:
        raw_data = originate(
            {"source": "website", "content": "raw_user_data"}, trust_score=0.5
        )
        clean_data = validate_and_clean(raw_data)

        # Current Trust Score should be max(0.8, 0.5) + 0.3 = 1.1
        report = generate_report(clean_data)

        assert report.passport is not None
        leaf_id = list(report.passport.history.keys())[-1]
        final_score = report.passport.history[leaf_id].trust_score
        print(f"Final Trust Score: {final_score}")
    except Exception as e:
        print(f"Unexpected Exception: {e}")


if __name__ == "__main__":
    run_demo()

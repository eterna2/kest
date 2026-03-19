"""
End to end demonstration of Kest v0.3.0 taint propagation and DAG lineage tracking.
Demonstrates async execution, handling sensitive PII, exception tracking,
and applying strict OPA logic to prevent untrusted data crossing.
"""

import asyncio
import json
from typing import Any, Dict

from kest.config import config
from kest.core.crypto import LocalJWKStore, generate_keypair
from kest.core.helpers import originate
from kest.core.policy import LocalOpaEngine, OpaEngine
from kest.presentation.decorators import kest_verified
from kest.presentation.defaults import HostnameCollector, NDJSONExporter


class MockWorkaroundEngine(OpaEngine):
    """Local workaround for OPA evaluation when lakera-regorus or OPA server is unavailable."""

    def evaluate(self, payload: Dict[str, Any], rule_path: str) -> bool:
        print(f"   [MockEngine] Evaluating rule: {rule_path}")
        taints = payload.get("taints", [])
        if rule_path.endswith("allow"):
            has_pii = "pii_data" in taints
            has_internet = "internet_data" in taints
            has_stripped = "pii_stripped" in taints
            unsafe_mix = has_pii and has_internet and not has_stripped
            return not unsafe_mix
        elif rule_path.endswith("allow_strip_pii"):
            return "pii_data" in taints
        return False


# Setup shared dependencies
exporter = NDJSONExporter()
env_collector = HostnameCollector()
priv_key, pub_key = generate_keypair()

# Global DX: Configure the security policy engine for evaluation
try:
    config.policy_engine = LocalOpaEngine()

    # Configure Keys for JWS
    config.signing_key = priv_key
    config.signing_key_id = "demo-key-1"
    config.verification_key = pub_key

    # Mock a Local Key Store
    keystore = LocalJWKStore({"demo-key-1": pub_key})

    policy = """
package kest.policy
default allow = false

# Global allow rule used by merge_data
allow {
    not unsafe_mix
}

# Specific rule for strip_pii: must have pii_data taint as input
allow_strip_pii {
    has_pii
}

# Logic for unsafe mixing
unsafe_mix {
    has_pii
    has_internet
    not has_stripped
}

has_pii { "pii_data" in input.taints }
has_internet { "internet_data" in input.taints }
has_stripped { "pii_stripped" in input.taints }
"""
    config.policy_engine.add_policy("data_access", policy)

except Exception as e:
    print(f"Warning: LocalOpaEngine unavailable ({e}). Using MockWorkaroundEngine.")
    config.policy_engine = MockWorkaroundEngine()

    # Still setup keys for MockWorkaroundEngine testing
    config.signing_key = priv_key
    config.signing_key_id = "demo-key-1"
    config.verification_key = pub_key
    keystore = LocalJWKStore({"demo-key-1": pub_key})


@kest_verified(
    added_taint=["internet_data"],
    env_collectors=[env_collector],
    telemetry_exporters=[exporter],
)
async def fetch_from_internet(query: str) -> dict:
    """Simulates fetching external data concurrently."""
    await asyncio.sleep(0.1)
    return {"source": "internet", "query": query, "data": "public_dataset"}


@kest_verified(
    added_taint=["pii_stripped"],
    env_collectors=[env_collector],
    telemetry_exporters=[exporter],
    enforce_rules=["data.kest.policy.allow_strip_pii"],
)
async def strip_pii(data: dict) -> dict:
    """Simulates stripping sensitive information from a payload."""
    safe_data = data.copy()
    if "social_security" in safe_data:
        safe_data["social_security"] = "***-**-****"
    return safe_data


@kest_verified(
    env_collectors=[env_collector],
    telemetry_exporters=[exporter],
    enforce_rules=["data.kest.policy.allow"],
)
async def merge_data(packet_a: dict, packet_b: dict) -> dict:
    """
    Merges two datasets together.
    Kest automatically aggregates the DAG lineages and taints from BOTH input wrappers
    and evaluates them against the OPA rule before executing this function.
    """
    return {"merged": True, "dataset_a": packet_a, "dataset_b": packet_b}


@kest_verified(
    added_taint=["risky_agent"],
)
async def faulty_process(data: dict) -> dict:
    """Simulates a model hallucination or crash."""
    raise RuntimeError("LLM Inference Crash")


async def run_demo():
    print("==================================================")
    print("Running Advanced Kest v0.3.0 Async Demo Flow")
    print("==================================================")

    # 1. Originate starting points
    raw_pii = originate(
        {"user": "Alice", "social_security": "123-45-678"},
        user_id="system-ingress",
        taint=["pii_data"],
    )

    print("\n[STEP 1] Fetching Data Asynchronously...")
    internet_payload = await fetch_from_internet("weather_stats")
    print(" -> Internet Payload Fetched safely (Taint: internet_data)")

    # ---------------------------------------------------------
    # UNHAPPY PATH: UNSTRIPPED MERGE
    # ---------------------------------------------------------
    print("\n---------------------------------------------------------")
    print("UNHAPPY PATH: Merging RAW PII with Internet Data directly")
    print("---------------------------------------------------------")
    try:
        await merge_data(raw_pii, internet_payload)
        print(" [!] ERROR: This should have been blocked!")
    except PermissionError as e:
        print(f" -> [BLOCKED] Caught Expected Security Exception: {e}")

    # ---------------------------------------------------------
    # EXCEPTION TAINT CATCHING
    # ---------------------------------------------------------
    print("\n---------------------------------------------------------")
    print("FAIL-OPEN EXCEPTION: Catching AI Hallucinations")
    print("---------------------------------------------------------")
    try:
        await faulty_process(internet_payload)
    except RuntimeError:
        print(
            " -> Caught expected LLM crash. Kest implicitly logged the failure taint."
        )

    # ---------------------------------------------------------
    # HAPPY PATH
    # ---------------------------------------------------------
    print("\n---------------------------------------------------------")
    print("HAPPY PATH: Stripping PII before Merging")
    print("---------------------------------------------------------")
    print(" -> Stripping PII...")
    safe_pii = await strip_pii(raw_pii)

    print(" -> Merging Safe PII with Internet Data...")
    final_result = await merge_data(safe_pii, internet_payload)
    print("\n[RESULT] Domain Output (Successfully Merged!):")
    print(final_result.data)

    # ---------------------------------------------------------
    # JWS VERIFICATION & TRACE
    # ---------------------------------------------------------
    print("\n---------------------------------------------------------")
    print("JWS DAG VERIFICATION & TRACE")
    print("---------------------------------------------------------")

    # Normally decoded instantly upon ingress crossing network barriers
    assert final_result.passport is not None
    print(f" -> Leaf Node IDs: {final_result.passport.history.keys()}")

    leaf_entry = list(final_result.passport.history.values())[-1]
    print(f" -> Final Accumulated Taints: {leaf_entry.accumulated_taint}")
    print(" -> Node Event Breakdown:")
    print(json.dumps(leaf_entry.model_dump(mode="json"), indent=2))


if __name__ == "__main__":
    asyncio.run(run_demo())

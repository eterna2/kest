"""
End to end demonstration of Kest taint propagation and DAG lineage tracking.
Demonstrates complex merging of disparate datasets, handling sensitive PII,
and applying strict OPA logic to prevent untrusted data crossing.
"""

from kest import config, originate, verified
from kest.core.crypto import generate_keypair, sign_passport
from kest.core.policy import LocalOpaEngine
from kest.presentation.defaults import HostnameCollector, NDJSONExporter

# Setup shared dependencies
exporter = NDJSONExporter()
env_collector = HostnameCollector()
_priv_key, pub_key = generate_keypair()

# Global DX: Configure the security policy engine for evaluation
config.policy_engine = LocalOpaEngine()

# Our Security Policy:
# 1. Generic allow: You cannot merge 'pii_data' and 'internet_data' unless 'pii_stripped' is present.
# 2. allow_strip_pii: Can only strip if input actually has pii_data taint.
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

# Specific rule: only allow input that came from System A
allow_system_a_only {
    has_system_a
}

# Logic for unsafe mixing
unsafe_mix {
    has_pii
    has_internet
    not has_stripped
}

has_pii { input.taints[_] == "pii_data" }
has_internet { input.taints[_] == "internet_data" }
has_stripped { input.taints[_] == "pii_stripped" }
has_system_a { input.taints[_] == "system_a" }
"""
config.policy_engine.add_policy("data_access", policy)


@verified(
    added_taint=["internet_data"],
    env_collectors=[env_collector],
    telemetry_exporters=[exporter],
)
def fetch_from_internet(query: str) -> dict:
    """Simulates fetching external data."""
    return {"source": "internet", "query": query, "data": "public_dataset"}


@verified(
    added_taint=["pii_stripped"],
    env_collectors=[env_collector],
    telemetry_exporters=[exporter],
    enforce_rules=["data.kest.policy.allow_strip_pii"],
)
def strip_pii(data: dict) -> dict:
    """Simulates stripping sensitive information from a payload."""
    safe_data = data.copy()
    if "social_security" in safe_data:
        safe_data["social_security"] = "***-**-****"
    return safe_data


@verified(
    env_collectors=[env_collector],
    telemetry_exporters=[exporter],
    enforce_rules=["data.kest.policy.allow"],
)
def merge_data(packet_a: dict, packet_b: dict) -> dict:
    """
    Merges two datasets together.
    Kest will automatically aggregate the DAG lineages and taints from BOTH input wrappers
    and evaluate them against the OPA rule before executing this function.
    """
    return {"merged": True, "dataset_a": packet_a, "dataset_b": packet_b}


@verified(
    added_taint=["system_a"],
    env_collectors=[env_collector],
    telemetry_exporters=[exporter],
)
def process_on_system_a(data: dict) -> dict:
    """Simulates processing on a specific approved system."""
    return {"system": "System A", "processed_data": data}


@verified(
    env_collectors=[env_collector],
    telemetry_exporters=[exporter],
    enforce_rules=["data.kest.policy.allow_system_a_only"],
)
def restricted_system_process(data: dict) -> dict:
    """A highly secure function that ONLY accepts data processed by System A."""
    return {"status": "highly_secure", "data": data}


def run_demo():
    print("==================================================")
    print("Running Advanced Kest Demo Flow (PII vs Internet)")
    print("==================================================")

    # 1. Originate starting points
    # Raw PII data entering the system natively tainted via DX helper
    raw_pii = originate(
        {"user": "Alice", "social_security": "123-45-678"},
        user_id="system-ingress",
        taint=["pii_data"],
    )

    print("\n[STEP 1] Fetching Data...")
    internet_payload = fetch_from_internet("weather_stats")
    print(" -> Internet Payload Fetched safely (Taint: internet_data)")

    # ---------------------------------------------------------
    # UNHAPPY PATH
    # ---------------------------------------------------------
    print("\n---------------------------------------------------------")
    print("UNHAPPY PATH: Merging RAW PII with Internet Data directly")
    print("---------------------------------------------------------")
    try:
        # merge_data inherently pulls taints from `raw_pii` and `internet_payload`
        merge_data(raw_pii, internet_payload)
        print(" [!] ERROR: This should have been blocked!")
    except PermissionError as e:
        print(f" -> [BLOCKED] Caught Expected Security Exception: {e}")

    # ---------------------------------------------------------
    # NEW: TAINT REQUIREMENT PATH
    # ---------------------------------------------------------
    print("\n---------------------------------------------------------")
    print("TAINT REQUIREMENT: Stripping PII from clean Internet Data")
    print("---------------------------------------------------------")
    try:
        print(" -> Attempting to strip PII from data that has NO PII taint...")
        # This should fail because allow_strip_pii requires has_pii
        strip_pii(internet_payload)
        print(" [!] ERROR: This should have been blocked (missing PII taint)!")
    except PermissionError as e:
        print(f" -> [BLOCKED] Caught Expected Security Exception: {e}")

    # ---------------------------------------------------------
    # HAPPY PATH
    # ---------------------------------------------------------
    print("\n---------------------------------------------------------")
    print("HAPPY PATH: Stripping PII before Merging")
    print("---------------------------------------------------------")
    print(" -> Stripping PII...")
    safe_pii = strip_pii(raw_pii)

    print(" -> Merging Safe PII with Internet Data...")
    final_result = merge_data(safe_pii, internet_payload)
    print("\n[RESULT] Domain Output (Successfully Merged!):")
    print(final_result.data)

    # ---------------------------------------------------------
    # SYSTEM ORIGIN RESTRICTION EXAMPLES
    # ---------------------------------------------------------
    print("\n---------------------------------------------------------")
    print("SYSTEM RESTRICTION: Rejecting data not from System A")
    print("---------------------------------------------------------")
    try:
        print(" -> Attempting to pass generic internet data to restricted process...")
        restricted_system_process(internet_payload)
        print(" [!] ERROR: This should have been blocked!")
    except PermissionError as e:
        print(f" -> [BLOCKED] Caught Expected Security Exception: {e}")

    print("\n---------------------------------------------------------")
    print("SYSTEM RESTRICTION: Allowing data from System A")
    print("---------------------------------------------------------")
    print(" -> Processing internet data on System A first...")
    system_a_data = process_on_system_a(internet_payload)

    print(" -> Passing System A data to restricted process...")
    secure_result = restricted_system_process(system_a_data)
    print(f" -> [SUCCESS] Secure Process Result: {secure_result.data}")

    # Sign and print lineage visually
    passport = final_result.passport
    if passport:
        final_passport = sign_passport(_priv_key, passport)
        print("\n[FINAL PASSPORT LINEAGE] Execution Path Details:")
        for node, entry in final_passport.history.items():
            print(f"  -> Node: {entry.node_id}")
            print(f"     Accumulated Taint: {entry.accumulated_taint}")
        print(f"  -> Cryptographic Signature: {final_passport.signature[:40]}...")


if __name__ == "__main__":
    run_demo()

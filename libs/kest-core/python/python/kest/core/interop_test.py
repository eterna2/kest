"""
Interoperability tests (F-INTER-*) ensuring cross-language compatibility.
"""

import hashlib
import json

def test_rfc_8785_canonicalization():
    """
    F-INTER-01: Serialized forms MUST be canonicalized using RFC 8785.
    
    This test uses a hardcoded dictionary that represents a strict KestEntry payload
    with nested structures and ensuring it hashes perfectly. If Python's json.dumps
    changes its whitespace or sorting algorithms in the future, this test will break,
    guarding against cross-language deserialization fractures.
    """
    payload = {
        "added_taints": ["taint_a", "taint_b"],
        "classification": "user_input",
        "entry_id": "019d6e05-7ead-7000-952a-cdbb3e7f0c5f",
        "labels": {"foo": "bar", "num": 42},
        "operation": "test_op",
        "parent_ids": ["0", "a8940770792ae81b5a2f629d9edf2d6adcb9a1b489371453459fda3fa1e36c7a"],
        "policy_context": {
            "app_policies": ["app_pol1"],
            "deviations": [
                {
                    "approver": "eterna2",
                    "policy": "strict_mode",
                    "reason": "emergency",
                    "tier": "enterprise"
                }
            ],
            "enterprise_policies": [],
            "function_policies": ["func_pol1", "func_pol2"],
            "platform_policies": []
        },
        "removed_taints": [],
        "runtime": {
            "name": "kest-python",
            "version": "0.3.0"
        },
        "schema_version": "0.3.0",
        "taints": [],
        "trust_score": 50
    }

    # RFC 8785 (JCS) mandates:
    # 1. Lexicographical sorting of keys
    # 2. No extra whitespace after colons or commas
    serialized_str = json.dumps(payload, separators=(',', ':'), sort_keys=True)
    
    # Asserting exactly equal to known good JCS formatted string
    expected_jcs = (
        '{"added_taints":["taint_a","taint_b"],"classification":"user_input",'
        '"entry_id":"019d6e05-7ead-7000-952a-cdbb3e7f0c5f","labels":{"foo":"bar","num":42},'
        '"operation":"test_op","parent_ids":["0","a8940770792ae81b5a2f629d9edf2d6adcb9a1b489371453459fda3fa1e36c7a"],'
        '"policy_context":{"app_policies":["app_pol1"],"deviations":[{"approver":"eterna2",'
        '"policy":"strict_mode","reason":"emergency","tier":"enterprise"}],"enterprise_policies":[],'
        '"function_policies":["func_pol1","func_pol2"],"platform_policies":[]},'
        '"removed_taints":[],"runtime":{"name":"kest-python","version":"0.3.0"},'
        '"schema_version":"0.3.0","taints":[],"trust_score":50}'
    )
    
    assert serialized_str == expected_jcs, "Serialization does not match RFC 8785 canonical format"
    
    # Hash check
    digest = hashlib.sha256(serialized_str.encode("utf-8")).hexdigest()
    assert digest == "939a97e9ea233522cd47c4aa938648d983462dc91a34f82ea1ac00ca00d2c879"
    

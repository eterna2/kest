from pathlib import Path

import pytest
from regopy import Interpreter

from .testing_utils import HAS_CEDAR, HAS_REGOPY, is_allowed, is_cedar_allowed


@pytest.mark.opa
@pytest.mark.skipif(not HAS_REGOPY, reason="regopy not installed")
def test_biba_rego():
    """
    Tests the Biba integrity policy (No Read Down, No Write Up).
    """
    # Load the Rego policy
    policy_path = Path(__file__).parent / "biba.rego"
    with open(policy_path, "r") as f:
        rego_content = f.read()

    rego = Interpreter()
    rego.add_module("biba", rego_content)

    # --- Read Authorization (No Read Down) ---

    # Case 1: Allow - Integrity equals Object Integrity
    rego.set_input(
        {"action": "read", "subject": {"integrity": 2}, "object": {"integrity": 2}}
    )
    res = rego.query("data.kest.advanced.biba.allow")
    assert is_allowed(res) is True

    # Case 2: Allow - Subject integrity LESS than Object integrity
    rego.set_input(
        {"action": "read", "subject": {"integrity": 1}, "object": {"integrity": 2}}
    )
    res = rego.query("data.kest.advanced.biba.allow")
    assert is_allowed(res) is True

    # Case 3: Deny - Subject integrity GREATER than Object integrity (No Read Down)
    rego.set_input(
        {"action": "read", "subject": {"integrity": 3}, "object": {"integrity": 2}}
    )
    res = rego.query("data.kest.advanced.biba.allow")
    assert is_allowed(res) is False

    # --- Write Authorization (No Write Up) ---

    # Case 4: Allow - Integrity equals Object Integrity
    rego.set_input(
        {"action": "write", "subject": {"integrity": 2}, "object": {"integrity": 2}}
    )
    res = rego.query("data.kest.advanced.biba.allow")
    assert is_allowed(res) is True

    # Case 5: Allow - Subject integrity GREATER than Object integrity
    rego.set_input(
        {"action": "write", "subject": {"integrity": 3}, "object": {"integrity": 2}}
    )
    res = rego.query("data.kest.advanced.biba.allow")
    assert is_allowed(res) is True

    # Case 6: Deny - Subject integrity LESS than Object integrity (No Write Up)
    rego.set_input(
        {"action": "write", "subject": {"integrity": 1}, "object": {"integrity": 2}}
    )
    res = rego.query("data.kest.advanced.biba.allow")
    assert is_allowed(res) is False


@pytest.mark.cedar
@pytest.mark.skipif(not HAS_CEDAR, reason="cedarpy not installed")
def test_biba_cedar():
    """
    Tests the Biba integrity Cedar policy (No Read Down, No Write Up).
    """
    # Load the Cedar policy
    policy_path = Path(__file__).parent / "biba.cedar"
    with open(policy_path, "r") as f:
        policies = f.read()

    # --- Read Authorization (No Read Down) ---

    # Case 1: Allow - Integrity equals Object Integrity
    assert (
        is_cedar_allowed(
            policies,
            'User::"alice"',
            'Action::"read"',
            'File::"secret"',
            {"subject": {"integrity": 2}, "object": {"integrity": 2}},
        )
        is True
    )

    # Case 2: Allow - Subject integrity LESS than Object integrity
    assert (
        is_cedar_allowed(
            policies,
            'User::"alice"',
            'Action::"read"',
            'File::"secret"',
            {"subject": {"integrity": 1}, "object": {"integrity": 2}},
        )
        is True
    )

    # Case 3: Deny - Subject integrity GREATER than Object integrity (No Read Down)
    assert (
        is_cedar_allowed(
            policies,
            'User::"alice"',
            'Action::"read"',
            'File::"secret"',
            {"subject": {"integrity": 3}, "object": {"integrity": 2}},
        )
        is False
    )

    # --- Write Authorization (No Write Up) ---

    # Case 4: Allow - Integrity equals Object Integrity
    assert (
        is_cedar_allowed(
            policies,
            'User::"alice"',
            'Action::"write"',
            'File::"secret"',
            {"subject": {"integrity": 2}, "object": {"integrity": 2}},
        )
        is True
    )

    # Case 5: Allow - Subject integrity GREATER than Object integrity
    assert (
        is_cedar_allowed(
            policies,
            'User::"alice"',
            'Action::"write"',
            'File::"secret"',
            {"subject": {"integrity": 3}, "object": {"integrity": 2}},
        )
        is True
    )

    # Case 6: Deny - Subject integrity LESS than Object integrity (No Write Up)
    assert (
        is_cedar_allowed(
            policies,
            'User::"alice"',
            'Action::"write"',
            'File::"secret"',
            {"subject": {"integrity": 1}, "object": {"integrity": 2}},
        )
        is False
    )

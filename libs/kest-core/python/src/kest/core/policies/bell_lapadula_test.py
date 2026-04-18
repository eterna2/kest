from pathlib import Path

import pytest
from regopy import Interpreter

from .testing_utils import HAS_CEDAR, HAS_REGOPY, is_allowed, is_cedar_allowed


@pytest.mark.opa
@pytest.mark.skipif(not HAS_REGOPY, reason="regopy not installed")
def test_bell_lapadula_rego():
    """
    Tests the Bell-LaPadula Rego policy (No Read Up, No Write Down).
    """
    # Load the Rego policy
    policy_path = Path(__file__).parent / "bell_lapadula.rego"
    with open(policy_path, "r") as f:
        rego_content = f.read()

    rego = Interpreter()
    # The package name in the rego file is kest.advanced.bell_lapadula
    rego.add_module("bell_lapadula", rego_content)

    # --- Read Authorization ---

    # Case 1: Allow - Clearance equals Classification
    rego.set_input(
        {"action": "read", "subject": {"clearance": 2}, "object": {"classification": 2}}
    )
    res = rego.query("data.kest.advanced.bell_lapadula.allow")
    assert is_allowed(res) is True

    # Case 2: Allow - Clearance greater than Classification
    rego.set_input(
        {"action": "read", "subject": {"clearance": 3}, "object": {"classification": 2}}
    )
    res = rego.query("data.kest.advanced.bell_lapadula.allow")
    assert is_allowed(res) is True

    # Case 3: Deny - Clearance less than Classification (No Read Up)
    rego.set_input(
        {"action": "read", "subject": {"clearance": 1}, "object": {"classification": 2}}
    )
    res = rego.query("data.kest.advanced.bell_lapadula.allow")
    assert is_allowed(res) is False

    # --- Write Authorization ---

    # Case 4: Allow - Clearance equals Classification
    rego.set_input(
        {
            "action": "write",
            "subject": {"clearance": 2},
            "object": {"classification": 2},
        }
    )
    res = rego.query("data.kest.advanced.bell_lapadula.allow")
    assert is_allowed(res) is True

    # Case 5: Allow - Clearance less than Classification
    rego.set_input(
        {
            "action": "write",
            "subject": {"clearance": 1},
            "object": {"classification": 2},
        }
    )
    res = rego.query("data.kest.advanced.bell_lapadula.allow")
    assert is_allowed(res) is True

    # Case 6: Deny - Clearance greater than Classification (No Write Down)
    rego.set_input(
        {
            "action": "write",
            "subject": {"clearance": 3},
            "object": {"classification": 2},
        }
    )
    res = rego.query("data.kest.advanced.bell_lapadula.allow")
    assert is_allowed(res) is False


@pytest.mark.cedar
@pytest.mark.skipif(not HAS_CEDAR, reason="cedarpy not installed")
def test_bell_lapadula_cedar():
    """
    Tests the Bell-LaPadula Cedar policy (No Read Up, No Write Down).
    """
    # Load the Cedar policy
    policy_path = Path(__file__).parent / "bell_lapadula.cedar"
    with open(policy_path, "r") as f:
        policies = f.read()

    # --- Read Authorization ---

    # Case 1: Allow - Clearance equals Classification
    assert (
        is_cedar_allowed(
            policies,
            'User::"alice"',
            'Action::"read"',
            'File::"secret"',
            {"subject": {"clearance": 2}, "object": {"classification": 2}},
        )
        is True
    )

    # Case 2: Allow - Clearance greater than Classification
    assert (
        is_cedar_allowed(
            policies,
            'User::"alice"',
            'Action::"read"',
            'File::"secret"',
            {"subject": {"clearance": 3}, "object": {"classification": 2}},
        )
        is True
    )

    # Case 3: Deny - Clearance less than Classification (No Read Up)
    assert (
        is_cedar_allowed(
            policies,
            'User::"alice"',
            'Action::"read"',
            'File::"secret"',
            {"subject": {"clearance": 1}, "object": {"classification": 2}},
        )
        is False
    )

    # --- Write Authorization ---

    # Case 4: Allow - Clearance equals Classification
    assert (
        is_cedar_allowed(
            policies,
            'User::"alice"',
            'Action::"write"',
            'File::"secret"',
            {"subject": {"clearance": 2}, "object": {"classification": 2}},
        )
        is True
    )

    # Case 5: Allow - Clearance less than Classification
    assert (
        is_cedar_allowed(
            policies,
            'User::"alice"',
            'Action::"write"',
            'File::"secret"',
            {"subject": {"clearance": 1}, "object": {"classification": 2}},
        )
        is True
    )

    # Case 6: Deny - Clearance greater than Classification (No Write Down)
    assert (
        is_cedar_allowed(
            policies,
            'User::"alice"',
            'Action::"write"',
            'File::"secret"',
            {"subject": {"clearance": 3}, "object": {"classification": 2}},
        )
        is False
    )

import pytest
from pathlib import Path
from regopy import Interpreter
from .testing_utils import HAS_REGOPY, is_allowed, HAS_CEDAR, is_cedar_allowed


@pytest.mark.opa
@pytest.mark.skipif(not HAS_REGOPY, reason="regopy not installed")
def test_clark_wilson_rego():
    """
    Tests the Clark-Wilson (Subject-Program-Object Triple) integrity policy (Rego).
    """
    # Load the Rego policy
    policy_path = Path(__file__).parent / "clark_wilson.rego"
    with open(policy_path, "r") as f:
        rego_content = f.read()

    rego = Interpreter()
    rego.add_module("clark_wilson", rego_content)

    # --- Operational Integrity Authorization ---

    certified_triples = [
        {"subject": "alice", "program": "payroll_app", "object": "payroll_db"},
        {"subject": "bob", "program": "inventory_app", "object": "inventory_db"},
    ]

    # Case 1: Allow - Certified Triple matches Exactly
    rego.set_input(
        {
            "certified_triples": certified_triples,
            "subject": {"id": "alice"},
            "program": {"id": "payroll_app"},
            "object": {"id": "payroll_db"},
        }
    )
    res = rego.query("data.kest.advanced.clark_wilson.allow")
    assert is_allowed(res) is True

    # Case 2: Deny - Unauthorized Program for Subject
    rego.set_input(
        {
            "certified_triples": certified_triples,
            "subject": {"id": "alice"},
            "program": {"id": "inventory_app"},
            "object": {"id": "inventory_db"},
        }
    )
    res = rego.query("data.kest.advanced.clark_wilson.allow")
    assert is_allowed(res) is False


@pytest.mark.cedar
@pytest.mark.skipif(not HAS_CEDAR, reason="cedarpy not installed")
def test_clark_wilson_cedar():
    """
    Tests the Clark-Wilson operational integrity Cedar policy.
    """
    # Load the Cedar policy
    policy_path = Path(__file__).parent / "clark_wilson.cedar"
    with open(policy_path, "r") as f:
        policies = f.read()

    # Case 1: Allow - Certified Triple
    assert (
        is_cedar_allowed(
            policies,
            'User::"alice"',
            'Action::"use"',
            'Program::"payroll_app"',
            {"is_certified_triple": True},
        )
        is True
    )

    # Case 2: Deny - Not a Certified Triple
    assert (
        is_cedar_allowed(
            policies,
            'User::"alice"',
            'Action::"use"',
            'Program::"payroll_app"',
            {"is_certified_triple": False},
        )
        is False
    )

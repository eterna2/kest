import pytest
from pathlib import Path
from regopy import Interpreter
from .testing_utils import HAS_REGOPY, is_allowed, HAS_CEDAR, is_cedar_allowed


@pytest.mark.opa
@pytest.mark.skipif(not HAS_REGOPY, reason="regopy not installed")
def test_goguen_meseguer_rego():
    """
    Tests the Goguen-Meseguer (Non-interference/Domain isolation) policy (Rego).
    """
    # Load the Rego policy
    policy_path = Path(__file__).parent / "goguen_meseguer.rego"
    with open(policy_path, "r") as f:
        rego_content = f.read()

    rego = Interpreter()
    rego.add_module("goguen_meseguer", rego_content)

    # --- Non-interference Authorization ---

    non_interference_mappings = [
        {"from_domain": "admin", "to_domain": "service"},
        {"from_domain": "user", "to_domain": "public"},
    ]

    # Case 1: Allow - Subject and Object are in same Domain
    rego.set_input({"subject": {"domain": "service"}, "object": {"domain": "service"}})
    res = rego.query("data.kest.advanced.goguen_meseguer.allow")
    assert is_allowed(res) is True

    # Case 2: Allow - Cross Domain with Permission (admin -> service)
    rego.set_input(
        {
            "non_interference_mappings": non_interference_mappings,
            "subject": {"domain": "admin"},
            "object": {"domain": "service"},
        }
    )
    res = rego.query("data.kest.advanced.goguen_meseguer.allow")
    assert is_allowed(res) is True


@pytest.mark.cedar
@pytest.mark.skipif(not HAS_CEDAR, reason="cedarpy not installed")
def test_goguen_meseguer_cedar():
    """
    Tests the Goguen-Meseguer non-interference Cedar policy.
    """
    # Load the Cedar policy
    policy_path = Path(__file__).parent / "goguen_meseguer.cedar"
    with open(policy_path, "r") as f:
        policies = f.read()

    # Case 1: Allow - Same Domain
    assert (
        is_cedar_allowed(
            policies,
            'User::"alice"',
            'Action::"access"',
            'Domain::"service"',
            {"subject": {"domain": "service"}, "object": {"domain": "service"}},
        )
        is True
    )

    # Case 2: Allow - Cross Domain with Non-Interference
    assert (
        is_cedar_allowed(
            policies,
            'User::"alice"',
            'Action::"access"',
            'Domain::"public"',
            {
                "subject": {"domain": "user"},
                "object": {"domain": "public"},
                "is_non_interfering": True,
            },
        )
        is True
    )

    # Case 3: Deny - Cross Domain without Non-Interference
    assert (
        is_cedar_allowed(
            policies,
            'User::"alice"',
            'Action::"access"',
            'Domain::"service"',
            {
                "subject": {"domain": "user"},
                "object": {"domain": "service"},
                "is_non_interfering": False,
            },
        )
        is False
    )

import pytest
from pathlib import Path
from regopy import Interpreter
from .testing_utils import HAS_REGOPY, is_allowed, HAS_CEDAR, is_cedar_allowed


@pytest.mark.opa
@pytest.mark.skipif(not HAS_REGOPY, reason="regopy not installed")
def test_brewer_nash_rego():
    """
    Tests the Brewer-Nash (Chinese Wall) conflict of interest policy (Rego).
    """
    # Load the Rego policy
    policy_path = Path(__file__).parent / "brewer_nash.rego"
    with open(policy_path, "r") as f:
        rego_content = f.read()

    rego = Interpreter()
    rego.add_module("brewer_nash", rego_content)

    # --- Conflict of Interest Authorization ---

    # Case 1: Allow - No previous history in this conflict class
    rego.set_input(
        {
            "subject": {"history": []},
            "object": {"conflict_class": "finance", "company_id": "bank_a"},
        }
    )
    res = rego.query("data.kest.advanced.brewer_nash.allow")
    assert is_allowed(res) is True

    # Case 2: Allow - Accessing the same company as previously accessed in this class
    rego.set_input(
        {
            "subject": {
                "history": [{"conflict_class": "finance", "company_id": "bank_a"}]
            },
            "object": {"conflict_class": "finance", "company_id": "bank_a"},
        }
    )
    res = rego.query("data.kest.advanced.brewer_nash.allow")
    assert is_allowed(res) is True

    # Case 3: Deny - Accessing a competitor in the same conflict class
    rego.set_input(
        {
            "subject": {
                "history": [{"conflict_class": "finance", "company_id": "bank_a"}]
            },
            "object": {"conflict_class": "finance", "company_id": "bank_b"},
        }
    )
    res = rego.query("data.kest.advanced.brewer_nash.allow")
    assert is_allowed(res) is False

    # Case 4: Allow - Accessing a company in a DIFFERENT conflict class
    rego.set_input(
        {
            "subject": {
                "history": [{"conflict_class": "finance", "company_id": " bank_a"}]
            },
            "object": {"conflict_class": "tech", "company_id": "google"},
        }
    )
    res = rego.query("data.kest.advanced.brewer_nash.allow")
    assert is_allowed(res) is True

    # Case 5: Allow - Object has no conflict class (Public Data)
    rego.set_input(
        {
            "subject": {
                "history": [{"conflict_class": "finance", "company_id": "bank_a"}]
            },
            "object": {},  # No conflict_class
        }
    )
    res = rego.query("data.kest.advanced.brewer_nash.allow")
    assert is_allowed(res) is True


@pytest.mark.cedar
@pytest.mark.skipif(not HAS_CEDAR, reason="cedarpy not installed")
def test_brewer_nash_cedar():
    """
    Tests the Brewer-Nash conflict of interest Cedar policy.
    """
    # Load the Cedar policy
    policy_path = Path(__file__).parent / "brewer_nash.cedar"
    with open(policy_path, "r") as f:
        policies = f.read()

    # --- Conflict of Interest Authorization ---

    # Case 1: Allow - No previous history in this conflict class
    assert (
        is_cedar_allowed(
            policies,
            'User::"alice"',
            'Action::"read"',
            'File::"bank_a_data"',
            {
                "subject": {"history_in_conflict_class": 0},
                "object": {"conflict_class": "finance", "company_id": "bank_a"},
            },
        )
        is True
    )

    # Case 2: Allow - Accessing the same company as previously accessed in this class
    assert (
        is_cedar_allowed(
            policies,
            'User::"alice"',
            'Action::"read"',
            'File::"bank_a_data"',
            {
                "subject": {
                    "history_in_conflict_class": 1,
                    "accessed_company_id": "bank_a",
                },
                "object": {"conflict_class": "finance", "company_id": "bank_a"},
            },
        )
        is True
    )

    # Case 3: Deny - Accessing a competitor in the same conflict class
    assert (
        is_cedar_allowed(
            policies,
            'User::"alice"',
            'Action::"read"',
            'File::"bank_b_data"',
            {
                "subject": {
                    "history_in_conflict_class": 1,
                    "accessed_company_id": "bank_a",
                },
                "object": {"conflict_class": "finance", "company_id": "bank_b"},
            },
        )
        is False
    )

    # Case 4: Allow - Object has no conflict class (Public Data)
    assert (
        is_cedar_allowed(
            policies,
            'User::"alice"',
            'Action::"read"',
            'File::"public_data"',
            {
                "subject": {
                    "history_in_conflict_class": 1,
                    "accessed_company_id": "bank_a",
                },
                "object": {},
            },
        )
        is True
    )

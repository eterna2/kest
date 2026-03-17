import pytest

from kest.core.policy import _HAS_REGORUS, LocalOpaEngine


@pytest.mark.skipif(not _HAS_REGORUS, reason="lakera-regorus requires Python 3.11")
def test_opa_engine_inline_evaluation():
    """Verify OPA engine compiles inline Rego and correctly evaluates taint."""
    engine = LocalOpaEngine()
    rego_rule = """
    package kest.policy
    
    default allow = false
    
    allow {
        not has_untrusted
    }

    has_untrusted {
        some i
        input.history[input.leaf_node].accumulated_taint[i] == "untrusted"
    }
    """
    engine.add_policy("inline", rego_rule)

    # Mock evaluation payload mirroring the Kest passport structure
    passport_data_tainted = {
        "history": {"node-1": {"accumulated_taint": ["untrusted"]}},
        "leaf_node": "node-1",
    }

    assert engine.evaluate(passport_data_tainted, "data.kest.policy.allow") is False

    passport_data_clean = {
        "history": {"node-2": {"accumulated_taint": ["clean_data"]}},
        "leaf_node": "node-2",
    }

    assert engine.evaluate(passport_data_clean, "data.kest.policy.allow") is True


@pytest.mark.skipif(not _HAS_REGORUS, reason="lakera-regorus requires Python 3.11")
def test_opa_engine_missing_policy():
    """Verify OPA engine raises an error when evaluating a non-existent package."""
    engine = LocalOpaEngine()
    with pytest.raises(Exception):
        engine.evaluate({"input": "data"}, "data.missing.policy")

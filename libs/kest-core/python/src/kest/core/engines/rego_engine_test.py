"""Unit tests for RegoLocalEngine."""

import importlib.util

import pytest

from kest.core.engines.engine import PolicyCache, RegoLocalEngine

HAS_REGOPY = importlib.util.find_spec("regopy") is not None

ALLOW_POLICY = """
package kest.authz

default allow = false

allow {
    input.trust_score >= 50
}
"""

DENY_POLICY = """
package kest.denyall

default allow = false
"""

TAINT_POLICY = """
package kest.taints

default allow = false

allow {
    not "pii" in input.taints
}
"""


@pytest.mark.skipif(
    not HAS_REGOPY, reason="regopy not installed — skip RegoLocalEngine tests"
)
class TestRegoLocalEngine:
    def _engine(self, **extra_policies) -> RegoLocalEngine:
        policies = {"authz": ALLOW_POLICY, "taints": TAINT_POLICY, **extra_policies}
        return RegoLocalEngine(policies=policies)

    def test_allow_when_trust_score_sufficient(self):
        engine = self._engine()
        assert engine.evaluate("res-1", ["authz"], {"trust_score": 50}) is True
        assert engine.evaluate("res-1", ["authz"], {"trust_score": 100}) is True

    def test_deny_when_trust_score_insufficient(self):
        engine = self._engine()
        assert engine.evaluate("res-1", ["authz"], {"trust_score": 49}) is False
        assert engine.evaluate("res-1", ["authz"], {"trust_score": 0}) is False

    def test_taint_policy_allows_clean_input(self):
        engine = self._engine()
        assert engine.evaluate("res-1", ["taints"], {"taints": []}) is True
        assert engine.evaluate("res-1", ["taints"], {"taints": ["safe"]}) is True

    def test_taint_policy_denies_pii(self):
        engine = self._engine()
        assert engine.evaluate("res-1", ["taints"], {"taints": ["pii"]}) is False
        assert (
            engine.evaluate("res-1", ["taints"], {"taints": ["pii", "safe"]}) is False
        )

    def test_all_policies_must_pass(self):
        """Both authz and taints must pass for allow."""
        engine = self._engine()
        # trust ok, taint ok → allow
        assert (
            engine.evaluate(
                "res-1", ["authz", "taints"], {"trust_score": 60, "taints": []}
            )
            is True
        )
        # trust ok, taint fail → deny
        assert (
            engine.evaluate(
                "res-1", ["authz", "taints"], {"trust_score": 60, "taints": ["pii"]}
            )
            is False
        )
        # trust fail, taint ok → deny
        assert (
            engine.evaluate(
                "res-1", ["authz", "taints"], {"trust_score": 10, "taints": []}
            )
            is False
        )

    def test_resource_injected_into_input(self):
        """entry_id is injected as input.resource."""
        resource_policy = """
            package kest.res
            default allow = false
            allow { input.resource == "allowed-resource" }
        """
        engine = RegoLocalEngine(policies={"res": resource_policy})
        assert engine.evaluate("allowed-resource", ["res"], {}) is True
        assert engine.evaluate("other-resource", ["res"], {}) is False

    def test_unknown_policy_name_denies(self):
        engine = self._engine()
        assert engine.evaluate("res-1", ["nonexistent"], {}) is False

    def test_empty_policy_names_allows(self):
        """No policies to check → vacuously true (consistent with Cedar/OPA behaviour)."""
        engine = self._engine()
        assert engine.evaluate("res-1", [], {}) is True

    def test_cache_is_used_on_repeat_calls(self):
        cache = PolicyCache()
        engine = RegoLocalEngine(policies={"authz": ALLOW_POLICY}, cache=cache)
        ctx = {"trust_score": 80}

        result1 = engine.evaluate("res-1", ["authz"], ctx)
        result2 = engine.evaluate("res-1", ["authz"], ctx)
        assert result1 is True
        assert result2 is True  # served from cache

    def test_deny_only_policy(self):
        engine = RegoLocalEngine(policies={"deny": DENY_POLICY})
        assert engine.evaluate("res-1", ["deny"], {"trust_score": 100}) is False

    def test_custom_query_rule(self):
        policy = """
            package kest.custom
            default permitted = false
            permitted { input.level >= 3 }
        """
        engine = RegoLocalEngine(policies={"custom": policy}, query_rule="permitted")
        assert engine.evaluate("res-1", ["custom"], {"level": 3}) is True
        assert engine.evaluate("res-1", ["custom"], {"level": 2}) is False


def test_import_error_without_regopy(monkeypatch):
    """RegoLocalEngine raises ImportError when regopy is not available."""
    import builtins

    real_import = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if name == "regopy":
            raise ImportError("mocked absence")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", mock_import)
    with pytest.raises(ImportError, match="regopy is not installed"):
        RegoLocalEngine(policies={"authz": ALLOW_POLICY})

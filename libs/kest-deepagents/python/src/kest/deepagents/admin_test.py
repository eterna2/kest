"""
Tests for KestAdminSubagent.

All tool methods use @kest_verified, so policy allow/deny is exercised
using HardcodedRuleEngine + MockIdentityProvider — no mocks.
"""

import json

import pytest
from typing import Any, Dict

from langchain_core.tools import BaseTool

from kest.core import configure, invalidate_policy_cache
from kest.core.identity import MockIdentityProvider

from kest.deepagents._test_helpers import HardcodedRuleEngine
from kest.deepagents.admin import InMemoryPolicyStore, KestAdminSubagent
from kest.deepagents.subagent import SubagentProtocol


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


class MemoryTraceBackend:
    """In-memory trace backend for realistic testing without coupling."""
    def __init__(self, trace_store: Dict[str, Dict[str, Any]]):
        self._store = trace_store

    def get_trace(self, trace_id: str) -> Dict[str, Any]:
        return self._store.get(trace_id, {})


@pytest.fixture(autouse=True)
def kest_env():
    """Clean kest environment for each test."""
    invalidate_policy_cache()
    configure(
        engine=HardcodedRuleEngine(
            blocked_policies=frozenset({"blocked_policy"}),
            min_trust=50,
        ),
        identity=MockIdentityProvider(),
    )
    yield
    configure(clear=True)
    invalidate_policy_cache()


@pytest.fixture()
def store():
    return {
        "trace-123": {
            "spans": [
                {"attributes": {"kest.policy_ids": "authz_policy", "kest.allowed": True}},
                {"attributes": {"kest.policy_ids": "fs_policy", "kest.allowed": False}},
            ]
        }
    }


@pytest.fixture()
def agent(store):
    return KestAdminSubagent(MemoryTraceBackend(store))


# ---------------------------------------------------------------------------
# SubagentProtocol conformance
# ---------------------------------------------------------------------------


def test_admin_satisfies_subagent_protocol(agent):
    assert isinstance(agent, SubagentProtocol)
    assert agent.name == "admin"
    assert agent.description != ""


def test_admin_get_tools_returns_list_of_base_tools(agent):
    tools = agent.get_tools()
    assert len(tools) == 5
    assert all(isinstance(t, BaseTool) for t in tools)


def test_admin_get_tools_names(agent):
    names = [t.name for t in agent.get_tools()]
    assert "explain_limits" in names
    assert "create_policy" in names
    assert "list_policies" in names
    assert "apply_policy" in names
    assert "delete_policy" in names


# ---------------------------------------------------------------------------
# parse_policy_decisions — pure domain logic, no kest involved
# ---------------------------------------------------------------------------


def test_admin_subagent_parse_decisions():
    agent = KestAdminSubagent(MemoryTraceBackend({}))
    spans = [
        {"attributes": {"kest.policy_ids": "authz_policy"}},
        {"attributes": {"kest.policy_ids": "network_policy, fs_policy", "kest.allowed": False}},
        {"attributes": {}},
    ]
    decisions = agent.parse_policy_decisions(spans)
    assert decisions == ["authz_policy", "network_policy", "fs_policy"]


# ---------------------------------------------------------------------------
# get_explain_tool — @tool + @kest_verified
# ---------------------------------------------------------------------------


class TestExplainLimitsTool:
    def test_returns_basetool_with_correct_name(self, agent):
        from langchain_core.tools import BaseTool
        tool = agent.get_explain_tool()
        assert isinstance(tool, BaseTool)
        assert tool.name == "explain_limits"

    def test_allowed_policy_returns_explanation(self, agent):
        tool = agent.get_explain_tool()
        result = tool.invoke({"trace_id": "trace-123"})
        assert "Policy 'authz_policy' evaluated to ALLOWED." in result
        assert "Policy 'fs_policy' evaluated to DENIED." in result

    def test_missing_trace_returns_not_found(self, agent):
        tool = agent.get_explain_tool()
        result = tool.invoke({"trace_id": "trace-999"})
        assert "Trace trace-999 not found" in result

    def test_blocked_by_policy_raises_permission_error(self, store):
        """When admin_policy is blocked, explain_limits must be denied by kest."""
        configure(engine=HardcodedRuleEngine(
            blocked_policies=frozenset({"admin_policy"}),
        ))
        agent = KestAdminSubagent(MemoryTraceBackend(store))
        tool = agent.get_explain_tool()
        with pytest.raises(PermissionError, match="denied execution"):
            tool.invoke({"trace_id": "trace-123"})

    def test_low_trust_raises_permission_error(self, store):
        """explain_limits with trust below min_trust must be denied."""
        configure(engine=HardcodedRuleEngine(min_trust=100))  # nothing passes
        agent = KestAdminSubagent(MemoryTraceBackend(store))
        tool = agent.get_explain_tool()
        with pytest.raises(PermissionError, match="denied execution"):
            tool.invoke({"trace_id": "trace-123"})


# ---------------------------------------------------------------------------
# InMemoryPolicyStore — CRUD round-trips
# ---------------------------------------------------------------------------


class TestInMemoryPolicyStore:
    def test_create_and_get(self):
        ps = InMemoryPolicyStore()
        ps.create("p1", {"type": "deny", "resource": "fs"})
        result = ps.get("p1")
        assert result is not None
        assert result["id"] == "p1"
        assert result["type"] == "deny"

    def test_create_duplicate_raises(self):
        ps = InMemoryPolicyStore()
        ps.create("p1", {"type": "allow"})
        with pytest.raises(ValueError, match="already exists"):
            ps.create("p1", {"type": "deny"})

    def test_list_empty(self):
        ps = InMemoryPolicyStore()
        assert ps.list() == []

    def test_list_returns_all(self):
        ps = InMemoryPolicyStore()
        ps.create("p1", {"type": "allow"})
        ps.create("p2", {"type": "deny"})
        result = ps.list()
        assert len(result) == 2

    def test_get_missing_returns_none(self):
        ps = InMemoryPolicyStore()
        assert ps.get("nope") is None

    def test_delete(self):
        ps = InMemoryPolicyStore()
        ps.create("p1", {"type": "allow"})
        ps.delete("p1")
        assert ps.get("p1") is None

    def test_delete_missing_raises(self):
        ps = InMemoryPolicyStore()
        with pytest.raises(KeyError, match="not found"):
            ps.delete("nope")


# ---------------------------------------------------------------------------
# Policy CRUD tools — kest-verified
# ---------------------------------------------------------------------------


class TestCreatePolicyTool:
    def test_creates_policy(self, agent):
        tool = agent.get_create_policy_tool()
        result = tool.invoke({
            "policy_id": "test-policy",
            "definition_json": json.dumps({"type": "allow", "resource": "*"}),
        })
        assert "created successfully" in result
        assert agent.policy_store.get("test-policy") is not None

    def test_invalid_json(self, agent):
        tool = agent.get_create_policy_tool()
        result = tool.invoke({
            "policy_id": "bad",
            "definition_json": "not-json{",
        })
        assert "Invalid JSON" in result

    def test_duplicate_returns_error(self, agent):
        tool = agent.get_create_policy_tool()
        tool.invoke({"policy_id": "dup", "definition_json": "{}"})
        result = tool.invoke({"policy_id": "dup", "definition_json": "{}"})
        assert "already exists" in result


class TestListPoliciesTool:
    def test_empty_store(self, agent):
        tool = agent.get_list_policies_tool()
        result = tool.invoke({})
        assert "No policies" in result

    def test_lists_created_policies(self, agent):
        agent.policy_store.create("p1", {"type": "allow"})
        tool = agent.get_list_policies_tool()
        result = tool.invoke({})
        parsed = json.loads(result)
        assert len(parsed) == 1
        assert parsed[0]["id"] == "p1"


class TestApplyPolicyTool:
    def test_applies_policy_to_target(self, agent):
        agent.policy_store.create("p1", {"type": "allow"})
        tool = agent.get_apply_policy_tool()
        result = tool.invoke({"policy_id": "p1", "target": "cat"})
        assert "bound to 'cat'" in result
        assert "kest.core.configure" in result

    def test_apply_missing_policy(self, agent):
        tool = agent.get_apply_policy_tool()
        result = tool.invoke({"policy_id": "nope", "target": "cat"})
        assert "not found" in result

    def test_idempotent_apply(self, agent):
        agent.policy_store.create("p1", {"type": "allow"})
        tool = agent.get_apply_policy_tool()
        tool.invoke({"policy_id": "p1", "target": "cat"})
        tool.invoke({"policy_id": "p1", "target": "cat"})
        policy = agent.policy_store.get("p1")
        assert policy is not None
        assert policy["bindings"].count("cat") == 1


class TestDeletePolicyTool:
    def test_deletes_policy(self, agent):
        agent.policy_store.create("p1", {"type": "allow"})
        tool = agent.get_delete_policy_tool()
        result = tool.invoke({"policy_id": "p1"})
        assert "deleted" in result
        assert agent.policy_store.get("p1") is None

    def test_delete_missing(self, agent):
        tool = agent.get_delete_policy_tool()
        result = tool.invoke({"policy_id": "nope"})
        assert "not found" in result

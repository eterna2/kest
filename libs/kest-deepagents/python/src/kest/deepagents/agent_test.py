"""
Tests for KestAgent — the composable multi-agent orchestrator.
"""

import pytest
from langchain_core.tools import BaseTool, tool

from kest.deepagents.agent import KestAgent
from kest.deepagents.subagent import SubagentBase


# ---------------------------------------------------------------------------
# Fixtures — lightweight subagent stubs
# ---------------------------------------------------------------------------


class _StubSubagentA(SubagentBase):
    name = "alpha"
    description = "first stub"

    def get_tools(self):
        @tool
        def alpha_tool() -> str:
            """Alpha tool."""
            return "alpha"
        return [alpha_tool]


class _StubSubagentB(SubagentBase):
    name = "beta"
    description = "second stub"

    def get_tools(self):
        @tool
        def beta_one() -> str:
            """Beta one."""
            return "b1"

        @tool
        def beta_two() -> str:
            """Beta two."""
            return "b2"
        return [beta_one, beta_two]


class _NotASubagent:
    """Does not satisfy SubagentProtocol."""
    pass


# ---------------------------------------------------------------------------
# Constructor & registration
# ---------------------------------------------------------------------------


def test_empty_agent_has_no_tools():
    agent = KestAgent()
    assert agent.get_tools() == []
    assert agent.subagents == []


def test_register_at_construction():
    agent = KestAgent(subagents=[_StubSubagentA(), _StubSubagentB()])
    assert len(agent.subagents) == 2


def test_register_returns_self_for_chaining():
    agent = KestAgent()
    result = agent.register(_StubSubagentA())
    assert result is agent


def test_register_rejects_non_protocol():
    agent = KestAgent()
    with pytest.raises(TypeError, match="does not satisfy SubagentProtocol"):
        agent.register(_NotASubagent())  # type: ignore[arg-type]


def test_duplicate_name_raises_value_error():
    agent = KestAgent(subagents=[_StubSubagentA()])
    with pytest.raises(ValueError, match="already registered"):
        agent.register(_StubSubagentA())


# ---------------------------------------------------------------------------
# get_tools — flat aggregation
# ---------------------------------------------------------------------------


def test_get_tools_aggregates_from_all_subagents():
    agent = KestAgent(subagents=[_StubSubagentA(), _StubSubagentB()])
    tools = agent.get_tools()
    assert len(tools) == 3  # 1 from A + 2 from B
    assert all(isinstance(t, BaseTool) for t in tools)


def test_get_tools_preserves_registration_order():
    agent = KestAgent(subagents=[_StubSubagentA(), _StubSubagentB()])
    names = [t.name for t in agent.get_tools()]
    assert names == ["alpha_tool", "beta_one", "beta_two"]


# ---------------------------------------------------------------------------
# get_subagent — name-based lookup
# ---------------------------------------------------------------------------


def test_get_subagent_by_name():
    a = _StubSubagentA()
    agent = KestAgent(subagents=[a, _StubSubagentB()])
    assert agent.get_subagent("alpha") is a


def test_get_subagent_returns_none_for_unknown():
    agent = KestAgent(subagents=[_StubSubagentA()])
    assert agent.get_subagent("nonexistent") is None


# ---------------------------------------------------------------------------
# Agent name
# ---------------------------------------------------------------------------


def test_default_name():
    agent = KestAgent()
    assert agent.name == "kest-agent"


def test_custom_name():
    agent = KestAgent(name="my-agent")
    assert agent.name == "my-agent"

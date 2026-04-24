"""
Tests for SubagentProtocol and SubagentBase.

Verifies structural conformance so that any class satisfying the protocol
can be registered with KestAgent.
"""

from langchain_core.tools import BaseTool, tool

from kest.deepagents.subagent import SubagentBase, SubagentProtocol


# ---------------------------------------------------------------------------
# SubagentProtocol — runtime_checkable structural tests
# ---------------------------------------------------------------------------


class _BareConformant:
    """Minimal class that satisfies SubagentProtocol structurally."""
    name = "bare"
    description = "bare subagent"

    def get_tools(self):
        return []


class _MissingName:
    description = "no name"

    def get_tools(self):
        return []


class _MissingGetTools:
    name = "broken"
    description = "missing get_tools"


def test_protocol_accepts_conformant_class():
    assert isinstance(_BareConformant(), SubagentProtocol)


def test_protocol_rejects_missing_name():
    assert not isinstance(_MissingName(), SubagentProtocol)


def test_protocol_rejects_missing_get_tools():
    assert not isinstance(_MissingGetTools(), SubagentProtocol)


# ---------------------------------------------------------------------------
# SubagentBase — convenience base class
# ---------------------------------------------------------------------------


def test_base_default_name_and_description():
    base = SubagentBase()
    assert base.name == ""
    assert base.description == ""


def test_base_custom_name_and_description():
    base = SubagentBase(name="test", description="a test subagent")
    assert base.name == "test"
    assert base.description == "a test subagent"


def test_base_get_tools_returns_empty_list():
    base = SubagentBase(name="test")
    tools = base.get_tools()
    assert tools == []
    assert isinstance(tools, list)


def test_base_satisfies_protocol():
    base = SubagentBase(name="proto", description="test")
    assert isinstance(base, SubagentProtocol)


class _CustomSubagent(SubagentBase):
    """Subclass that overrides get_tools."""
    name = "custom"
    description = "custom subagent"

    def get_tools(self):
        @tool
        def dummy() -> str:
            """A dummy tool."""
            return "ok"
        return [dummy]


def test_subclass_get_tools_returns_tools():
    agent = _CustomSubagent()
    tools = agent.get_tools()
    assert len(tools) == 1
    assert isinstance(tools[0], BaseTool)
    assert tools[0].name == "dummy"


def test_subclass_satisfies_protocol():
    assert isinstance(_CustomSubagent(), SubagentProtocol)

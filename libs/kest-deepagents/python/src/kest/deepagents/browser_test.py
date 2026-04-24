import pytest
from langchain_core.tools import BaseTool

from kest.core import configure, invalidate_policy_cache, MockPolicyEngine
from kest.core.identity import MockIdentityProvider
from kest.deepagents.browser import BrowserSubagent
from kest.deepagents.subagent import SubagentProtocol


@pytest.fixture(autouse=True)
def setup_kest():
    invalidate_policy_cache()

    class PassEngine(MockPolicyEngine):
        def evaluate(self, entry_id, policy_names, context):
            return True

    class RejectEngine(MockPolicyEngine):
        def evaluate(self, entry_id, policy_names, context):
            return False

    yield {"allow": PassEngine(), "reject": RejectEngine()}
    configure(clear=True)
    invalidate_policy_cache()


# ---------------------------------------------------------------------------
# SubagentProtocol conformance
# ---------------------------------------------------------------------------


def test_browser_satisfies_subagent_protocol():
    agent = BrowserSubagent(allowed_domains=["example.com"])
    assert isinstance(agent, SubagentProtocol)
    assert agent.name == "browser"
    assert agent.description != ""


def test_browser_get_tools_returns_list(setup_kest):
    configure(engine=setup_kest["allow"], identity=MockIdentityProvider())
    agent = BrowserSubagent(allowed_domains=["github.com"])
    tools = agent.get_tools()
    assert isinstance(tools, list)
    assert len(tools) == 1
    assert isinstance(tools[0], BaseTool)
    assert tools[0].name == "navigate"


# ---------------------------------------------------------------------------
# Existing tests (unchanged)
# ---------------------------------------------------------------------------


def test_browser_subagent_navigate_tool(setup_kest):
    configure(engine=setup_kest["allow"], identity=MockIdentityProvider())

    agent = BrowserSubagent(allowed_domains=["github.com"])
    tool = agent.get_navigate_tool()

    assert isinstance(tool, BaseTool)

    # Valid domain
    res = tool.invoke({"url": "https://github.com/sickn33"})
    assert "Successfully navigated" in res

    # Invalid domain explicitly tested
    with pytest.raises(PermissionError, match="outside allowed policy boundaries"):
        tool.invoke({"url": "https://malicious.com"})


def test_browser_subagent_kest_policy_rejection(setup_kest):
    # Kest policy dynamically rejects despite being a valid constructor domain
    configure(engine=setup_kest["reject"], identity=MockIdentityProvider())

    agent = BrowserSubagent(allowed_domains=["github.com"])
    tool = agent.get_navigate_tool()

    with pytest.raises(PermissionError, match="denied execution"):
        tool.invoke({"url": "https://github.com/sickn33"})

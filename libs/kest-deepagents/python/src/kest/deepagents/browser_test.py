from unittest.mock import MagicMock

import pytest

from kest.deepagents.browser import BrowserSubagent


class TestBrowserSubagent:
    def test_delegated_passport_initialization(self):
        """Should initialize with a sub-passport scoped to particular constraints"""
        parent_passport = MagicMock()
        parent_passport.subject = "Terminal-1"
        parent_passport.scope = "full"

        agent = BrowserSubagent(
            parent_passport=parent_passport, allowed_domains=["example.com"]
        )

        # Verify the passport was properly restricted
        assert agent.passport != parent_passport
        assert agent.passport.subject == "Terminal-1.browser"

    def test_blocks_disallowed_navigation(self):
        """Should block URL navigation if domain is not in allowed list"""
        agent = BrowserSubagent(
            parent_passport=MagicMock(), allowed_domains=["example.com"]
        )

        with pytest.raises(
            ValueError, match="Domain test.com is outside allowed policy boundaries"
        ):
            agent.navigate("http://test.com")

    def test_allows_permitted_navigation(self):
        """Should execute original navigate if allowed"""
        agent = BrowserSubagent(
            parent_passport=MagicMock(), allowed_domains=["example.com"]
        )
        agent.mcp_client = MagicMock()

        agent.navigate("http://example.com/about")
        agent.mcp_client.navigate.assert_called_once_with("http://example.com/about")

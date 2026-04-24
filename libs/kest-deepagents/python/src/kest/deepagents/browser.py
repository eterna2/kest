"""
BrowserSubagent — A zero-trust web navigation agent.

Satisfies ``SubagentProtocol`` so it can be registered with ``KestAgent``.

Uses the idiomatic @tool + @kest_verified stacking pattern.
The 'url' argument is mapped into the OTel baggage via context_map
so that policy engines can inspect the navigation target.
"""

from __future__ import annotations

from typing import Any, List, Optional
from urllib.parse import urlparse

from langchain_core.tools import BaseTool, tool

from kest.core import kest_verified


class BrowserSubagent:
    """Agent capable of surfing the web constrained by zero-trust policies."""

    name: str = "browser"
    description: str = "Zero-trust web navigation"

    def __init__(self, allowed_domains: List[str], mcp_client: Optional[Any] = None):
        """
        Initializes the Browser Subagent.

        Args:
            allowed_domains: A list of explicitly permitted domains to navigate to.
            mcp_client: (Optional) The connected MCP client handle.
        """
        self.allowed_domains = allowed_domains
        self.mcp_client = mcp_client

    # ------------------------------------------------------------------
    # SubagentProtocol.get_tools
    # ------------------------------------------------------------------

    def get_tools(self) -> List[BaseTool]:
        """Return all browser tools as a flat list."""
        return [self.get_navigate_tool()]

    # ------------------------------------------------------------------
    # Tool: navigate
    # ------------------------------------------------------------------

    def get_navigate_tool(self) -> BaseTool:
        """Exposes the `navigate` action as a LangChain BaseTool."""

        # Idiomatic pattern: @tool over @kest_verified.
        # 'url' is mapped into OTel baggage so policy engines can inspect
        # the navigation target before execution proceeds.
        @tool
        @kest_verified(
            policy="browser_policy",
            context_map={"url": "url"},
        )
        def navigate(url: str) -> str:
            """Navigates the browser to a given URL if it adheres to boundary policies."""
            parsed = urlparse(url)
            domain = parsed.netloc

            if domain not in self.allowed_domains:
                raise PermissionError(f"Domain {domain} is outside allowed policy boundaries")

            if self.mcp_client:
                self.mcp_client.navigate(url)

            return f"Successfully navigated to {url}"

        return navigate

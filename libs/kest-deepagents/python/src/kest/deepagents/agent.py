"""
KestAgent — Composable multi-agent orchestrator.

Manages a registry of subagents (``SubagentProtocol``) and exposes their
combined tools as a flat list for use with any LangChain agent executor.
Subagents can be registered at construction time or dynamically afterwards.

Example::

    from kest.deepagents.agent import KestAgent
    from kest.deepagents.admin import KestAdminSubagent
    from kest.deepagents.browser import BrowserSubagent

    agent = KestAgent(subagents=[
        KestAdminSubagent(trace_backend=backend),
        BrowserSubagent(allowed_domains=["github.com"]),
    ])

    tools = agent.get_tools()       # flat list from all subagents
    admin = agent.get_subagent("admin")
"""

from __future__ import annotations

from typing import Dict, List, Optional

from langchain_core.tools import BaseTool

from kest.deepagents.subagent import SubagentProtocol


class KestAgent:
    """
    Composable multi-agent host.

    Manages a registry of subagents (``SubagentProtocol``) and exposes
    their combined tools as a flat list. Subagents are identified by their
    unique ``name`` attribute.

    Args:
        subagents: Optional list of subagents to register at construction.
        name:      Display name for this agent (e.g. shown in TUI header).
    """

    def __init__(
        self,
        subagents: Optional[List[SubagentProtocol]] = None,
        name: str = "kest-agent",
    ) -> None:
        self.name = name
        self._registry: Dict[str, SubagentProtocol] = {}

        for sa in subagents or []:
            self.register(sa)

    def register(self, subagent: SubagentProtocol) -> "KestAgent":
        """
        Register a subagent.

        Args:
            subagent: Must satisfy ``SubagentProtocol``.

        Returns:
            ``self`` for method chaining.

        Raises:
            TypeError:  If *subagent* does not satisfy ``SubagentProtocol``.
            ValueError: If a subagent with the same ``name`` is already
                        registered.
        """
        if not isinstance(subagent, SubagentProtocol):
            raise TypeError(
                f"{subagent!r} does not satisfy SubagentProtocol. "
                f"It must have 'name: str', 'description: str', and "
                f"'get_tools() -> list[BaseTool]'."
            )

        if subagent.name in self._registry:
            raise ValueError(
                f"A subagent named '{subagent.name}' is already registered. "
                f"Use a unique name for each subagent."
            )

        self._registry[subagent.name] = subagent
        return self

    def get_tools(self) -> List[BaseTool]:
        """
        Collect tools from all registered subagents into a flat list.

        The order follows subagent registration order, with each subagent's
        tools in the order returned by ``subagent.get_tools()``.
        """
        tools: List[BaseTool] = []
        for sa in self._registry.values():
            tools.extend(sa.get_tools())
        return tools

    def get_subagent(self, name: str) -> Optional[SubagentProtocol]:
        """
        Look up a registered subagent by name.

        Returns:
            The matching subagent, or ``None`` if not found.
        """
        return self._registry.get(name)

    @property
    def subagents(self) -> List[SubagentProtocol]:
        """All registered subagents in registration order."""
        return list(self._registry.values())

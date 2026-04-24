"""
SubagentProtocol — The structural contract for all kest-agent subagents.

Any class satisfying this protocol can be registered with ``KestAgent``.
Framework-agnostic: subagents can be pure code, LangChain-based, or
wrap external services (MCP, REST, etc.).

``SubagentBase`` is an optional convenience base class that provides
sensible defaults — using it is NOT required; only the protocol matters.
"""

from __future__ import annotations

from typing import List, Protocol, runtime_checkable

from langchain_core.tools import BaseTool


@runtime_checkable
class SubagentProtocol(Protocol):
    """
    Structural protocol every subagent must satisfy.

    Attributes:
        name:        Unique identifier (e.g. "admin", "browser", "fs").
                     Used for ``@name`` routing in the TUI and for
                     ``KestAgent.get_subagent(name)``.
        description: One-line summary shown in TUI panels and tool rosters.
    """

    name: str
    description: str

    def get_tools(self) -> List[BaseTool]:
        """Return all LangChain tools this subagent exposes."""
        ...


class SubagentBase:
    """
    Optional convenience base class for subagents.

    Provides ``name`` and ``description`` as instance attributes and a
    default ``get_tools()`` that returns an empty list. Subclasses override
    ``get_tools()`` with their actual tool roster.

    Using ``SubagentBase`` is purely optional — ``KestAgent`` only checks
    structural conformance with ``SubagentProtocol``.
    """

    name: str = ""
    description: str = ""

    def __init__(self, name: str = "", description: str = "") -> None:
        if name:
            self.name = name
        if description:
            self.description = description

    def get_tools(self) -> List[BaseTool]:
        """Override in subclasses to return the subagent's tool roster."""
        return []

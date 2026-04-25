"""ToolProxy — the audited bridge between sandboxed code and the host."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class ToolProxy(ABC):
    """
    Mediates all tool calls from sandboxed code to the host.

    Every call_tool() implementation MUST be decorated with @kest_verified so
    that each tool invocation produces a KestEntry in the lineage chain.

    Taint accumulation:
      - Implementations must merge taints from each tool result into an
        internal set.
      - accumulated_taints is read by SandboxProvider.execute() after the
        script completes and placed into SandboxResult.taints_added.
      - reset() is called by execute() before each run to prevent leakage
        across multiple execute() calls on the same proxy instance.
    """

    @abstractmethod
    async def call_tool(self, tool_name: str, args: dict) -> Any:
        """
        Async tool invocation — primary contract.

        MUST be decorated with @kest_verified in every concrete implementation.
        """

    def call_tool_sync(self, tool_name: str, args: dict) -> Any:
        """
        Synchronous bridge. Delegates to call_tool() via asyncio.run().
        Override for a truly synchronous implementation.
        """
        import asyncio

        return asyncio.run(self.call_tool(tool_name, args))

    @property
    @abstractmethod
    def accumulated_taints(self) -> frozenset[str]:
        """All taints accumulated since last reset()."""

    @abstractmethod
    def reset(self) -> None:
        """Reset accumulated_taints to empty set.
        Called by SandboxProvider at the start of each execute()."""

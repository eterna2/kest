"""
SubagentPanel — A reusable Textual widget that renders one subagent's log.

Each registered subagent in ``KestAgent`` gets its own ``SubagentPanel``
row in ``KestAgentApp``. New panels appear automatically as subagents
are registered.
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import RichLog, Static

from kest.deepagents.subagent import SubagentProtocol


class SubagentPanel(Vertical):
    """
    A vertical panel that displays a subagent's name, description, and log.

    Args:
        subagent: The subagent whose label and events this panel represents.
    """

    DEFAULT_CSS = """
    SubagentPanel {
        height: 1fr;
        border: solid $primary-lighten-2;
        padding: 1;
    }
    SubagentPanel .panel-title {
        color: $accent;
        text-style: bold;
        margin-bottom: 0;
    }
    SubagentPanel .panel-desc {
        color: $text-muted;
        text-style: italic;
        margin-bottom: 1;
    }
    """

    def __init__(self, subagent: SubagentProtocol, panel_id: str | None = None) -> None:
        super().__init__(id=panel_id or f"panel-{subagent.name}")
        self._subagent = subagent
        self._log_id = f"log-{subagent.name}"

    def compose(self) -> ComposeResult:
        yield Static(f"🔹 {self._subagent.name}", classes="panel-title")
        yield Static(self._subagent.description, classes="panel-desc")
        yield RichLog(id=self._log_id, highlight=True, markup=True)

    def write(self, text: str) -> None:
        """Append *text* to this panel's log."""
        self.query_one(f"#{self._log_id}", RichLog).write(text)

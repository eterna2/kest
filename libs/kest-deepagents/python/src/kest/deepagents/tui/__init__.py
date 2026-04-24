"""
kest.deepagents.tui — Optional Textual TUI integration.

This sub-package is only importable when the ``tui`` optional extra is
installed::

    pip install kest-deepagents[tui]
    uv add kest-deepagents[tui]

Importing ``kest.deepagents`` without this extra is unaffected — the root
package never imports from here.

Public surface::

    from kest.deepagents.tui import KestAgentApp
"""

from __future__ import annotations

try:
    import textual  # noqa: F401
except ModuleNotFoundError as _exc:
    raise ModuleNotFoundError(
        "The 'tui' optional dependency is required to use kest.deepagents.tui.\n"
        "Install it with:  uv add 'kest-deepagents[tui]'  "
        "or  pip install 'kest-deepagents[tui]'"
    ) from _exc

from kest.deepagents.tui.app import KestAgentApp
from kest.deepagents.tui.completion import AgentCommandProvider, CommandSuggester
from kest.deepagents.tui.dialogs import MountDialog, SchemeSelectDialog
from kest.deepagents.tui.panels import SubagentPanel

__all__ = [
    "KestAgentApp",
    "CommandSuggester",
    "AgentCommandProvider",
    "MountDialog",
    "SchemeSelectDialog",
    "SubagentPanel",
]

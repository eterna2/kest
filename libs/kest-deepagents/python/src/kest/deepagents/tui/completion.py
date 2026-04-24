"""
kest.deepagents.tui.completion — Command autocomplete for KestAgentApp.

Provides:

* ``CommandSuggester`` — inline ghost-text Textual ``Suggester`` that
  completes ``@<agent> <tool> <arg>=`` token by token as the user types.

* ``AgentCommandProvider`` — Textual ``CommandPalette`` provider (Ctrl+P)
  that shows fuzzy-searchable subagent tools with descriptions.

Both are optional progressive enhancements; the TUI degrades gracefully if
they raise import errors.
"""

from __future__ import annotations

from textual.command import Hit, Hits, Provider
from textual.suggester import Suggester

from kest.deepagents.agent import KestAgent


# ---------------------------------------------------------------------------
# Inline suggester
# ---------------------------------------------------------------------------

_BARE_CMDS = [
    "@admin ",
    "@browser ",
    "@fs ",
    "agents",
    "help",
    "quit",
    "ls ",
    "cat ",
    "head ",
    "tail ",
    "tee ",
    "write ",
    "append ",
    "grep ",
    "exec ",
    "mount ",
    "shell ",
    "info ",
    "mkdir ",
    "rm ",
]


class CommandSuggester(Suggester):
    """
    Context-aware inline autocomplete for the KestAgentApp input bar.

    Completion strategy (evaluated in order):

    1. ``@``  alone → suggest all subagent names as ``@<name> ``
    2. ``@<partial>``  → suggest matching subagent name
    3. ``@<name> ``  → suggest available tool names for that subagent
    4. ``@<name> <partial-tool>`` → suggest matching tool name
    5. ``@<name> <tool> `` → suggest ``<arg>=`` stubs for that tool
    6. Bare prefix → suggest from built-in command list
    """

    def __init__(self, agent: KestAgent) -> None:
        # case_insensitive, no caching (tools can change at runtime)
        super().__init__(use_cache=False, case_sensitive=False)
        self._agent = agent

    async def get_suggestion(self, value: str) -> str | None:  # noqa: C901
        if not value:
            return None

        # --- @-routed subagent commands -----------------------------------------
        if value.startswith("@"):
            payload = value[1:]  # strip leading @
            tokens = payload.split(" ", 2)

            agent_token = tokens[0]
            has_space_after_agent = " " in payload

            # Stage 1/2: still typing the agent name
            if not has_space_after_agent:
                for sa in self._agent.subagents:
                    if sa.name.lower().startswith(agent_token.lower()):
                        if sa.name.lower() != agent_token.lower():
                            return f"@{sa.name} "
                        else:
                            # Exact match — prompt to add a tool
                            return f"@{sa.name} "
                return None

            # We have "@<name> " — look up the subagent
            sa = self._agent.get_subagent(agent_token)
            if sa is None:
                return None

            tool_token = tokens[1] if len(tokens) > 1 else ""
            has_space_after_tool = len(tokens) > 1 and " " in payload[len(agent_token) + 1:]

            # Stage 3/4: typing the tool name
            if not has_space_after_tool:
                for tool in sa.get_tools():
                    if tool.name.lower().startswith(tool_token.lower()):
                        if tool.name.lower() != tool_token.lower():
                            return f"@{agent_token} {tool.name} "
                        else:
                            return f"@{agent_token} {tool.name} "
                return None

            # Stage 5: tool name complete, suggest first arg stub
            tool_name = tokens[1]
            matched_tool = next(
                (t for t in sa.get_tools() if t.name.lower() == tool_name.lower()),
                None,
            )
            if matched_tool is None:
                return None

            arg_stubs = _arg_stubs(matched_tool)
            if not arg_stubs:
                return None

            # Only suggest if no args typed yet
            arg_area = tokens[2] if len(tokens) > 2 else ""
            if not arg_area.strip():
                stub = arg_stubs[0]
                return f"@{agent_token} {tool_name} {stub}"

            # Suggest next arg not yet present
            for stub in arg_stubs:
                key = stub.split("=")[0]
                if key not in arg_area:
                    return f"{value} {stub}"

            return None

        # --- bare commands -------------------------------------------------------
        lower = value.lower()
        for cmd in _BARE_CMDS:
            if cmd.lower().startswith(lower) and cmd.lower() != lower:
                return cmd

        return None


def _arg_stubs(tool: object) -> list[str]:
    """
    Extract ``arg=`` stubs from a LangChain tool's ``args_schema`` (Pydantic model).
    Returns a list like ``["path=", "encoding="]``.
    Falls back to an empty list if no schema is available.
    """
    schema = getattr(tool, "args_schema", None)
    if schema is None:
        return []
    try:
        fields = schema.model_fields  # Pydantic v2
    except AttributeError:
        try:
            fields = schema.__fields__  # Pydantic v1
        except AttributeError:
            return []
    return [f"{name}=" for name in fields]


# ---------------------------------------------------------------------------
# CommandPalette provider (Ctrl+P)
# ---------------------------------------------------------------------------


class AgentCommandProvider(Provider):
    """
    Textual CommandPalette provider that surfaces all registered subagent
    tools as fuzzy-searchable commands with inline descriptions.

    Registered automatically by ``KestAgentApp`` via ``COMMANDS``.
    """

    async def search(self, query: str) -> Hits:
        app = self.app
        agent: KestAgent | None = getattr(app, "agent", None)
        if not isinstance(agent, KestAgent):
            return

        query_lower = query.lower()

        for sa in agent.subagents:
            for tool in sa.get_tools():
                cmd = f"@{sa.name} {tool.name}"
                score = _fuzzy_score(query_lower, cmd.lower())
                if score > 0 or not query:
                    yield Hit(
                        score=score,
                        match_display=cmd,
                        command=lambda c=cmd: _run_command(app, c),
                        help=getattr(tool, "description", ""),
                    )

        # Also surface bare built-in commands
        for bare in ["help", "agents", "quit"]:
            if query_lower in bare or not query:
                yield Hit(
                    score=0.5 if query_lower in bare else 0.1,
                    match_display=bare,
                    command=lambda c=bare: _run_command(app, c),
                    help=f"Built-in: {bare}",
                )


def _fuzzy_score(query: str, candidate: str) -> float:
    """Simple substring / prefix scoring (0.0 = no match)."""
    if not query:
        return 0.1
    if candidate.startswith(query):
        return 1.0
    if query in candidate:
        return 0.7
    # check if all query chars appear in order in candidate
    it = iter(candidate)
    if all(ch in it for ch in query):
        return 0.4
    return 0.0


def _run_command(app: object, cmd: str) -> None:
    """Populate the input bar and submit the chosen command."""
    try:
        from textual.widgets import Input
        inp = app.query_one(Input)  # type: ignore[union-attr]
        inp.value = cmd
        app.query_one(Input).action_submit()  # type: ignore[union-attr]
    except Exception:
        pass

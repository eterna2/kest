"""
CLI entry points for kest-deepagents.

``kest-agent`` is the single entry point — launches the multi-subagent TUI
with ``fs``, ``admin``, and ``browser`` subagents pre-registered.

    kest-agent [--workdir /path/to/sandbox]
"""

from __future__ import annotations


def agent() -> None:
    """Launch the Kest Agent TUI with fs, admin, and browser subagents."""
    try:
        from kest.deepagents.examples.agent_demo import main
    except ModuleNotFoundError as exc:
        if "textual" in str(exc):
            raise SystemExit(
                "The 'tui' optional dependency is required.\n"
                "Install it with:  uv add 'kest-deepagents[tui]'"
            ) from exc
        raise

    main()

"""
Kest Agent TUI — Default multi-subagent demo.

Registers ``fs``, ``admin``, and ``browser`` subagents into a ``KestAgent``
and launches ``KestAgentApp``.  Imported by ``cli.agent()``; also runnable
directly::

    uv run python -m kest.deepagents.examples.agent_demo [--workdir /tmp]
"""

from __future__ import annotations

import argparse
import tempfile
from pathlib import Path

from fsspec.implementations.local import LocalFileSystem

from kest.core import configure
from kest.core.identity import MockIdentityProvider

from kest.deepagents._test_helpers import HardcodedRuleEngine
from kest.deepagents.admin import KestAdminSubagent
from kest.deepagents.agent import KestAgent
from kest.deepagents.browser import BrowserSubagent
from kest.deepagents.fsspec_agent import FsspecAgent
from kest.deepagents.tui import KestAgentApp


# ---------------------------------------------------------------------------
# Demo policy engine
# ---------------------------------------------------------------------------

DEMO_ENGINE = HardcodedRuleEngine(
    blocked_policies=frozenset({"fs_delete_policy"}),
    min_trust=60,
)


# ---------------------------------------------------------------------------
# No-op trace backend for the demo
# ---------------------------------------------------------------------------

class _DemoTraceBackend:
    def get_trace(self, trace_id: str) -> dict:
        return {}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(description="Kest Agent TUI")
    parser.add_argument(
        "--workdir",
        default=None,
        help="Sandbox working directory (default: fresh temp dir)",
    )
    args = parser.parse_args()

    if args.workdir:
        workdir = Path(args.workdir)
        workdir.mkdir(parents=True, exist_ok=True)
        tmp_ctx = None
    else:
        tmp_ctx = tempfile.TemporaryDirectory()
        workdir = Path(tmp_ctx.name)

    # Seed demo files
    (workdir / "notes.txt").write_text("Hello from Kest zero-trust lab!\n")
    (workdir / "config.toml").write_text("[kest]\npolicy = 'fs_read_policy'\n")

    configure(engine=DEMO_ENGINE, identity=MockIdentityProvider())

    agent = KestAgent(
        name="kest-agent",
        subagents=[
            FsspecAgent(
                fs=LocalFileSystem(),
                root=str(workdir),
                allow_shell=True,
                allowed_commands=["echo", "cat", "ls", "git", "python", "uv"],
            ),
            KestAdminSubagent(trace_backend=_DemoTraceBackend()),
            BrowserSubagent(allowed_domains=["localhost", "127.0.0.1"]),
        ],
    )

    try:
        KestAgentApp(agent=agent).run()
    finally:
        configure(clear=True)
        if tmp_ctx:
            tmp_ctx.cleanup()


if __name__ == "__main__":
    main()

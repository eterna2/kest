"""
KestAgentApp — Reusable Textual TUI for any KestAgent.

Renders a dynamic multi-column layout: one log panel per registered
subagent, flanked by a unified output column (left) and a Merkle audit
trail column (right). New subagent columns appear automatically when
subagents are registered before the app starts.

Usage::

    from kest.deepagents.agent import KestAgent
    from kest.deepagents.admin import KestAdminSubagent
    from kest.deepagents.browser import BrowserSubagent
    from kest.deepagents.fsspec_agent import FsspecAgent
    from kest.deepagents.tui import KestAgentApp

    agent = KestAgent(subagents=[
        fs_agent,
        KestAdminSubagent(trace_backend=backend),
        BrowserSubagent(allowed_domains=["github.com"]),
    ])
    KestAgentApp(agent=agent).run()

Command routing
---------------
Commands can be prefixed with ``@<subagent-name>`` to route output to a
specific subagent panel::

    @admin list_policies
    @browser navigate url=https://github.com

Un-prefixed commands are dispatched to the built-in filesystem command
handler (backward-compatible with the original terminal demo) if an ``fs``
subagent is registered; otherwise they fall through to ``help``.

Extensibility
-------------
Override ``_dispatch_custom(cmd, args)`` in a subclass to add application-
specific commands without touching the base routing logic.
"""

from __future__ import annotations

import json
from typing import Any, Optional

from textual import work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Footer, Header, Input, RichLog, Static

from kest.deepagents.agent import KestAgent
from kest.deepagents.tui.completion import AgentCommandProvider, CommandSuggester
from kest.deepagents.tui.panels import SubagentPanel


class KestAgentApp(App):
    """
    Reusable Textual TUI for any ``KestAgent``.

    Args:
        agent: A ``KestAgent`` with subagents already registered.
        title: Optional header title (defaults to ``agent.name``).
    """

    CSS = """
    Screen {
        background: $surface;
        layout: vertical;
    }
    Header {
        background: $primary;
        color: $text;
    }
    /* Stack of output rows fills all available space above the input */
    #rows {
        height: 1fr;
    }
    /* Unified output row — taller than the others */
    #output-row {
        height: 3fr;
        border: solid $primary-lighten-2;
        padding: 1;
    }
    /* Audit trail row */
    #audit-row {
        height: 1fr;
        border: solid $primary-lighten-2;
        padding: 1;
    }
    #input-area {
        height: auto;
        border-top: solid $primary-lighten-2;
        padding: 1;
    }
    .panel-title {
        color: $accent;
        text-style: bold;
        margin-bottom: 1;
    }
    #fs-banner {
        color: $success;
        text-style: bold;
        margin-bottom: 1;
    }
    #fs-banner.shell-off {
        color: $warning;
    }
    Input {
        width: 1fr;
    }
    """

    BINDINGS = [("ctrl+q", "quit", "Quit"), ("ctrl+c", "quit", "Quit")]
    COMMANDS = App.COMMANDS | {AgentCommandProvider}

    def __init__(self, agent: KestAgent, title: Optional[str] = None) -> None:
        super().__init__()
        self.agent = agent
        self._title = title or agent.name

    # ------------------------------------------------------------------
    # Compose — dynamic layout
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical(id="rows"):
            # Top row: unified output (taller)
            with Vertical(id="output-row"):
                yield Static("📟  Output", classes="panel-title")
                fs = self._fs_agent()
                if fs is not None:
                    yield Static(self._fs_label(fs), id="fs-banner")
                yield RichLog(id="output", highlight=True, markup=True)

            # One row per subagent (equal height)
            for sa in self.agent.subagents:
                yield SubagentPanel(sa)

            # Bottom row: Merkle audit trail
            with Vertical(id="audit-row"):
                yield Static("⛓   Merkle audit trail", classes="panel-title")
                yield RichLog(id="audit_log", highlight=True, markup=True)

        with Horizontal(id="input-area"):
            yield Input(
                placeholder="> type a command  (@admin list_policies | ctrl+p to search | ctrl+q to quit)",
                suggester=CommandSuggester(self.agent),
            )
        yield Footer()

    def on_mount(self) -> None:
        subagent_list = ", ".join(
            f"[bold]{sa.name}[/]" for sa in self.agent.subagents
        ) or "[dim]none[/]"
        banner = (
            f"[bold green]🔒 {self._title}[/]  — Zero-Trust Multi-Agent TUI\n"
            f"Subagents: {subagent_list}\n"
            "─" * 40
        )
        self._echo(banner)
        self._write_audit("[dim]No entries yet.[/]")
        self.query_one(Input).focus()

    # ------------------------------------------------------------------
    # Input handler
    # ------------------------------------------------------------------

    def on_input_submitted(self, event: Input.Submitted) -> None:
        raw = event.value.strip()
        event.input.clear()
        if not raw:
            return

        # HITL mount confirmation (only when fs subagent is active)
        fs = self._fs_agent()
        if fs is not None and hasattr(self, "_mount_params") and self._mount_params is not None:
            if raw.lower() in ("y", "yes"):
                params = {**self._mount_params, "confirmed": "true"}
                scheme = params.pop("_scheme")
                self._mount_params = None
                self._execute_mount(fs, scheme, params)
                return
            if raw.lower() in ("n", "no", "q"):
                self._mount_params = None
                self._echo("[dim]Mount cancelled.[/]")
                return

        self._dispatch(raw)

    def _dispatch(self, raw: str) -> None:
        """Route a raw command string."""
        self._echo(f"[bold cyan]>[/] {raw}")

        # @subagent-name routing
        if raw.startswith("@"):
            self._dispatch_subagent_command(raw)
            return

        parts = raw.split()
        cmd = parts[0].lower()
        args = parts[1:]

        if cmd in ("quit", "exit", "q"):
            self.exit()
        elif cmd == "help":
            self._show_help()
        elif cmd == "agents":
            self._show_agents()
        else:
            # Try fs-agent built-in commands for backward compatibility
            fs = self._fs_agent()
            if fs is not None:
                if self._dispatch_fs(cmd, args, fs):
                    return
            # Try custom extension point
            if not self._dispatch_custom(cmd, args):
                self._echo(
                    f"[red]Unknown command:[/] {cmd}  "
                    f"(type [bold]help[/] or [bold]agents[/])"
                )

    def _dispatch_subagent_command(self, raw: str) -> None:
        """Handle ``@name tool arg=val ...`` routing."""
        parts = raw[1:].split(maxsplit=1)
        sa_name = parts[0]
        rest = parts[1] if len(parts) > 1 else ""

        sa = self.agent.get_subagent(sa_name)
        if sa is None:
            self._echo(
                f"[red]No subagent named '[bold]{sa_name}[/]'.[/] "
                f"Type [bold]agents[/] to list registered subagents."
            )
            return

        panel = self._subagent_panel(sa_name)
        if not rest:
            # No tool specified — list available tools
            tool_names = [t.name for t in sa.get_tools()]
            msg = (
                f"[bold]{sa_name}[/] tools: "
                + (", ".join(f"[cyan]{n}[/]" for n in tool_names) or "[dim]none[/]")
            )
            self._echo(msg)
            if panel:
                panel.write(msg)
            return

        # Parse: first token = tool name, rest = key=value pairs
        toks = rest.split()
        tool_name = toks[0]
        kwargs: dict[str, Any] = {}
        for tok in toks[1:]:
            if "=" in tok:
                k, _, v = tok.partition("=")
                kwargs[k.strip()] = v.strip()
            else:
                # positional token — use as unnamed string arg
                kwargs.setdefault("_positional", []).append(tok)  # type: ignore[arg-type]

        # Find the tool in the subagent
        tools = {t.name: t for t in sa.get_tools()}
        lc_tool = tools.get(tool_name)
        if lc_tool is None:
            self._echo(
                f"[red]No tool '[bold]{tool_name}[/]' in subagent '[bold]{sa_name}[/]'.[/]"
            )
            return

        self._run_subagent_tool(sa_name, tool_name, lc_tool, kwargs)

    # ------------------------------------------------------------------
    # Fs-agent dispatch (backward-compatible)
    # ------------------------------------------------------------------

    def _dispatch_fs(self, cmd: str, args: list[str], fs: Any) -> bool:
        """
        Dispatch built-in filesystem commands.

        Returns ``True`` if the command was handled, ``False`` otherwise.
        """
        from kest.deepagents.fsspec_agent import FsspecAgent
        if not isinstance(fs, FsspecAgent):
            return False

        if cmd == "cat":
            self._run_tool(fs, "cat", {"path": args[0] if args else "."})
        elif cmd == "tee":
            path = args[0] if args else "out.txt"
            content = " ".join(args[1:]) if len(args) > 1 else ""
            self._run_tool(fs, "tee", {"path": path, "content": content})
        elif cmd == "ls":
            self._run_tool(fs, "ls", {"path": args[0] if args else "."})
        elif cmd == "rm":
            self._run_tool(fs, "rm", {"path": args[0] if args else ""})
        elif cmd == "grep":
            pattern = args[0] if args else ""
            path = args[1] if len(args) > 1 else "."
            self._run_tool(fs, "grep", {"pattern": pattern, "path": path})
        elif cmd == "exec":
            command = args[0] if args else ""
            argv = args[1:] if len(args) > 1 else []
            self._run_tool(fs, "exec", {"command": command, "argv": argv})
        elif cmd == "mount":
            scheme = args[0] if args else None
            self._start_mount(fs, scheme)
        elif cmd == "shell":
            self._cmd_shell(fs, args[0].lower() if args else "status")
        else:
            return False
        return True

    def _dispatch_custom(self, cmd: str, args: list[str]) -> bool:
        """
        Override in subclasses to handle application-specific commands.

        Return ``True`` if handled, ``False`` to fall through to the
        'unknown command' error message.
        """
        return False

    # ------------------------------------------------------------------
    # Mount HITL (delegated from fs dispatch)
    # ------------------------------------------------------------------

    def _start_mount(self, fs_agent: Any, scheme: Optional[str]) -> None:
        """Entry point for interactive mount (scheme selection → param dialog)."""
        from kest.deepagents.tui.dialogs import SchemeSelectDialog

        if scheme is None:
            self.push_screen(
                SchemeSelectDialog(),
                callback=lambda s: self._on_scheme_selected(fs_agent, s),
            )
        else:
            self._on_scheme_selected(fs_agent, scheme)

    def _on_scheme_selected(self, fs_agent: Any, scheme: Optional[str]) -> None:
        from kest.deepagents.fsspec_agent import FILESYSTEM_REGISTRY
        if not scheme:
            self._echo("[dim]Mount cancelled.[/]")
            return
        spec = FILESYSTEM_REGISTRY.get(scheme)
        if not spec:
            self._echo(f"[red]Unknown scheme:[/] '{scheme}'.")
            return
        if spec.import_check:
            import importlib
            try:
                importlib.import_module(spec.import_check)
            except ModuleNotFoundError:
                self._echo(
                    f"[red]Missing driver:[/] install [dim]kest-deepagents[{scheme}][/]"
                )
                return
        try:
            from kest.deepagents.tui.dialogs import MountDialog
        except ImportError:
            self._echo("[yellow]MountDialog not available.[/]")
            return
        self.push_screen(
            MountDialog(scheme, list(spec.params), {}, set()),
            callback=lambda c: self._on_params_collected(fs_agent, scheme, c),
        )

    def _on_params_collected(
        self, fs_agent: Any, scheme: str, collected: Optional[dict]
    ) -> None:
        if collected is None:
            self._echo("[dim]Mount cancelled.[/]")
            return
        self._request_confirmation(fs_agent, scheme, collected)

    @work(thread=True)
    def _request_confirmation(
        self, fs_agent: Any, scheme: str, provided: dict
    ) -> None:
        try:
            raw = fs_agent.get_mount_tool().invoke({
                "scheme": scheme,
                "params": json.dumps(provided),
            })
            resp = json.loads(raw)
        except (ValueError, PermissionError, RuntimeError) as exc:
            self.call_from_thread(self._echo, f"[red]Mount error:[/] {exc}")
            return
        self.call_from_thread(
            self._handle_mount_response, resp, fs_agent, scheme, provided
        )

    def _handle_mount_response(
        self, resp: dict, fs_agent: Any, scheme: str, provided: dict
    ) -> None:
        from kest.deepagents.fsspec_agent import FILESYSTEM_REGISTRY
        rtype = resp.get("type")
        if rtype == "ImportError":
            self._echo(f"[red]Missing driver:[/]\n{resp['message']}")
        elif rtype == "ParamRequest":
            spec = FILESYSTEM_REGISTRY.get(scheme)
            all_params = list(spec.params) if spec else []
            missing_names = {m["name"] for m in resp.get("missing", [])}
            self._echo(
                "[yellow]⚠ Required fields missing:[/] "
                + ", ".join(f"[bold]{n}[/]" for n in missing_names)
            )
            try:
                from kest.deepagents.tui.dialogs import MountDialog
                self.push_screen(
                    MountDialog(scheme, all_params, provided, missing_names),
                    callback=lambda c: self._on_params_collected(fs_agent, scheme, c),
                )
            except ImportError:
                pass
        elif rtype == "ConfirmRequest":
            summary = resp.get("summary", "")
            self._echo(
                f"[yellow]⚠ Confirm filesystem switch:[/]\n"
                f"  {summary}\n"
                "[dim]Type [bold]y[/] to confirm or [bold]n[/] to cancel.[/]"
            )
            self._mount_params = {**provided, "_scheme": scheme}
        elif rtype == "MountResult":
            proto = resp.get("protocol", scheme)
            root = resp.get("root", ".")
            shell_disabled = resp.get("shell_disabled", False)
            self._echo(f"[green]✅ Mounted:[/] [bold]{proto}::{root}[/]")
            if shell_disabled:
                self._echo(
                    "[bold yellow]⚠  Shell execution DISABLED (remote FS).[/]\n"
                    "   Mount a local filesystem then type [bold]shell on[/] to re-enable."
                )
            self._write_audit(f"[bold]mount_fs[/]  {proto}::{root}")
            self._update_fs_banner(fs_agent)
        else:
            self._echo(f"[red]Unexpected mount response:[/] {resp}")

    @work(thread=True)
    def _execute_mount(self, fs_agent: Any, scheme: str, params: dict) -> None:
        params_with_confirm = {**params, "confirmed": "true"}
        try:
            raw = fs_agent.get_mount_tool().invoke({
                "scheme": scheme,
                "params": json.dumps(params_with_confirm),
            })
            resp = json.loads(raw)
        except (PermissionError, RuntimeError) as exc:
            self.call_from_thread(self._echo, f"[red]Mount denied:[/] {exc}")
            return
        self.call_from_thread(
            self._handle_mount_response, resp, fs_agent, scheme, params
        )

    def _cmd_shell(self, fs_agent: Any, sub: str) -> None:
        from fsspec.implementations.local import LocalFileSystem
        if sub == "status":
            state = "[green]ON[/]" if fs_agent.allow_shell else "[yellow]OFF[/]"
            self._echo(f"Shell execution: {state}")
        elif sub == "off":
            fs_agent.allow_shell = False
            self._echo("[yellow]⚠ Shell execution disabled.[/]")
            self._update_fs_banner(fs_agent)
        elif sub == "on":
            if not isinstance(fs_agent.fs, LocalFileSystem):
                self._echo(
                    "[red]❌ Cannot enable shell:[/] active filesystem is remote. "
                    "Mount a local filesystem first."
                )
                return
            if not fs_agent.allowed_commands:
                self._echo("[red]❌ No allowed_commands configured.[/]")
                return
            fs_agent.allow_shell = True
            self._echo("[green]✅ Shell execution enabled.[/]")
            self._update_fs_banner(fs_agent)
        else:
            self._echo(f"[red]Unknown shell sub-command:[/] '{sub}'  (on | off | status)")

    # ------------------------------------------------------------------
    # Background workers
    # ------------------------------------------------------------------

    @work(thread=True)
    def _run_tool(self, fs_agent: Any, cmd: str, kwargs: dict[str, Any]) -> None:
        tool_map = {
            "cat":  fs_agent.get_cat_tool,
            "tee":  fs_agent.get_tee_tool,
            "ls":   fs_agent.get_ls_tool,
            "rm":   fs_agent.get_rm_tool,
            "grep": fs_agent.get_grep_tool,
            "exec": fs_agent.get_exec_tool,
        }
        getter = tool_map.get(cmd)
        if getter is None:
            self.call_from_thread(self._echo, f"[red]No tool for:[/] {cmd}")
            return
        try:
            lc_tool = getter()
        except RuntimeError as exc:
            self.call_from_thread(self._echo, f"[red]Tool disabled:[/] {exc}")
            return
        try:
            result = lc_tool.invoke(kwargs)
            self.call_from_thread(self._on_tool_success, cmd, result)
        except PermissionError as exc:
            self.call_from_thread(self._on_tool_denied, cmd, str(exc))
        except Exception as exc:
            self.call_from_thread(self._echo, f"[red]Error:[/] {exc}")

    @work(thread=True)
    def _run_subagent_tool(
        self, sa_name: str, tool_name: str, lc_tool: Any, kwargs: dict[str, Any]
    ) -> None:
        try:
            result = lc_tool.invoke(kwargs)
            self.call_from_thread(
                self._on_subagent_tool_success, sa_name, tool_name, str(result)
            )
        except PermissionError as exc:
            self.call_from_thread(
                self._on_subagent_tool_denied, sa_name, tool_name, str(exc)
            )
        except Exception as exc:
            self.call_from_thread(
                self._echo, f"[red]Error in @{sa_name}.{tool_name}:[/] {exc}"
            )

    # ------------------------------------------------------------------
    # UI update helpers
    # ------------------------------------------------------------------

    def _on_tool_success(self, cmd: str, result: str) -> None:
        self._echo(f"[green]✅ {cmd}[/]\n{result}")
        self._write_audit(f"[bold]{cmd}[/]  [dim]ALLOW[/]")
        panel = self._subagent_panel("fs")
        if panel:
            panel.write(f"[green]✅ ALLOW[/]  [bold]{cmd}[/]")

    def _on_tool_denied(self, cmd: str, reason: str) -> None:
        self._echo(f"[red]❌ {cmd} denied[/]\n[dim]{reason}[/]")
        self._write_audit(f"[bold red]{cmd}[/]  [dim]BLOCKED[/]")
        panel = self._subagent_panel("fs")
        if panel:
            panel.write(f"[red]❌ DENY[/]   [bold]{cmd}[/]")

    def _on_subagent_tool_success(
        self, sa_name: str, tool_name: str, result: str
    ) -> None:
        self._echo(f"[green]✅ @{sa_name}.{tool_name}[/]\n{result}")
        self._write_audit(f"[bold]{sa_name}.{tool_name}[/]  [dim]ALLOW[/]")
        panel = self._subagent_panel(sa_name)
        if panel:
            panel.write(f"[green]✅ ALLOW[/]  [bold]{tool_name}[/]\n[dim]{result[:200]}[/]")

    def _on_subagent_tool_denied(
        self, sa_name: str, tool_name: str, reason: str
    ) -> None:
        self._echo(f"[red]❌ @{sa_name}.{tool_name} denied[/]\n[dim]{reason}[/]")
        self._write_audit(f"[bold red]{sa_name}.{tool_name}[/]  [dim]BLOCKED[/]")
        panel = self._subagent_panel(sa_name)
        if panel:
            panel.write(f"[red]❌ DENY[/]   [bold]{tool_name}[/]")

    def _subagent_panel(self, name: str) -> Optional[SubagentPanel]:
        """Return the panel for subagent *name*, or None if absent."""
        try:
            return self.query_one(f"#panel-{name}", SubagentPanel)
        except Exception:
            return None

    def _fs_agent(self) -> Optional[Any]:
        """Return the registered FsspecAgent, if any."""
        from kest.deepagents.fsspec_agent import FsspecAgent
        sa = self.agent.get_subagent("fs")
        return sa if isinstance(sa, FsspecAgent) else None

    def _fs_label(self, fs_agent: Any) -> str:
        shell_indicator = (
            " [green]🖥 shell:on[/]" if fs_agent.allow_shell
            else " [yellow]🔒 shell:off[/]"
        )
        return f"📂 Active FS: [bold]{fs_agent.protocol}::{fs_agent.root}[/]{shell_indicator}"

    def _update_fs_banner(self, fs_agent: Any) -> None:
        try:
            banner = self.query_one("#fs-banner", Static)
            banner.update(self._fs_label(fs_agent))
            if fs_agent.allow_shell:
                banner.remove_class("shell-off")
            else:
                banner.add_class("shell-off")
        except Exception:
            pass

    def _echo(self, text: str) -> None:
        self.query_one("#output", RichLog).write(text)

    def _write_audit(self, text: str) -> None:
        self.query_one("#audit_log", RichLog).write(text)

    # ------------------------------------------------------------------
    # Help
    # ------------------------------------------------------------------

    def _show_agents(self) -> None:
        lines = ["[bold]Registered subagents:[/]"]
        for sa in self.agent.subagents:
            tools = ", ".join(t.name for t in sa.get_tools())
            lines.append(
                f"  [cyan]@{sa.name}[/]  [dim]{sa.description}[/]\n"
                f"    tools: {tools or '(none)'}"
            )
        self._echo("\n".join(lines))

    def _show_help(self) -> None:
        help_text = (
            "[bold]Subagent routing:[/]\n"
            "  [cyan]@<name>[/]                    list tools for subagent\n"
            "  [cyan]@<name> <tool> [k=v ...][/]   invoke tool with kwargs\n"
            "  [cyan]agents[/]                     show all registered subagents\n\n"
            "[bold]Filesystem commands (if 'fs' subagent registered):[/]\n"
            "  [cyan]cat[/] <path>  [cyan]ls[/] [path]  [cyan]tee[/] <path> <content>  [cyan]rm[/] <path>\n"
            "  [cyan]grep[/] <pattern> [path]  [cyan]exec[/] <cmd> [argv...]\n"
            "  [cyan]mount[/] [scheme]  [cyan]shell[/] on|off|status\n\n"
            "[bold]General:[/]\n"
            "  [cyan]help[/]  [cyan]quit[/] / [cyan]exit[/]\n"
        )
        self._echo(help_text)

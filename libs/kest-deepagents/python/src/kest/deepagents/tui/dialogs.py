"""
kest.deepagents.tui.dialogs — Textual modal screens for interactive filesystem mounting.

``MountDialog`` and ``SchemeSelectDialog`` are reusable Textual ModalScreens
used by ``KestAgentApp`` to collect filesystem credentials at runtime.
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, Select

from kest.deepagents.fsspec_agent import FILESYSTEM_REGISTRY, ParamSpec


class MountDialog(ModalScreen["dict[str, str] | None"]):
    """
    Modal form for reviewing and editing all filesystem connection parameters.

    Shows every field registered for the chosen scheme, pre-filled with
    already-provided values (falling back to defaults). Password fields are
    masked. Required fields that have no value are highlighted in red.

    Returns a ``dict[str, str]`` of collected values on submit, or ``None``
    on cancel.
    """

    DEFAULT_CSS = """
    MountDialog {
        align: center middle;
    }
    #mount-dialog {
        width: 62;
        height: auto;
        max-height: 85%;
        border: thick $primary;
        background: $surface;
        padding: 1 2;
    }
    #mount-dialog Label {
        margin-top: 1;
        color: $text-muted;
    }
    #mount-dialog Input {
        margin-bottom: 0;
    }
    .param-required {
        color: $error;
        text-style: bold;
    }
    .param-optional {
        color: $text-muted;
        text-style: italic;
    }
    #mount-title {
        color: $accent;
        text-style: bold;
        margin-bottom: 1;
    }
    #mount-hint {
        color: $text-muted;
        text-style: italic;
        margin-bottom: 1;
    }
    #mount-buttons {
        margin-top: 1;
        height: 3;
        align-horizontal: right;
    }
    #mount-buttons Button {
        margin-left: 1;
    }
    """

    def __init__(
        self,
        scheme: str,
        all_params: list[ParamSpec],
        provided: dict[str, str],
        missing_names: set[str] | None = None,
    ) -> None:
        """
        Args:
            scheme:        fsspec protocol name.
            all_params:    Every ``ParamSpec`` for this scheme from the registry.
            provided:      Already-collected values (e.g. from a previous attempt).
            missing_names: Names of required fields that still lack a value;
                           used to highlight fields in red on re-display.
        """
        super().__init__()
        self.scheme = scheme
        self.all_params = all_params
        self.provided = provided
        self.missing_names: set[str] = missing_names or set()
        spec = FILESYSTEM_REGISTRY.get(scheme)
        self._spec_label = spec.label if spec else scheme

    def compose(self) -> ComposeResult:
        with Vertical(id="mount-dialog"):
            yield Label(
                f"🔗 Mount: {self._spec_label} ({self.scheme})",
                id="mount-title",
            )
            yield Label(
                "Review and edit all connection parameters, then click Connect.",
                id="mount-hint",
            )
            for p in self.all_params:
                is_missing = p.name in self.missing_names
                label_css = "param-required" if is_missing else ("param-optional" if not p.required else "")
                suffix = "  ✕ required" if is_missing else ("  (optional)" if not p.required else "")
                yield Label(p.label + suffix, classes=label_css)
                yield Input(
                    value=str(self.provided.get(p.name, p.default or "")),
                    placeholder=p.label,
                    password=p.password,
                    id=f"mount-param-{p.name}",
                )

            yield Label("Root  (directory path or bucket name)")
            yield Input(
                value=str(self.provided.get("root", ".")),
                placeholder="/path  or  bucket-name",
                id="mount-param-root",
            )

            with Horizontal(id="mount-buttons"):
                yield Button("Cancel", variant="default", id="mount-cancel")
                yield Button("Connect →", variant="primary", id="mount-submit")

    def on_mount(self) -> None:
        for p in self.all_params:
            widget = self.query_one(f"#mount-param-{p.name}", Input)
            if p.name in self.missing_names or not widget.value:
                widget.focus()
                return
        self.query_one("#mount-param-root", Input).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "mount-cancel":
            self.dismiss(None)
            return

        collected: dict[str, str] = {}
        for p in self.all_params:
            widget = self.query_one(f"#mount-param-{p.name}", Input)
            val = widget.value.strip()
            if val:
                collected[p.name] = val
            elif p.default:
                collected[p.name] = p.default
        root_widget = self.query_one("#mount-param-root", Input)
        collected["root"] = root_widget.value.strip() or "."
        self.dismiss(collected)


class SchemeSelectDialog(ModalScreen["str | None"]):
    """
    Ask the user to choose a filesystem scheme when ``mount`` is typed without
    arguments. Returns the scheme string, or ``None`` if cancelled.
    """

    DEFAULT_CSS = """
    SchemeSelectDialog {
        align: center middle;
    }
    #scheme-dialog {
        width: 50;
        height: auto;
        border: thick $primary;
        background: $surface;
        padding: 1 2;
    }
    #scheme-title {
        color: $accent;
        text-style: bold;
        margin-bottom: 1;
    }
    #scheme-select { margin-bottom: 1; }
    #scheme-buttons {
        height: 3;
        align-horizontal: right;
    }
    #scheme-buttons Button { margin-left: 1; }
    """

    def compose(self) -> ComposeResult:
        options = [(spec.label, scheme) for scheme, spec in FILESYSTEM_REGISTRY.items()]
        with Vertical(id="scheme-dialog"):
            yield Label("🔗 Choose filesystem", id="scheme-title")
            yield Select(options, id="scheme-select")
            with Horizontal(id="scheme-buttons"):
                yield Button("Cancel", variant="default", id="scheme-cancel")
                yield Button("Select →", variant="primary", id="scheme-ok")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "scheme-cancel":
            self.dismiss(None)
            return
        sel = self.query_one("#scheme-select", Select)
        if sel.value is Select.BLANK:
            self.dismiss(None)
        else:
            self.dismiss(str(sel.value))

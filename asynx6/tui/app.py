"""Textual-based interactive dashboard.

New in V2. Optional — only enabled when --tui flag is passed and textual is
installed.
"""

from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger(__name__)

try:
    from textual.app import App, ComposeResult
    from textual.containers import Vertical
    from textual.widgets import Button, DataTable, Footer, Header, Input, RichLog, Static
    TEXTUAL_AVAILABLE = True
except ImportError:  # pragma: no cover
    TEXTUAL_AVAILABLE = False


_INSTALL_HINT = ("textual is not installed. Install with: "
                 "`pip install textual` to enable the TUI dashboard.")


def require_textual() -> None:
    """Raise ImportError with install hint when textual is missing."""
    if not TEXTUAL_AVAILABLE:
        raise ImportError(_INSTALL_HINT)


if TEXTUAL_AVAILABLE:

    class Asynx6App(App):
        """Interactive Textual dashboard for Asynx6 Web Scanner V2."""

        CSS = """
        Screen { background: $surface; }
        #title { content-align: center middle; text-style: bold; color: $accent; }
        #log { height: 1fr; border: solid $primary; }
        #results { height: 30%; }
        """

        BINDINGS = [("q", "quit", "Quit")]

        def __init__(self, target: str = "", aggressive: bool = False) -> None:
            super().__init__()
            self.target = target
            self.aggressive = aggressive

        def compose(self) -> ComposeResult:
            yield Header(show_clock=True)
            yield Static("🎯 Asynx6 V2 Dashboard", id="title")
            with Vertical():
                yield Input(placeholder="Target URL", value=self.target, id="target")
                yield Button("Start Scan", id="start", variant="primary")
                yield RichLog(id="log", highlight=True, markup=True, wrap=True)
                yield DataTable(id="results", zebra_stripes=True)
            yield Footer()

        def on_mount(self) -> None:
            table = self.query_one("#results", DataTable)
            table.add_columns("Severity", "Type", "Location")

        def on_button_pressed(self, event: Any) -> None:
            if event.button.id == "start":
                target = self.query_one("#target", Input).value
                self.query_one("#log", RichLog).write(
                    f"[bold cyan]Starting scan against {target}...[/]"
                )
                # Real implementation would spawn an Orchestrator here
                self.query_one("#log", RichLog).write(
                    "[yellow]Scan dispatched (stub). Run with --no-tui for CLI mode.[/]"
                )

else:  # pragma: no cover
    Asynx6App = None  # type: ignore[assignment]
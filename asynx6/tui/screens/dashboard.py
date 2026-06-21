"""Dashboard screen stub."""

from __future__ import annotations

try:
    from textual.containers import Container
except ImportError:  # pragma: no cover
    Container = object  # type: ignore[assignment,misc]


class DashboardScreen(Container):  # type: ignore[misc,valid-type]
    """Placeholder dashboard screen."""

    def compose(self):  # pragma: no cover - requires textual
        from textual.widgets import Static
        yield Static("Asynx6 Dashboard")
"""Results screen stub."""

from __future__ import annotations

try:
    from textual.containers import Container
except ImportError:  # pragma: no cover
    Container = object  # type: ignore[assignment,misc]


class ResultsScreen(Container):  # type: ignore[misc,valid-type]
    """Placeholder results screen."""

    def compose(self):  # pragma: no cover - requires textual
        from textual.widgets import DataTable
        yield DataTable()
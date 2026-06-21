"""Log stream widget stub."""

from __future__ import annotations

try:
    from textual.widgets import RichLog
except ImportError:  # pragma: no cover
    RichLog = object  # type: ignore[assignment,misc]


class LogStream(RichLog):  # type: ignore[misc,valid-type]
    """RichLog-derived widget for streaming log output."""

    pass
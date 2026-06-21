"""Structured logging setup with Rich sink and sensitive-data redaction."""

from __future__ import annotations

import logging
import re
from logging.handlers import RotatingFileHandler
from pathlib import Path

from rich.logging import RichHandler


_SENSITIVE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r'x-api-key\s*[:=]\s*["\']?[a-zA-Z0-9_\-]+["\']?', re.I),
     "x-api-key: [REDACTED]"),
    (re.compile(r'password\s*[:=]\s*["\']?[a-zA-Z0-9_\-]+["\']?', re.I),
     "password: [REDACTED]"),
    (re.compile(r'authorization\s*[:]\s*bearer\s+[a-zA-Z0-9\._\-]+', re.I),
     "Authorization: Bearer [REDACTED]"),
]


class _RedactionFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:  # type: ignore[override]
        msg = str(record.msg)
        for pattern, replacement in _SENSITIVE_PATTERNS:
            msg = pattern.sub(replacement, msg)
        record.msg = msg
        record.args = ()
        return True


def setup_logging(log_dir: Path | str, *, level: int = logging.INFO) -> Path:
    """Configure root logger with a rotating file handler and Rich console sink.

    Returns the path of the log file.
    """
    log_dir = Path(log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "audit.log"

    root = logging.getLogger()
    root.setLevel(level)
    # Wipe out handlers installed by other libs (urllib3, requests).
    for handler in list(root.handlers):
        root.removeHandler(handler)

    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    fh = RotatingFileHandler(log_file, maxBytes=2_000_000, backupCount=3,
                             encoding="utf-8")
    fh.setFormatter(formatter)
    fh.addFilter(_RedactionFilter())
    root.addHandler(fh)

    rh = RichHandler(rich_tracebacks=True, markup=True, show_path=False)
    rh.setFormatter(logging.Formatter("%(message)s"))
    root.addHandler(rh)

    return log_file

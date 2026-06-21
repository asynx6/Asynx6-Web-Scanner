"""Local File Inclusion scanner."""

from __future__ import annotations

import logging
from typing import Any

from asynx6.core.http import HttpClient
from asynx6.core.models import Finding, Severity

log = logging.getLogger(__name__)

_PAYLOADS = ["/etc/passwd", "../../../../etc/passwd", "C:\\Windows\\win.ini"]
_MARKERS = ("root:x:0:0:", "[extensions]")


def run(url: str, *, client: HttpClient, **_kwargs: Any) -> list[Finding]:
    """Probe `?file=` for arbitrary file read."""
    findings: list[Finding] = []
    sep = "&" if "?" in url else "?"
    for payload in _PAYLOADS:
        r = client.get(f"{url}{sep}file={payload}")
        if r is None:
            continue
        if any(marker in r.text for marker in _MARKERS):
            findings.append(Finding(
                type="Local File Inclusion",
                severity=Severity.CRITICAL,
                confidence=95,
                location=f"{url}{sep}file={payload}",
                payload=payload,
                description=f"Arbitrary file read confirmed. Path: {payload}",
                remediation="Whitelist allowed paths; never pass user input to FS.",
            ))
            return findings
    return findings

"""Security header audit."""

from __future__ import annotations

import logging
from typing import Any

from asynx6.core.http import HttpClient
from asynx6.core.models import Finding, Severity

log = logging.getLogger(__name__)

_REQ_HEADERS = {
    "Content-Security-Policy": Severity.HIGH,
    "Strict-Transport-Security": Severity.MEDIUM,
    "X-Frame-Options": Severity.LOW,
    "X-Content-Type-Options": Severity.LOW,
}
_LEAKY = ("Server", "X-Powered-By", "X-AspNet-Version", "X-Runtime")


def run(url: str, *, client: HttpClient, **_kwargs: Any) -> list[Finding]:
    findings: list[Finding] = []
    r = client.get(url)
    if r is None:
        return findings
    for h, sev in _REQ_HEADERS.items():
        if h not in r.headers:
            findings.append(Finding(
                type=f"Missing {h}",
                severity=sev,
                location=url,
                description=f"Security header {h} is not set.",
            ))
    for h in _LEAKY:
        if h in r.headers:
            findings.append(Finding(
                type="Information Exposure",
                severity=Severity.LOW,
                location=url,
                description=f"Header '{h}' discloses: {r.headers[h]}",
            ))
    return findings

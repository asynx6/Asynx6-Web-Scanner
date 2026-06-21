"""CORS misconfiguration scanner."""

from __future__ import annotations

import logging
from typing import Any

from asynx6.core.http import HttpClient
from asynx6.core.models import Finding, Severity

log = logging.getLogger(__name__)

_ORIGIN = "https://evil.example.com"


def run(url: str, *, client: HttpClient, **_kwargs: Any) -> list[Finding]:
    findings: list[Finding] = []
    r = client.get(url, headers={"Origin": _ORIGIN})
    if r is None:
        return findings
    aco = r.headers.get("Access-Control-Allow-Origin", "")
    if aco == "*":
        findings.append(Finding(
            type="CORS wildcard",
            severity=Severity.MEDIUM,
            confidence=90,
            location=url,
            description="Access-Control-Allow-Origin is '*'.",
            remediation="Restrict CORS to a known allowlist of origins.",
        ))
    elif aco == _ORIGIN:
        findings.append(Finding(
            type="CORS arbitrary origin reflected",
            severity=Severity.HIGH,
            confidence=95,
            location=url,
            description="Server reflects arbitrary Origin header in ACAO.",
            remediation="Validate Origin against an allowlist.",
        ))
    return findings

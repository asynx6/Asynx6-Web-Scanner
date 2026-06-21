"""Open redirect chain detector.

New in V2. Probes `?url=`, `?next=`, `?return=`, `?redirect=` for unvalidated
redirects, including allowlist bypass via `@` and `//` schemes.
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

from asynx6.core.http import HttpClient
from asynx6.core.models import Finding, Severity

log = logging.getLogger(__name__)

_PARAMS = ("url", "next", "return", "redirect", "continue", "redir", "goto")
_PAYLOADS = [
    "https://evil.example.com",
    "//evil.example.com",
    "https://asynx6.ngrok.io",
    "/\\evil.example.com",
]


def _host_of(location: str) -> str:
    return (urlparse(location).netloc or "").lower()


def run(url: str, *, client: HttpClient, **_kwargs: Any) -> list[Finding]:
    findings: list[Finding] = []
    sep = "&" if "?" in url else "?"
    for param in _PARAMS:
        for payload in _PAYLOADS:
            probe = f"{url}{sep}{param}={payload}"
            r = client.get(probe, allow_redirects=False)
            if r is None:
                continue
            if r.status_code not in (301, 302, 303, 307, 308):
                continue
            location = r.headers.get("Location", "")
            if not location:
                continue
            host = _host_of(location)
            if not host or host == _host_of(url):
                continue
            if "evil.example" in host or "asynx6.ngrok" in host:
                findings.append(Finding(
                    type="Open Redirect",
                    severity=Severity.MEDIUM,
                    confidence=90,
                    location=probe,
                    payload=payload,
                    description=f"Redirects to attacker-controlled host: {location}",
                    remediation="Validate redirect targets against an allowlist.",
                ))
                return findings
    return findings

"""Reflected XSS detection."""

from __future__ import annotations

import logging
from typing import Any

from asynx6.core.http import HttpClient
from asynx6.core.models import Finding, Severity

log = logging.getLogger(__name__)

_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "\"'><svg/onload=alert(1)>",
]


def run(url: str, *, client: HttpClient, **_kwargs: Any) -> list[Finding]:
    """Probe `?q=` and `?id=` for unescaped reflection of XSS payloads."""
    findings: list[Finding] = []
    sep = "&" if "?" in url else "?"
    for payload in _PAYLOADS:
        for param in ("q", "id"):
            r = client.get(f"{url}{sep}{param}={payload}")
            if r is None:
                continue
            if payload in r.text:
                findings.append(Finding(
                    type="Reflected XSS",
                    severity=Severity.HIGH,
                    confidence=80,
                    location=f"{url}{sep}{param}={payload}",
                    payload=payload,
                    description=("Input is reflected in the response without "
                                 "proper output encoding."),
                    remediation="Apply contextual output encoding (HTML/attr/JS).",
                ))
                return findings
    return findings

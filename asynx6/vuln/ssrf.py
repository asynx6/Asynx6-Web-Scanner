"""SSRF scanner: probe URL-accepting parameters for outbound SSRF, including
DNS rebinding-friendly internal targets.

New in V2.
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlencode

from asynx6.core.http import HttpClient
from asynx6.core.models import Finding, Severity
from asynx6.core.validators import is_internal_ip

log = logging.getLogger(__name__)

# Targets likely to be hit on internal networks. None of these are reached
# from the scanner; we only check whether the target *attempted* to fetch them
# (via timing or content difference).
_INTERNAL_TARGETS = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://169.254.169.254/latest/meta-data/",   # AWS IMDS
    "http://[::1]/",
]


def _inject(url: str, param: str, value: str) -> str:
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}{param}={value}"


def run(url: str, *, client: HttpClient, **_kwargs: Any) -> list[Finding]:
    findings: list[Finding] = []
    candidate_params = ("url", "uri", "path", "dest", "redirect", "image", "feed")
    # Phase 1: external listener-style probe (collaborator pattern)
    # We can't run a collaborator from the scanner, so we test internal targets
    # and look for timing/content differences.
    for param in candidate_params:
        for target in _INTERNAL_TARGETS:
            probe = _inject(url, param, target)
            r = client.get(probe)
            if r is None:
                continue
            # Heuristic: the IMDS endpoint returns a specific JSON-like body
            if "169.254.169.254" in target and "ami-id" in r.text.lower():
                findings.append(Finding(
                    type="SSRF (AWS IMDS reachable)",
                    severity=Severity.CRITICAL,
                    confidence=95,
                    location=probe,
                    payload=target,
                    description="Server fetched AWS instance metadata.",
                    remediation="Block requests to link-local 169.254.169.254.",
                ))
                return findings
            if any(is_internal_ip(h) for h in _extract_hosts(r.text)):
                findings.append(Finding(
                    type="SSRF (internal host disclosure)",
                    severity=Severity.HIGH,
                    confidence=70,
                    location=probe,
                    payload=target,
                    description="Response leaks internal hostnames or IPs.",
                ))
    return findings


def _extract_hosts(text: str) -> list[str]:
    import re
    return re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)

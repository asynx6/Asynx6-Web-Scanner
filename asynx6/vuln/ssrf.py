"""SSRF scanner.

Probes URL-accepting parameters for SSRF by pointing them at internal
addresses (loopback, IMDS). A response is treated as an SSRF hit only when
its body is JSON-parseable AND contains a recognizable cloud-metadata or
internal-host response shape. Plain-text substrings like "ami-id" inside an
HTML page are ignored.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any
from urllib.parse import urlencode

from asynx6.core.http import HttpClient
from asynx6.core.models import Finding, Severity
from asynx6.core.validators import is_internal_ip

log = logging.getLogger(__name__)

_INTERNAL_TARGETS = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://169.254.169.254/latest/meta-data/",  # AWS IMDSv1
    "http://[::1]/",
]

# Well-known AWS IMDS response keys. Real IMDS responses contain at least one.
_IMDS_KEYS = (
    "ami-id", "ami-launch-index", "ami-manifest-path",
    "instance-id", "instance-type", "instance-action",
    "hostname", "local-hostname", "public-hostname",
    "reservation-id", "security-groups", "network/",
)

# Common parameter names that accept URLs.
_CANDIDATE_PARAMS = ("url", "uri", "path", "dest", "redirect", "image", "feed")


def _inject(url: str, param: str, value: str) -> str:
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}{param}={value}"


def _is_imds_response(body: str) -> bool:
    """True iff body parses as JSON and contains at least one IMDS key."""
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return False
    if not isinstance(data, (dict, list)):
        return False
    blob = json.dumps(data).lower()
    return any(key in blob for key in _IMDS_KEYS)


def _extract_internal_hosts(body: str) -> list[str]:
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    return [ip for ip in ip_pattern.findall(body) if is_internal_ip(ip)]


def run(url: str, *, client: HttpClient, **_kwargs: Any) -> list[Finding]:
    findings: list[Finding] = []
    for param in _CANDIDATE_PARAMS:
        for target in _INTERNAL_TARGETS:
            probe = _inject(url, param, target)
            r = client.get(probe)
            if r is None:
                continue

            if "169.254.169.254" in target and _is_imds_response(r.text):
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

            # Internal IP disclosure in a JSON-shaped response body only.
            if r.headers.get("Content-Type", "").lower().startswith("application/json"):
                hosts = _extract_internal_hosts(r.text)
                if hosts:
                    findings.append(Finding(
                        type="SSRF (internal host disclosure)",
                        severity=Severity.HIGH,
                        confidence=80,
                        location=probe,
                        payload=target,
                        description=f"Response leaks internal host(s): {', '.join(hosts)}",
                    ))
    return findings
"""Insecure Direct Object Reference (IDOR) / API authorization scanner.

Refactored from V1's scanner_api.py. Detects:
  - Parameter-driven data leaks
  - PUT/DELETE without auth
  - Mass assignment
  - 500-on-large-payload
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urljoin

from asynx6.core.http import HttpClient
from asynx6.core.models import Finding, Severity

log = logging.getLogger(__name__)

_PATHS = ["/api/v1/", "/api/v2/", "/api/admin/", "/api/user/"]
_IDOR_PARAMS = ("user_id", "order_token", "payment_status", "uuid", "client_id",
                "auth_key")
_LEAK_KEYWORDS = ("password", "email", "secret", "token", "balance", "admin")


def _is_api_url(url: str) -> bool:
    return "/api/" in url.lower()


def run(url: str, *, client: HttpClient, **_kwargs: Any) -> list[Finding]:
    findings: list[Finding] = []
    base = url if url.endswith("/") else url + "/"
    paths = list(_PATHS)
    if _is_api_url(url):
        paths.extend(["/api/swagger/", "/api/graphql/", "/api/config/",
                      "/api/private/"])

    for path in paths:
        target = urljoin(base, path.lstrip("/"))
        findings.extend(_probe_idor(client, target))
        findings.extend(_probe_methods(client, target))
        findings.extend(_probe_mass_assignment(client, target))
        findings.extend(_probe_large_payload(client, target))
    return findings


def _probe_idor(client: HttpClient, target: str) -> list[Finding]:
    out: list[Finding] = []
    for param in _IDOR_PARAMS:
        r = client.get(f"{target}?{param}=1")
        if r is None or r.status_code != 200 or len(r.text) >= 5000:
            continue
        if any(kw in r.text.lower() for kw in _LEAK_KEYWORDS):
            out.append(Finding(
                type="IDOR / Data Leak",
                severity=Severity.HIGH,
                confidence=85,
                location=f"{target}?{param}=1",
                description=f"Sensitive data leak via parameter: {param}",
            ))
    return out


def _probe_methods(client: HttpClient, target: str) -> list[Finding]:
    out: list[Finding] = []
    for method in ("PUT", "DELETE"):
        r = client.request(method, target)
        if r is None or r.status_code not in (200, 204):
            continue
        check = client.get(target)
        if check is None:
            continue
        if method == "DELETE" and check.status_code == 404:
            out.append(Finding(
                type="Unprotected DELETE",
                severity=Severity.CRITICAL,
                confidence=100,
                location=target,
                description="Resource deletion without authorization.",
            ))
        elif method == "PUT" and r.text != check.text:
            out.append(Finding(
                type="Unprotected PUT",
                severity=Severity.CRITICAL,
                confidence=95,
                location=target,
                description="Resource modification without authorization.",
            ))
    return out


def _probe_mass_assignment(client: HttpClient, target: str) -> list[Finding]:
    out: list[Finding] = []
    payload = {"is_admin": True, "role": "admin", "privileges": "all",
               "balance": 999_999}
    r = client.post(target, json=payload)
    if r is None or r.status_code not in (200, 201):
        return out
    check = client.get(target)
    if check is None:
        return out
    if '"role":"admin"' in check.text.lower() or '"is_admin":true' in check.text.lower():
        out.append(Finding(
            type="Mass Assignment",
            severity=Severity.CRITICAL,
            confidence=100,
            location=target,
            description="Privileges escalated via mass assignment.",
        ))
    return out


def _probe_large_payload(client: HttpClient, target: str) -> list[Finding]:
    r = client.post(target, json={"data": "A" * 50_000})
    if r is not None and r.status_code == 500:
        return [Finding(
            type="API Logic Failure (500 on large body)",
            severity=Severity.MEDIUM,
            location=target,
            description="Server returns 500 on a 50KB JSON body.",
        )]
    return []

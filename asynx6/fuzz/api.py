"""API endpoint discovery + parameter fuzzing.

Refactored from V1 scanner_api.py. Most logic moved to `vuln.idor`; this module
focuses on endpoint discovery (Swagger/OpenAPI probing, common API roots).
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urljoin

from asynx6.core.http import HttpClient
from asynx6.core.models import Finding, Severity

log = logging.getLogger(__name__)

_API_ROOTS = [
    "/api", "/api/v1", "/api/v2", "/api/v3", "/v1", "/v2",
    "/rest", "/graphql", "/swagger", "/swagger.json", "/openapi.json",
    "/api-docs", "/api/doc", "/docs",
]


def run(url: str, *, client: HttpClient, **_kwargs: Any) -> list[Finding]:
    """Probe for live API endpoints and Swagger/OpenAPI documentation."""
    findings: list[Finding] = []
    base = url if url.endswith("/") else url + "/"
    for path in _API_ROOTS:
        target = urljoin(base, path.lstrip("/"))
        r = client.get(target)
        if r is None or r.status_code != 200:
            continue
        body = r.text.lower()
        if "swagger" in body or "openapi" in body:
            findings.append(Finding(
                type="API documentation exposed",
                severity=Severity.LOW,
                confidence=95,
                location=target,
                description="Swagger/OpenAPI documentation publicly accessible.",
            ))
        if "{\"swagger\"" in body or "\"openapi\"" in body:
            findings.append(Finding(
                type="API schema exposed",
                severity=Severity.MEDIUM,
                confidence=90,
                location=target,
                description="OpenAPI/Swagger JSON schema publicly accessible.",
            ))
    return findings

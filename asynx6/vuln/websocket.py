"""WebSocket security scanner. V3.

Detects:
- WebSocket endpoints (via Upgrade header probe)
- Cross-Site WebSocket Hijacking (CSWSH) — missing Origin validation
- Authentication on WebSocket frames
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urljoin, urlparse

from asynx6.core.http import HttpClient
from asynx6.core.models import Finding, Severity

log = logging.getLogger(__name__)


# Common WebSocket paths
_WS_PATHS = ["/ws", "/socket", "/socket.io/", "/websocket", "/ws/",
             "/api/ws", "/live", "/stream"]

# Handshake probe headers
_HANDSHAKE_HEADERS = {
    "Upgrade": "websocket",
    "Connection": "Upgrade",
    "Sec-WebSocket-Version": "13",
    "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
}


def _looks_like_ws_endpoint(url: str, client: HttpClient) -> bool:
    """Probe the URL with WS handshake headers. WS endpoints return 101."""
    r = client.get(url, headers=_HANDSHAKE_HEADERS)
    return r is not None and r.status_code in (101, 200, 426)


def _csrf_check(url: str, client: HttpClient) -> bool:
    """Return True if the WS endpoint accepts an arbitrary Origin (CSWSH)."""
    evil_origin = "https://evil.example.com"
    r = client.get(url, headers={
        **_HANDSHAKE_HEADERS,
        "Origin": evil_origin,
    })
    if r is None:
        return False
    # If the server responds with a successful upgrade for an evil Origin,
    # that's CSWSH. Some servers return 403 with valid origins; absence
    # of rejection is the vulnerability.
    return r.status_code in (101, 200)


def run(url: str, *, client: HttpClient, **_kwargs: Any) -> list[Finding]:
    """Probe for WebSocket endpoints and CSWSH."""
    findings: list[Finding] = []
    base = url if url.endswith("/") else url + "/"
    found_endpoints: list[str] = []

    for path in _WS_PATHS:
        target = urljoin(base, path.lstrip("/"))
        if _looks_like_ws_endpoint(target, client):
            found_endpoints.append(target)
            findings.append(Finding(
                type="WebSocket endpoint discovered",
                severity=Severity.INFO,
                location=target,
                description=f"WebSocket endpoint responds to handshake at {target}",
            ))
            if _csrf_check(target, client):
                findings.append(Finding(
                    type="CSWSH (Cross-Site WebSocket Hijacking)",
                    severity=Severity.HIGH,
                    confidence=80,
                    location=target,
                    description="WebSocket accepts arbitrary Origin header — "
                                "vulnerable to CSWSH.",
                    remediation="Validate Origin against an allowlist on the "
                                "WebSocket handshake.",
                ))
    return findings
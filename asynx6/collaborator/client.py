"""Collaborator client — used by SSRF scans to inject + check tokens."""

from __future__ import annotations

import logging
import time
from typing import Any
from urllib.parse import urlparse

from asynx6.collaborator.tokens import build_payload_url, generate_token

log = logging.getLogger(__name__)


class CollaboratorClient:
    """Tracks tokens issued by the SSRF scan and polls the collaborator.

    Lifecycle:
        client = CollaboratorClient(domain="collab.asynx6.id")
        token = client.issue_token()          # generate + register
        url = client.payload_url(token)       # for injection into SSRF payloads
        ... wait for the target to be probed ...
        if client.poll(token):                 # check if the token was hit
            ... SSRF confirmed ...
    """

    def __init__(self, domain: str, *, poll_url: str | None = None,
                 poll_interval: float = 2.0) -> None:
        self.domain = domain
        self.poll_url = poll_url or f"http://{domain}/__poll__"
        self.poll_interval = poll_interval
        self._tokens: set[str] = set()

    def issue_token(self) -> str:
        t = generate_token()
        self._tokens.add(t)
        return t

    def payload_url(self, token: str, *, path: str = "/") -> str:
        return build_payload_url(self.domain, token, path=path)

    def poll(self, token: str, *, timeout: float = 30.0) -> bool:
        """Poll the collaborator's HTTP endpoint to check if `token` was hit.

        This is a stub implementation that simulates the check via an HTTP
        GET to `/__poll__/<token>`. A real implementation would query the
        collaborator server's database.
        """
        from asynx6.core.http import HttpClient
        try:
            with HttpClient(timeout=5) as client:
                url = f"{self.poll_url.rstrip('/')}/{token}"
                r = client.get(url)
                if r is None:
                    return False
                return r.status_code == 200 and b"hit" in r.content
        except Exception as exc:  # noqa: BLE001
            log.warning("Collaborator poll failed: %s", exc)
            return False

    def wait_for_hit(self, token: str, *, timeout: float = 30.0) -> bool:
        """Block up to `timeout` seconds, polling every `poll_interval`."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.poll(token):
                return True
            time.sleep(self.poll_interval)
        return False

    def tokens(self) -> set[str]:
        return set(self._tokens)
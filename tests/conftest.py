"""Shared pytest fixtures for Asynx6 V2 tests."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from asynx6.core.config import ScannerConfig
from asynx6.core.http import HttpClient
from asynx6.core.models import Finding, Severity


@pytest.fixture
def cfg() -> ScannerConfig:
    """Default scanner config (low-noise defaults for tests)."""
    return ScannerConfig(
        threads=2,
        timeout=2,
        jitter_min=0.0,
        jitter_max=0.0,
        show_banner=False,
        output_dir=Path("/tmp/asynx6-tests"),
        rate_limit__enabled=False,
    )


@pytest.fixture
def client(cfg: ScannerConfig) -> HttpClient:
    """HttpClient suitable for unit tests (no rate-limit, no jitter)."""
    return HttpClient(timeout=cfg.timeout,
                      jitter_min=cfg.jitter_min,
                      jitter_max=cfg.jitter_max)


@pytest.fixture
def sample_html() -> str:
    """Minimal page with a form, links, and a JS reference."""
    return """<!doctype html><html><head>
        <script src="/static/app.js"></script>
        <link rel="stylesheet" href="/static/style.css">
    </head><body>
        <form action="/login" method="post">
            <input type="text" name="user">
            <input type="password" name="pass">
        </form>
        <a href="/about">About</a>
        <a href="/api/v1/users?limit=10">API</a>
    </body></html>"""


@pytest.fixture
def sample_jwt() -> str:
    """Valid HS256 JWT signed with the secret 'secret'.

    Header: {"alg":"HS256","typ":"JWT"}
    Payload: {"sub":"1","exp":9999999999}
    """
    import base64
    import hmac
    import json

    def b64(d: bytes) -> str:
        return base64.urlsafe_b64encode(d).rstrip(b"=").decode()

    header = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = b64(json.dumps({"sub": "1", "exp": 9_999_999_999}).encode())
    signing_input = f"{header}.{payload}".encode()
    sig = b64(hmac.new(b"secret", signing_input, hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"


@pytest.fixture
def tmp_output_dir(tmp_path: Path) -> Path:
    """Isolated output dir for a single test."""
    p = tmp_path / "loot"
    p.mkdir()
    return p


@pytest.fixture
def fake_finding() -> Finding:
    """A reusable Finding instance."""
    return Finding(
        type="Test Vuln",
        severity=Severity.HIGH,
        location="https://example.com/x",
        description="desc",
        confidence=90,
    )
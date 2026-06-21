"""Tests for vuln.sqli."""

from __future__ import annotations

from unittest.mock import MagicMock

from asynx6.core.http import HttpResponse
from asynx6.vuln.sqli import run


def _resp(elapsed: float, status: int = 200) -> HttpResponse:
    r = MagicMock(spec=HttpResponse)
    r.status_code = status
    r.elapsed = elapsed
    r.headers = {}
    r.text = ""
    return r


def test_detects_sleep_payload(client, monkeypatch):
    """When the server actually sleeps 5s+, we get a Finding."""
    calls = {"n": 0}

    def fake_get(url, **kwargs):
        calls["n"] += 1
        # First probe returns 5.5s, double-check returns 10.5s
        return _resp(5.5 if calls["n"] == 1 else 10.5)

    monkeypatch.setattr(client, "get", fake_get)
    out = run("https://x.test/", client=client)
    assert out
    assert "SQL Injection" in out[0].type


def test_no_finding_on_fast_response(client, monkeypatch):
    monkeypatch.setattr(client, "get", lambda *a, **k: _resp(0.1))
    assert run("https://x.test/", client=client) == []
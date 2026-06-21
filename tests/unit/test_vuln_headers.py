"""Tests for vuln.headers."""

from __future__ import annotations

import responses

from asynx6.vuln.headers import run


@responses.activate
def test_missing_csp(client):
    responses.add(responses.GET, "https://x.test/",
                  status=200, headers={}, body="ok")
    out = run("https://x.test/", client=client)
    types = {f.type for f in out}
    assert any("Content-Security-Policy" in t for t in types)


@responses.activate
def test_all_headers_present(client):
    responses.add(responses.GET, "https://x.test/", status=200,
                  headers={"Content-Security-Policy": "default-src 'self'",
                           "Strict-Transport-Security": "max-age=31536000",
                           "X-Frame-Options": "DENY",
                           "X-Content-Type-Options": "nosniff"},
                  body="ok")
    assert run("https://x.test/", client=client) == []
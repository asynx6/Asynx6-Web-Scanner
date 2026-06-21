"""Tests for vuln.xss."""

from __future__ import annotations

import responses

from asynx6.vuln.xss import run


@responses.activate
def test_reflected_xss(client):
    payload = "<script>alert('XSS')</script>"
    responses.add(responses.GET, "https://x.test/",
                  body=f"<html><body>q={payload}</body></html>",
                  status=200)
    out = run("https://x.test/", client=client)
    assert out
    assert "XSS" in out[0].type


@responses.activate
def test_no_xss_when_not_reflected(client):
    responses.add(responses.GET, "https://x.test/",
                  body="<html><body>nothing here</body></html>",
                  status=200)
    assert run("https://x.test/", client=client) == []
"""Tests for vuln.open_redirect."""

from __future__ import annotations

import responses

from asynx6.vuln.open_redirect import run


@responses.activate
def test_open_redirect(client):
    responses.add(responses.GET, "https://x.test/",
                  status=302, headers={"Location": "https://evil.example.com/"})
    out = run("https://x.test/", client=client)
    assert any("Open Redirect" in f.type for f in out)


@responses.activate
def test_no_redirect(client):
    responses.add(responses.GET, "https://x.test/", status=200, body="ok")
    assert run("https://x.test/", client=client) == []
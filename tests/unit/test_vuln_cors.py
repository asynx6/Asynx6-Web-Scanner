"""Tests for vuln.cors."""

from __future__ import annotations

import responses

from asynx6.vuln.cors import run


@responses.activate
def test_wildcard_cors(client):
    responses.add(responses.GET, "https://x.test/", status=200,
                  headers={"Access-Control-Allow-Origin": "*"}, body="ok")
    out = run("https://x.test/", client=client)
    assert any("wildcard" in f.type for f in out)


@responses.activate
def test_reflected_origin(client):
    responses.add(responses.GET, "https://x.test/", status=200,
                  headers={"Access-Control-Allow-Origin":
                           "https://evil.example.com"},
                  body="ok")
    out = run("https://x.test/", client=client)
    assert any("arbitrary origin" in f.type for f in out)


@responses.activate
def test_safe_cors(client):
    responses.add(responses.GET, "https://x.test/", status=200,
                  headers={"Access-Control-Allow-Origin":
                           "https://trusted.com"}, body="ok")
    assert run("https://x.test/", client=client) == []
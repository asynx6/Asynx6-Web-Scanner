"""Tests for vuln.ssrf."""

from __future__ import annotations

import responses

from asynx6.vuln.ssrf import run


@responses.activate
def test_imds_marker(client):
    responses.add(responses.GET, "https://x.test/",
                  body='{"ami-id": "ami-deadbeef"}', status=200)
    out = run("https://x.test/", client=client)
    assert any("IMDS" in f.type for f in out)


@responses.activate
def test_internal_ip_disclosure(client):
    responses.add(responses.GET, "https://x.test/",
                  body="internal host: 10.0.0.5", status=200)
    out = run("https://x.test/", client=client)
    assert any("internal host" in f.type for f in out)
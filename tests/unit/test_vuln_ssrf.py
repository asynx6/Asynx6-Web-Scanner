"""Tests for vuln.ssrf."""

from __future__ import annotations

from pathlib import Path

import responses

from asynx6.vuln.ssrf import run


@responses.activate
def test_imds_marker(client):
    fixture = (Path(__file__).parent.parent / "fixtures"
               / "ssrf_imds_response.json")
    body = fixture.read_text(encoding="utf-8")
    responses.add(responses.GET, "https://x.test/",
                  body=body, status=200,
                  headers={"Content-Type": "application/json"})
    out = run("https://x.test/", client=client)
    assert any("IMDS" in f.type for f in out)


@responses.activate
def test_html_with_ami_id_substring_not_flagged(client):
    """HTML page mentioning 'ami-id' must NOT be flagged as IMDS."""
    fixture = (Path(__file__).parent.parent / "fixtures"
               / "ssrf_html_with_ami_id.html")
    body = fixture.read_text(encoding="utf-8")
    responses.add(responses.GET, "https://x.test/",
                  body=body, status=200,
                  headers={"Content-Type": "text/html"})
    assert run("https://x.test/", client=client) == []


@responses.activate
def test_imds_with_instance_id_flagged(client):
    """Real IMDS response uses 'instance-id' instead of 'ami-id' — must flag."""
    body = '{"instance-id": "i-aaaaaaaa", "local-hostname": "x"}'
    responses.add(responses.GET, "https://x.test/",
                  body=body, status=200,
                  headers={"Content-Type": "application/json"})
    out = run("https://x.test/", client=client)
    assert any("IMDS" in f.type for f in out)


@responses.activate
def test_internal_ip_disclosure(client):
    body = '{"error": "cannot connect to 10.0.0.5"}'
    responses.add(responses.GET, "https://x.test/",
                  body=body, status=200,
                  headers={"Content-Type": "application/json"})
    out = run("https://x.test/", client=client)
    assert any("internal host" in f.type for f in out)


@responses.activate
def test_internal_ip_in_html_not_flagged(client):
    """Internal IP only matters when the response body is JSON-shaped."""
    body = "Our internal gateway is at 10.0.0.5, please contact us."
    responses.add(responses.GET, "https://x.test/",
                  body=body, status=200,
                  headers={"Content-Type": "text/html"})
    assert run("https://x.test/", client=client) == []
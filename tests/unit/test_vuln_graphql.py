"""Tests for vuln.graphql."""

from __future__ import annotations

from pathlib import Path

import responses

from asynx6.vuln.graphql import run


@responses.activate
def test_introspection_detected(client):
    body = '{"data":{"__schema":{"types":[{"name":"Query"}]}}}'
    responses.add(responses.POST, "https://x.test/graphql",
                  body=body, status=200,
                  headers={"Content-Type": "application/json"})
    out = run("https://x.test/", client=client)
    assert any("introspection" in f.type for f in out)


@responses.activate
def test_no_graphql(client):
    responses.add(responses.POST, "https://x.test/graphql",
                  body="not graphql", status=404)
    assert run("https://x.test/", client=client) == []


@responses.activate
def test_html_response_with_data_word_not_flagged(client):
    """An HTML page containing the literal strings 'data' and 'errors'
    must NOT be flagged as GraphQL — only JSON responses count."""
    fixture = (Path(__file__).parent.parent / "fixtures"
               / "graphql_html_false_positive.html")
    body = fixture.read_text(encoding="utf-8")
    responses.add(responses.POST, "https://x.test/graphql",
                  body=body, status=200,
                  headers={"Content-Type": "text/html; charset=utf-8"})
    assert run("https://x.test/", client=client) == []


@responses.activate
def test_introspection_requires_json_content_type(client):
    """Same JSON body but Content-Type=text/html should NOT trigger."""
    body = '{"data":{"__schema":{"types":[{"name":"Query"}]}}}'
    responses.add(responses.POST, "https://x.test/graphql",
                  body=body, status=200,
                  headers={"Content-Type": "text/html; charset=utf-8"})
    assert run("https://x.test/", client=client) == []


@responses.activate
def test_real_introspection_fixture_flagged(client):
    """Real GraphQL introspection from fixture should be flagged."""
    fixture = (Path(__file__).parent.parent / "fixtures"
               / "graphql_real_introspection.json")
    body = fixture.read_text(encoding="utf-8")
    responses.add(responses.POST, "https://x.test/graphql",
                  body=body, status=200,
                  headers={"Content-Type": "application/json"})
    out = run("https://x.test/", client=client)
    assert any("introspection" in f.type for f in out)
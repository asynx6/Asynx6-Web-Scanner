"""Tests for vuln.graphql."""

from __future__ import annotations

import responses

from asynx6.vuln.graphql import run


@responses.activate
def test_introspection_detected(client):
    body = '{"data":{"__schema":{"types":[{"name":"Query"}]}}}'
    responses.add(responses.POST, "https://x.test/graphql",
                  body=body, status=200)
    out = run("https://x.test/", client=client)
    assert any("introspection" in f.type for f in out)


@responses.activate
def test_no_graphql(client):
    responses.add(responses.POST, "https://x.test/graphql",
                  body="not graphql", status=404)
    assert run("https://x.test/", client=client) == []
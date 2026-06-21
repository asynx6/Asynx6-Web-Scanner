"""Tests for fuzz.api."""

from __future__ import annotations

import responses

from asynx6.fuzz.api import run


@responses.activate
def test_swagger_detected(client):
    responses.add(responses.GET, "https://x.test/swagger.json",
                  body='{"swagger":"2.0","paths":{}}', status=200)
    out = run("https://x.test/", client=client)
    assert any("schema" in f.type for f in out)


@responses.activate
def test_no_api(client):
    responses.add(responses.GET, "https://x.test/swagger.json", status=404)
    responses.add(responses.GET, "https://x.test/api-docs", status=404)
    assert run("https://x.test/", client=client) == []
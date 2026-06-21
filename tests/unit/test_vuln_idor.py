"""Tests for vuln.idor."""

from __future__ import annotations

import responses

from asynx6.vuln.idor import run


@responses.activate
def test_idor_data_leak(client):
    responses.add(responses.GET, "https://x.test/api/v1/?user_id=1",
                  body='{"email":"a@b.c","password":"x"}', status=200)
    out = run("https://x.test/", client=client)
    assert any("IDOR" in f.type for f in out)


@responses.activate
def test_no_idor(client):
    responses.add(responses.GET, "https://x.test/api/v1/?user_id=1",
                  body="just plain text response with no keywords",
                  status=200)
    assert run("https://x.test/", client=client) == []
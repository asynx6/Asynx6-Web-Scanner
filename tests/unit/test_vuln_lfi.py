"""Tests for vuln.lfi."""

from __future__ import annotations

import responses

from asynx6.vuln.lfi import run


@responses.activate
def test_lfi_marker(client):
    responses.add(responses.GET, "https://x.test/",
                  body="root:x:0:0:root:/root:/bin/bash\n", status=200)
    out = run("https://x.test/", client=client)
    assert out
    assert out[0].type == "Local File Inclusion"


@responses.activate
def test_no_lfi(client):
    responses.add(responses.GET, "https://x.test/",
                  body="just a normal page", status=200)
    assert run("https://x.test/", client=client) == []
"""Tests for recon.chameleon."""

from __future__ import annotations

import responses

from asynx6.recon.chameleon import detect_stack


@responses.activate
def test_detects_react(client):
    responses.add(responses.GET, "https://x.test/",
                  body="<html><div id='__next'>Hello</div>"
                       "<script src='/_next/static/chunks/main.js'></script>"
                       "</body></html>",
                  status=200,
                  headers={"Server": "nginx"})
    stack = detect_stack("https://x.test/", client=client)
    assert "JavaScript" in stack["language"]
    assert stack["framework"] == "React/Next.js"


@responses.activate
def test_detects_wordpress(client):
    responses.add(responses.GET, "https://x.test/",
                  body="<script src='/wp-content/themes/foo.js'></script>",
                  status=200,
                  headers={"X-Powered-By": "PHP/8.1"})
    stack = detect_stack("https://x.test/", client=client)
    assert stack["language"] == "PHP"
    assert stack["cms"] == "WordPress"
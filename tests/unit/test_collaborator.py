"""Tests for SSRF collaborator."""

from __future__ import annotations

import time
from threading import Thread

import pytest

from asynx6.collaborator import (
    CollaboratorClient, CollaboratorServer, build_payload_url, generate_token,
)


def test_generate_token_unique():
    tokens = {generate_token() for _ in range(50)}
    assert len(tokens) == 50  # no collisions


def test_generate_token_length():
    assert len(generate_token()) == 16


def test_build_payload_url():
    url = build_payload_url("collab.asynx6.id", "abc123", path="/x")
    assert url == "http://abc123.collab.asynx6.id/x"


def test_build_payload_url_validation():
    with pytest.raises(ValueError):
        build_payload_url("", "token")
    with pytest.raises(ValueError):
        build_payload_url("x.com", "")


class TestCollaboratorServer:
    def test_starts_and_records_hit(self):
        import urllib.request
        server = CollaboratorServer(host="127.0.0.1", port=18903)
        server.start()
        try:
            urllib.request.urlopen("http://127.0.0.1:18903/my-token/abc",
                                    timeout=2).read()
            time.sleep(0.1)
            assert server.state.was_hit("my-token")
            hits = server.state.hits("my-token")
            assert hits[0]["path"] == "/my-token/abc"
        finally:
            server.stop()

    def test_poll_endpoint(self):
        import urllib.request
        import urllib.error
        server = CollaboratorServer(host="127.0.0.1", port=18905)
        server.start()
        try:
            # First trigger a hit
            urllib.request.urlopen("http://127.0.0.1:18905/hit-token/",
                                    timeout=2).read()
            time.sleep(0.1)
            # Now poll — hit returns 200 "hit"
            r = urllib.request.urlopen(
                "http://127.0.0.1:18905/__poll__/hit-token", timeout=2
            )
            assert r.read() == b"hit"
            # Unknown token returns 404 with body "miss"
            try:
                urllib.request.urlopen(
                    "http://127.0.0.1:18905/__poll__/unknown", timeout=2
                )
                raise AssertionError("expected 404 for unknown token")
            except urllib.error.HTTPError as exc:
                assert exc.code == 404
                assert exc.read() == b"miss"
        finally:
            server.stop()


class TestCollaboratorClient:
    def test_issue_and_payload_url(self):
        client = CollaboratorClient(domain="collab.example.com")
        token = client.issue_token()
        assert token in client.tokens()
        url = client.payload_url(token)
        assert token in url
        assert "collab.example.com" in url
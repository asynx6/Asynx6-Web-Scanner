"""Tests for core.http.HttpClient."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
import responses

from asynx6.core.http import HttpClient, get_morphing_headers


class TestMorphingHeaders:
    def test_returns_required_keys(self):
        h = get_morphing_headers()
        assert "User-Agent" in h
        assert "X-Forwarded-For" in h
        assert "Accept" in h

    def test_spoofed_ip_is_valid(self):
        h = get_morphing_headers()
        ip = h["X-Forwarded-For"]
        parts = ip.split(".")
        assert len(parts) == 4
        assert all(0 <= int(p) <= 255 for p in parts)


class TestHttpClient:
    @responses.activate
    def test_get_success(self, client: HttpClient):
        responses.add(responses.GET, "https://x.test/",
                      body="hello", status=200,
                      headers={"Content-Type": "text/plain"})
        r = client.get("https://x.test/", jitter=False)
        assert r is not None
        assert r.status_code == 200
        assert r.text == "hello"

    @responses.activate
    def test_get_returns_none_on_network_error(self, client: HttpClient):
        responses.add(responses.GET, "https://x.test/",
                      body=ConnectionError("nope"))
        assert client.get("https://x.test/", jitter=False) is None

    def test_jitter_sleep_is_bounded(self, client: HttpClient):
        import time
        client.jitter_min, client.jitter_max = 0.0, 0.0
        start = time.time()
        client._jitter_sleep()
        assert time.time() - start < 0.1

    def test_adapt_jitter_relaxes_on_200(self, client: HttpClient):
        client.jitter_min, client.jitter_max = 5.0, 10.0
        client.adapt_jitter(200, {})
        assert client.jitter_min < 1.0

    def test_adapt_jitter_strict_on_403(self, client: HttpClient):
        client.adapt_jitter(403, {"Server": "cloudflare"})
        assert client.jitter_min >= 3.0

    def test_close_is_idempotent(self, client: HttpClient):
        client.close()  # first call
        client.close()  # second call must not raise
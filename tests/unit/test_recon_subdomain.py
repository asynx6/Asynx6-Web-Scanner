"""Tests for recon.subdomain."""

from __future__ import annotations

import socket
from unittest.mock import patch

import responses

from asynx6.recon.subdomain import _query_crt, _detect_wildcard, run


class TestCrt:
    @responses.activate
    def test_returns_subs(self):
        responses.add(responses.GET, "https://crt.sh/?q=%25.example.com&output=json",
                      json=[{"name_value": "a.example.com\nb.example.com"},
                            {"name_value": "*.example.com"}],
                      status=200)
        subs = _query_crt("example.com")
        assert "a.example.com" in subs
        assert "b.example.com" in subs
        assert all("*" not in s for s in subs)

    @responses.activate
    def test_handles_non_200(self):
        responses.add(responses.GET, "https://crt.sh/?q=%25.example.com&output=json",
                      status=500)
        assert _query_crt("example.com") == set()


class TestWildcard:
    def test_returns_ip_when_resolvable(self):
        with patch("asynx6.recon.subdomain.socket.gethostbyname",
                   return_value="1.2.3.4"):
            assert _detect_wildcard("example.com") == "1.2.3.4"

    def test_returns_none_on_gaierror(self):
        import socket
        with patch("asynx6.recon.subdomain.socket.gethostbyname",
                   side_effect=socket.gaierror):
            assert _detect_wildcard("example.com") is None


class TestRun:
    @responses.activate
    def test_returns_deduped(self):
        responses.add(responses.GET, "https://crt.sh/?q=%25.example.com&output=json",
                      json=[{"name_value": "a.example.com"}], status=200)

        def fake_resolve(host):
            # Wildcard probes use the prefix "asynx6-probe-"; make those fail
            if host.startswith("asynx6-probe-"):
                raise socket.gaierror
            return "9.9.9.9"

        with patch("asynx6.recon.subdomain.socket.gethostbyname",
                   side_effect=fake_resolve):
            subs = run("https://example.com", threads=2)
            assert any(s.subdomain == "a.example.com" for s in subs)
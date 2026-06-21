"""Tests for recon.network."""

from __future__ import annotations

from unittest.mock import patch

import responses

from asynx6.recon.network import _probe_waf, _scan_port, run


class TestProbeWaf:
    @responses.activate
    def test_detects_cloudflare(self, client):
        responses.add(responses.GET, "https://x.test/",
                      body="", status=200,
                      headers={"Server": "cloudflare"})
        responses.add(responses.GET, "https://x.test/?id=<script>alert('WAF_TEST')</script>",
                      body="", status=403)
        assert _probe_waf("https://x.test/", client) == "Cloudflare"

    @responses.activate
    def test_returns_none(self, client):
        responses.add(responses.GET, "https://x.test/",
                      body="", status=200, headers={})
        responses.add(responses.GET, "https://x.test/?id=<script>alert('WAF_TEST')</script>",
                      body="", status=200)
        assert _probe_waf("https://x.test/", client) == "None"


class TestScanPort:
    def test_open_port(self):
        fake_sock = _FakeSocket(connect_result=0, banner="Apache/2.4")
        with patch("asynx6.recon.network.socket.socket", return_value=fake_sock):
            p = _scan_port("1.2.3.4", 80)
            assert p is not None
            assert p.port == 80
            assert p.service == "http"

    def test_closed_port(self):
        fake_sock = _FakeSocket(connect_result=1, banner="")
        with patch("asynx6.recon.network.socket.socket", return_value=fake_sock):
            assert _scan_port("1.2.3.4", 80) is None


class _FakeSocket:
    def __init__(self, connect_result: int = 0, banner: str = "") -> None:
        self.connect_result = connect_result
        self.banner = banner

    def __enter__(self): return self
    def __exit__(self, *a): return False
    def settimeout(self, _t): pass
    def connect_ex(self, _addr): return self.connect_result
    def sendall(self, _b): pass
    def recv(self, _n): return self.banner.encode()


class TestRun:
    @responses.activate
    def test_run_returns_dict(self, client):
        with patch("asynx6.recon.network._resolve", return_value="1.2.3.4"), \
             patch("asynx6.recon.network._scan_port", return_value=None), \
             patch("asynx6.recon.network._geo_lookup",
                   return_value=("Mars", "Aliens")), \
             patch("asynx6.recon.network._find_origin_ips", return_value=[]), \
             patch("asynx6.recon.network._probe_waf", return_value="None"):
            out = run("https://example.com", client)
            assert out["ip"] == "1.2.3.4"
            assert out["location"] == "Mars"
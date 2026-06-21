"""Tests for recon.dns_enum."""

from __future__ import annotations

from unittest.mock import patch

from asynx6.recon.dns_enum import run


class TestRun:
    def test_returns_dict(self):
        out = run("https://example.com")
        assert set(out.keys()) == {"spf", "dmarc", "mx", "txt"}

    def test_graceful_when_dig_missing(self):
        with patch("asynx6.recon.dns_enum.shutil.which", return_value=None):
            out = run("https://example.com")
            assert out["spf"] == []
            assert out["dmarc"] == []
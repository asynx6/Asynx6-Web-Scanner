"""Tests for recon.wayback."""

from __future__ import annotations

import responses

from asynx6.recon.wayback import run


class TestRun:
    @responses.activate
    def test_filters_junk_paths(self):
        responses.add(responses.GET, "https://web.archive.org/cdx/search/cdx",
                      json=[["original"],
                            ["https://example.com/admin"],
                            ["https://example.com/static/x.css"],
                            ["https://example.com/"]],
                      status=200)
        out = run("https://example.com")
        assert "https://example.com/admin" in out
        assert all("/static/" not in u for u in out)

    @responses.activate
    def test_handles_non_200(self):
        responses.add(responses.GET, "https://web.archive.org/cdx/search/cdx",
                      status=500)
        assert run("https://example.com") == set()
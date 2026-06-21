"""Tests for recon.headless."""

from __future__ import annotations

from asynx6.recon import headless


def test_returns_empty_when_playwright_missing(monkeypatch):
    monkeypatch.setattr(headless, "PLAYWRIGHT_AVAILABLE", False)
    out = headless.run("https://example.com")
    assert out == {"links": set(), "content": "", "api_endpoints": []}
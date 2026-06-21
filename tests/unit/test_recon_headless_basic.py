"""Tests for recon.headless run-without-playwright path."""

from __future__ import annotations

from asynx6.recon import headless


def test_run_returns_empty_when_playwright_missing(monkeypatch):
    monkeypatch.setattr(headless, "PLAYWRIGHT_AVAILABLE", False)
    out = headless.run("https://example.com")
    assert "links" in out
    assert "content" in out
    assert "api_endpoints" in out
    assert out["links"] == set()


def test_run_handles_exception(monkeypatch):
    """When playwright IS available but goto throws, return empty result."""
    monkeypatch.setattr(headless, "PLAYWRIGHT_AVAILABLE", True)

    class FakePage:
        def on(self, *_args):
            pass

        def goto(self, *_args, **_kw):
            raise RuntimeError("browser gone")

        def query_selector_all(self, *_):
            return []

    class FakeContext:
        def new_page(self):
            return FakePage()

    class FakeBrowser:
        def new_context(self, **_kw):
            return FakeContext()

        def close(self):
            pass

    class FakePW:
        def chromium(self):
            return FakeBrowser()

    from contextlib import contextmanager

    @contextmanager
    def fake_sync_playwright():
        yield FakePW()

    monkeypatch.setattr(headless, "sync_playwright", fake_sync_playwright)
    out = headless.run("https://example.com")
    assert "links" in out
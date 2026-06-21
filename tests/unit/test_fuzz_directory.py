"""Tests for fuzz.directory."""

from __future__ import annotations

import responses

from asynx6.fuzz.directory import _build_wordlist, run


def test_wordlist_contains_env():
    wl = _build_wordlist("https://example.com/", aggressive=False, baseline=None)
    assert ".env" in wl


def test_wordlist_extends_with_keywords():
    wl = _build_wordlist("https://example.com/", aggressive=False,
                         baseline="the billing dashboard login button")
    assert any("billing/" in w for w in wl)


def test_wordlist_aggressive():
    wl = _build_wordlist("https://example.com/", aggressive=True, baseline=None)
    assert "docker-compose.yml" in wl


@responses.activate
def test_run_finds_env(client):
    responses.add(responses.GET, "https://x.test/.env",
                  body="DB_HOST=localhost\nAPP_KEY=secret\nMAIL_HOST=mail",
                  status=200,
                  headers={"Content-Type": "text/plain"})
    responses.add(responses.GET, "https://x.test/non-existent-path-1234",
                  body="<html>not found</html>", status=200)
    out = run("https://x.test/", client=client, threads=2)
    assert any(".env" in r["url"] for r in out)
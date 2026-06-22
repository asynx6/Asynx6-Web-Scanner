"""Tests for fuzz.directory."""

from __future__ import annotations

from pathlib import Path

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
    responses.add(responses.GET,
                  "https://x.test/asynx6-baseline-probe",
                  body="<html>not found</html>", status=200)
    out = run("https://x.test/", client=client, threads=2)
    assert any(".env" in r["url"] for r in out)


def _read(name: str) -> str:
    return (Path(__file__).parent.parent / "fixtures" / name).read_text(
        encoding="utf-8"
    )


@responses.activate
def test_spa_nextjs_baseline_filters_candidate(client):
    """Next.js shell pages should not be reported as loot."""
    baseline = _read("spa_soft404_nextjs.html")
    responses.add(responses.GET,
                  "https://x.test/asynx6-baseline-probe",
                  body=baseline, status=200,
                  headers={"Content-Type": "text/html"})
    # Simulate the SPA returning the same shell page for /admin (SPA soft-404)
    responses.add(responses.GET, "https://x.test/admin/",
                  body=baseline, status=200,
                  headers={"Content-Type": "text/html"})
    out = run("https://x.test/", client=client, threads=2)
    assert not any("admin" in r["url"] for r in out), (
        f"SPA soft-404 was incorrectly flagged: {out}"
    )


@responses.activate
def test_spa_nuxt_baseline_filters_candidate(client):
    """Nuxt shell pages should not be reported as loot."""
    baseline = _read("spa_soft404_nuxt.html")
    responses.add(responses.GET,
                  "https://x.test/asynx6-baseline-probe",
                  body=baseline, status=200,
                  headers={"Content-Type": "text/html"})
    responses.add(responses.GET, "https://x.test/phpmyadmin/",
                  body=baseline, status=200,
                  headers={"Content-Type": "text/html"})
    out = run("https://x.test/", client=client, threads=2)
    assert not any("phpmyadmin" in r["url"] for r in out)


@responses.activate
def test_real_env_file_passes_dom_filter(client):
    """A genuine .env file with real markers should still be caught."""
    env_body = _read("real_findings_dotenv")
    baseline = _read("spa_soft404_nextjs.html")
    responses.add(responses.GET,
                  "https://x.test/asynx6-baseline-probe",
                  body=baseline, status=200,
                  headers={"Content-Type": "text/html"})
    responses.add(responses.GET, "https://x.test/.env",
                  body=env_body, status=200,
                  headers={"Content-Type": "text/plain"})
    out = run("https://x.test/", client=client, threads=2)
    assert any(".env" in r["url"] for r in out)


def test_dom_signature_diff_counter():
    """Structural fingerprint counter behaves as expected."""
    from bs4 import BeautifulSoup
    from asynx6.fuzz.directory import (
        _dom_signature, _signature_diff, _is_spa_soft404,
    )
    base = BeautifulSoup(
        _read("spa_soft404_nextjs.html"), "html.parser"
    )
    # Identical → diff is 0
    assert _signature_diff(_dom_signature(base), _dom_signature(base)) == 0
    assert _is_spa_soft404(base, base, str(base), str(base)) is True
    # Different structure → not a soft-404 of the baseline
    different = BeautifulSoup(
        "<html><body><h1>Hello</h1><p>world</p></body></html>", "html.parser"
    )
    assert _is_spa_soft404(different, base, str(different), str(base)) is False
"""Tests for recon.crawler."""

from __future__ import annotations

import responses

from asynx6.recon.crawler import run


@responses.activate
def test_crawler_extracts_forms_and_links(client, sample_html):
    responses.add(responses.GET, "https://x.test/",
                  body=sample_html, status=200,
                  headers={"Content-Type": "text/html"})
    responses.add(responses.GET, "https://x.test/about",
                  body="<html>about page</html>", status=200,
                  headers={"Content-Type": "text/html"})
    responses.add(responses.GET, "https://x.test/api/v1/users?limit=10",
                  body="<html>api page</html>", status=200,
                  headers={"Content-Type": "text/html"})
    out = run("https://x.test/", client=client, max_pages=5)
    assert "https://x.test/" in out["visited"]
    assert any("/about" in u for u in out["visited"])
    assert any(f["url"].endswith("/login") for f in out["forms"])


@responses.activate
def test_crawler_extracts_secret(client, tmp_output_dir):
    responses.add(responses.GET, "https://x.test/",
                  body="AKIAEXAMPLE0000000000 here", status=200)
    out = run("https://x.test/", client=client, max_pages=2,
              output_dir=str(tmp_output_dir))
    types = {s["type"] for s in out["sensitive_info"]}
    assert "AWS Access Key" in types
    assert (tmp_output_dir / "LOOT_VAULT.md").exists()
"""Tests for reporting.markdown."""

from __future__ import annotations

from asynx6.core.models import Finding, ScanContext, Severity, Subdomain
from asynx6.reporting.markdown import generate


def test_markdown_writes_report(tmp_path, fake_finding):
    ctx = ScanContext(target="t", base_url="http://t", domain="t")
    ctx.add_finding(fake_finding)
    ctx.subdomains.append(Subdomain(subdomain="a.t", ip="1.2.3.4"))
    p = generate("http://t", ctx, tmp_path)
    text = (tmp_path / "BUG_BOUNTY_POC.md").read_text(encoding="utf-8")
    assert "http://t" in text
    assert "Test Vuln" in text
    assert "a.t" in text


def test_markdown_no_findings(tmp_path):
    ctx = ScanContext(target="t", base_url="http://t", domain="t")
    generate("http://t", ctx, tmp_path)
    text = (tmp_path / "BUG_BOUNTY_POC.md").read_text(encoding="utf-8")
    assert "No findings" in text
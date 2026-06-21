"""Tests for reporting.html_report."""

from __future__ import annotations

from asynx6.core.models import ScanContext
from asynx6.reporting.html_report import generate


def test_html_writes_report(tmp_path, fake_finding):
    ctx = ScanContext(target="http://t", base_url="http://t", domain="t")
    ctx.add_finding(fake_finding)
    p = generate("http://t", ctx, tmp_path)
    text = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert "http://t" in text
    assert "Test Vuln" in text


def test_html_no_findings(tmp_path):
    ctx = ScanContext(target="t", base_url="http://t", domain="t")
    generate("http://t", ctx, tmp_path)
    text = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert "No findings" in text
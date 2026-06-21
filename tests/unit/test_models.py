"""Tests for core.models."""

from __future__ import annotations

from asynx6.core.models import Finding, ScanContext, Severity


class TestSeverity:
    def test_rank_order(self):
        assert Severity.CRITICAL.rank > Severity.HIGH.rank
        assert Severity.INFO.rank < Severity.LOW.rank


class TestFinding:
    def test_to_dict(self, fake_finding):
        d = fake_finding.to_dict()
        assert d["type"] == "Test Vuln"
        assert d["severity"] == "HIGH"
        assert d["confidence"] == 90


class TestScanContext:
    def test_add_and_extend(self):
        ctx = ScanContext(target="t", base_url="http://t", domain="t")
        ctx.add_finding(Finding(type="a", severity=Severity.INFO,
                                location="x", description="d"))
        ctx.extend_findings([
            Finding(type="b", severity=Severity.INFO, location="x",
                    description="d"),
            Finding(type="c", severity=Severity.INFO, location="x",
                    description="d"),
        ])
        assert len(ctx.findings) == 3
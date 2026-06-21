"""Tests for reporting.json_export."""

from __future__ import annotations

import json

from asynx6.core.models import ScanContext, Severity
from asynx6.reporting.json_export import generate_json, generate_sarif


def test_generate_json(tmp_path, fake_finding):
    ctx = ScanContext(target="t", base_url="http://t", domain="t")
    ctx.add_finding(fake_finding)
    p = generate_json(ctx, tmp_path)
    data = json.loads(open(p, encoding="utf-8").read())
    assert data["target"] == "http://t"
    assert data["stats"]["total_findings"] == 1
    assert data["stats"]["by_severity"]["HIGH"] == 1


def test_generate_sarif(tmp_path, fake_finding):
    ctx = ScanContext(target="t", base_url="http://t", domain="t")
    ctx.add_finding(fake_finding)
    p = generate_sarif(ctx, tmp_path)
    data = json.loads(open(p, encoding="utf-8").read())
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["results"][0]["ruleId"]
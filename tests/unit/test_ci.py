"""Tests for ci.py."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from asynx6.ci import (
    EXIT_CLEAN, EXIT_ERROR, EXIT_FINDINGS, _compare_to_baseline,
    _load_baseline, _severity_rank, run_ci,
)
from asynx6.core.models import Finding, Severity


def test_severity_rank():
    assert _severity_rank("CRITICAL") == 4
    assert _severity_rank("INFO") == 0
    assert _severity_rank("unknown") == 0


def test_load_baseline_missing_file(tmp_path):
    assert _load_baseline(tmp_path / "missing.json") == []


def test_load_baseline_list(tmp_path):
    p = tmp_path / "b.json"
    p.write_text(json.dumps([{"type": "X", "location": "/a"}]))
    assert _load_baseline(p) == [{"type": "X", "location": "/a"}]


def test_load_baseline_dict_with_items(tmp_path):
    p = tmp_path / "b.json"
    p.write_text(json.dumps({"items": [{"type": "Y", "location": "/b"}]}))
    assert _load_baseline(p) == [{"type": "Y", "location": "/b"}]


def test_compare_to_baseline():
    findings = [
        Finding(type="A", severity=Severity.HIGH, location="/x",
                description=""),
        Finding(type="B", severity=Severity.HIGH, location="/y",
                description=""),
    ]
    baseline = [{"type": "A", "location": "/x"}]
    new, matched = _compare_to_baseline(findings, baseline)
    assert len(new) == 1
    assert new[0].type == "B"
    assert len(matched) == 1
    assert matched[0].type == "A"


def test_run_ci_clean(tmp_path, capsys):
    # Mock orchestrator with empty findings
    fake_ctx = type("Ctx", (), {
        "target": "https://x.test/",
        "findings": [],
    })()
    with patch("asynx6.ci.Orchestrator") as MockOrch:
        MockOrch.return_value.run.return_value = fake_ctx
        rc = run_ci(_args(["https://x.test/"], tmp_path))
    assert rc == EXIT_CLEAN


def test_run_ci_with_findings(tmp_path):
    fake_ctx = type("Ctx", (), {
        "target": "https://x.test/",
        "findings": [
            Finding(type="SQLi", severity=Severity.CRITICAL,
                    location="/x", description="x"),
        ],
    })()
    with patch("asynx6.ci.Orchestrator") as MockOrch:
        MockOrch.return_value.run.return_value = fake_ctx
        rc = run_ci(_args(["https://x.test/"], tmp_path))
    assert rc == EXIT_FINDINGS


def test_run_ci_with_baseline_only_new_fails(tmp_path):
    fake_ctx = type("Ctx", (), {
        "target": "https://x.test/",
        "findings": [
            Finding(type="SQLi", severity=Severity.CRITICAL,
                    location="/x", description="x"),
        ],
    })()
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps([
        {"type": "SQLi", "location": "/x", "severity": "CRITICAL"}
    ]))
    args = _args(["https://x.test/"], tmp_path)
    args.baseline = baseline
    args.fail_on_new_only = True
    with patch("asynx6.ci.Orchestrator") as MockOrch:
        MockOrch.return_value.run.return_value = fake_ctx
        rc = run_ci(args)
    assert rc == EXIT_CLEAN  # matches baseline


def _args(argv: list[str], tmp_path) -> object:
    """Build a minimal Namespace for run_ci tests."""
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("target")
    p.add_argument("--baseline", type=Path, default=None)
    p.add_argument("--output-baseline", type=Path, default=None)
    p.add_argument("--format", default="sarif")
    p.add_argument("--severity-threshold", default="MEDIUM")
    p.add_argument("--fail-on-new-only", action="store_true")
    p.add_argument("--output", type=Path, default=None)
    p.add_argument("--config", type=Path, default=None)
    return p.parse_args(argv)
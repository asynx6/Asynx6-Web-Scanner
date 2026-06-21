"""Tests for CLI additional flows (V3)."""

from __future__ import annotations

from unittest.mock import patch


def test_cli_with_locale_id():
    """Verify --locale id is parsed."""
    from asynx6.cli import _build_parser
    p = _build_parser()
    args = p.parse_args(["https://x.test/", "--locale", "id"])
    assert args.locale == "id"


def test_cli_with_profile_known():
    from asynx6.cli import _build_parser
    p = _build_parser()
    args = p.parse_args(["https://x.test/", "--profile", "deep"])
    assert args.profile == "deep"


def test_cli_serve_flag():
    from asynx6.cli import _build_parser
    p = _build_parser()
    args = p.parse_args(["https://x.test/", "--serve"])
    assert args.serve is True


def test_cli_format_all():
    from asynx6.cli import _build_parser
    p = _build_parser()
    args = p.parse_args(["https://x.test/", "--format", "all"])
    assert args.report_format == "all"


def test_cli_runs_with_profile():
    """Smoke test: --profile quick-triage runs without error (mocked)."""
    from asynx6.cli import main
    fake_ctx = type("Ctx", (), {
        "target": "https://x.test/",
        "findings": [],
        "domain": "x.test",
    })()
    with patch("asynx6.cli.Orchestrator") as MockOrch, \
         patch("asynx6.cli.console.input", return_value=""):
        MockOrch.return_value.run.return_value = fake_ctx
        rc = main(["https://x.test/", "--profile", "quick-triage", "--no-banner"])
    assert rc == 0
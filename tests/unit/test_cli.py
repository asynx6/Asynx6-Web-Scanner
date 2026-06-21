"""Tests for cli.main."""

from __future__ import annotations

from unittest.mock import patch

from asynx6.cli import main


def test_cli_missing_target_returns_1(capsys):
    with patch("asynx6.cli.setup_logging"), \
         patch("asynx6.cli.console.input", return_value=""):
        assert main(["--no-banner"]) == 1


def test_cli_invokes_orchestrator():
    with patch("asynx6.cli.Orchestrator") as mock_orch, \
         patch("asynx6.cli.console.input", return_value=""):
        mock_orch.return_value.run.return_value.findings = []
        rc = main(["https://example.com", "--no-banner"])
    assert rc == 0
    assert mock_orch.called
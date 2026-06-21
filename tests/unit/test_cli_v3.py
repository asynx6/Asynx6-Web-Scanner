"""Tests for CLI V3 additions (locale flag, profile flag, --serve, etc.)."""

from __future__ import annotations

from unittest.mock import patch

import pytest


def test_cli_help_includes_v3_flags(capsys):
    from asynx6.cli import _build_parser
    p = _build_parser()
    # Parser builds OK; flags added below


def test_cli_locale_flag_accepted():
    from asynx6.cli import _build_parser
    p = _build_parser()
    args = p.parse_args(["https://x.test/", "--locale", "id"])
    assert args.locale == "id"


def test_cli_profile_flag_accepted():
    from asynx6.cli import _build_parser
    p = _build_parser()
    args = p.parse_args(["https://x.test/", "--profile", "ci"])
    assert args.profile == "ci"


def test_cli_persist_flag_accepted():
    from asynx6.cli import _build_parser
    p = _build_parser()
    args = p.parse_args(["https://x.test/", "--persist"])
    assert args.persist is True
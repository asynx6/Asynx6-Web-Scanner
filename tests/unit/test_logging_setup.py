"""Tests for core.logging_setup."""

from __future__ import annotations

import logging

from asynx6.core.logging_setup import _RedactionFilter, setup_logging


def test_filter_redacts_api_key():
    f = _RedactionFilter()
    rec = logging.LogRecord("x", logging.INFO, "", 0,
                            "x-api-key: ABCDEFGHIJKLMNOP", None, None)
    assert f.filter(rec) is True
    assert "[REDACTED]" in str(rec.msg)


def test_setup_logging_creates_file(tmp_path):
    p = setup_logging(tmp_path)
    assert p.exists()
    assert p.name == "audit.log"
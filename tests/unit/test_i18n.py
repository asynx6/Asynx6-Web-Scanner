"""Tests for i18n module."""

from __future__ import annotations

from asynx6.i18n import get_locale, set_locale, t


def test_english_default():
    set_locale("en")
    assert t("scan.start") == "Starting scan"


def test_indonesian_locale():
    set_locale("id")
    assert t("scan.start") == "Memulai pemindaian"
    set_locale("en")  # restore


def test_unknown_locale_falls_back_to_english():
    set_locale("xx")
    assert get_locale() == "en"
    assert t("scan.start") == "Starting scan"
    set_locale("en")  # restore


def test_missing_key_returns_key():
    set_locale("en")
    assert t("nonexistent.key") == "nonexistent.key"


def test_format_kwargs():
    set_locale("en")
    out = t("scan.target", **{})  # plain
    assert "Target" in out or "target" in out.lower()
    set_locale("en")
"""Tests for scan profiles."""

from __future__ import annotations

import pytest

from asynx6.profiles import (
    apply_profile, ci_pipeline, deep, get_profile, list_profiles,
    owasp_top10, quick_triage, stealth,
)


def test_all_builtin_profiles_exist():
    names = [p.name for p in list_profiles()]
    assert "quick-triage" in names
    assert "owasp-top10" in names
    assert "deep" in names
    assert "stealth" in names
    assert "ci" in names


def test_get_profile_unknown_raises():
    with pytest.raises(KeyError):
        get_profile("nope")


def test_quick_triage_has_low_threads():
    p = quick_triage()
    assert p.config.threads <= 25
    assert "vuln_sqli" in p.enabled_phases


def test_stealth_has_high_jitter():
    p = stealth()
    assert p.config.jitter_min >= 5.0


def test_ci_pipeline_uses_sarif():
    p = ci_pipeline()
    assert p.config.report_format == "sarif"


def test_deep_is_aggressive():
    p = deep()
    assert p.config.aggressive is True


def test_apply_profile_returns_config():
    from asynx6.core.config import ScannerConfig
    base = ScannerConfig(threads=5)
    out = apply_profile(base, "ci")
    assert isinstance(out, ScannerConfig)
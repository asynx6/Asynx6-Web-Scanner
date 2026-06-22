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


def test_apply_profile_profile_wins_over_base():
    """Profile config should override base config (V3 fix)."""
    from asynx6.core.config import ScannerConfig
    base = ScannerConfig(threads=100, aggressive=True)
    out = apply_profile(base, "ci")
    # ci profile says threads=20, should win
    assert out.threads == 20
    # ci profile explicitly sets show_banner=False
    assert out.show_banner is False
    # ci profile explicitly sets aggressive=False → wins over base
    assert out.aggressive is False


def test_apply_profile_preserves_base_fields_not_in_profile():
    """Fields not in the profile (e.g., proxies) should be preserved from base."""
    from asynx6.core.config import ScannerConfig
    base = ScannerConfig(
        threads=5,
        proxies=["http://127.0.0.1:8080"],
        verify_ssl=False,
    )
    out = apply_profile(base, "ci")
    assert out.proxies == ["http://127.0.0.1:8080"]
    assert out.verify_ssl is False


def test_apply_profile_invalid_raises():
    """Unknown profile name raises KeyError."""
    from asynx6.core.config import ScannerConfig
    base = ScannerConfig(threads=5)
    with pytest.raises(KeyError):
        apply_profile(base, "nonexistent_profile")
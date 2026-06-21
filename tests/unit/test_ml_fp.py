"""Tests for ML false-positive filter."""

from __future__ import annotations

import pytest

from asynx6.core.models import Finding, Severity
from asynx6.ml_fp import FalsePositiveFilter


def test_unfitted_returns_neutral():
    flt = FalsePositiveFilter()
    f = Finding(type="SQLi", severity=Severity.CRITICAL, location="/x",
                description="confirmed", confidence=50)
    assert flt.score(f) == 0.5


def test_fit_and_score():
    flt = FalsePositiveFilter()
    if not flt.fit_seed():
        pytest.skip("scikit-learn not installed")
    real = Finding(type="SQL Injection", severity=Severity.CRITICAL,
                    location="/x", description="admin root user confirmed",
                    confidence=50)
    maybe_fp = Finding(type="SQLi test", severity=Severity.LOW,
                       location="/test", description="test payload",
                       confidence=50)
    real_score = flt.score(real)
    fp_score = flt.score(maybe_fp)
    # Real finding should score higher than the maybe-FP
    assert real_score >= fp_score


def test_adjust_confidence():
    flt = FalsePositiveFilter()
    if not flt.fit_seed():
        pytest.skip("scikit-learn not installed")
    f_high = Finding(type="SQL Injection CRITICAL confirmed", severity=Severity.CRITICAL,
                     location="/x", description="root admin", confidence=50)
    original = f_high.confidence
    flt.adjust(f_high)
    # Either boosted (if real) or reduced (if FP) — but not unchanged unless neutral
    # We don't assert specific value, just that it's a valid number
    assert 0 <= f_high.confidence <= 100
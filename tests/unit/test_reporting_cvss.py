"""Tests for reporting.cvss."""

from __future__ import annotations

from asynx6.reporting.cvss import CvssVector, score


def test_zero_when_no_impact():
    v = CvssVector(AV="N", AC="L", PR="N", UI="N", C="N", I="N", A="N")
    assert score(v) == 0.0


def test_high_when_critical():
    v = CvssVector(AV="N", AC="L", PR="N", UI="N",
                   C="H", I="H", A="H")
    assert score(v) >= 9.0


def test_vector_string():
    v = CvssVector()
    assert v.to_string().startswith("CVSS:3.1/")
"""Tests for engine.scheduler."""

from __future__ import annotations

import pytest

from asynx6.engine.scheduler import Phase, schedule


def test_topological_order():
    a = Phase("a", lambda: None)
    b = Phase("b", lambda: None, needs=["a"])
    c = Phase("c", lambda: None, needs=["a", "b"])
    order = [p.name for p in schedule([c, a, b])]
    assert order.index("a") < order.index("b") < order.index("c")


def test_unknown_need_raises():
    with pytest.raises(ValueError):
        list(schedule([Phase("a", lambda: None, needs=["missing"])]))


def test_cycle_raises():
    a = Phase("a", lambda: None, needs=["b"])
    b = Phase("b", lambda: None, needs=["a"])
    with pytest.raises(ValueError):
        list(schedule([a, b]))
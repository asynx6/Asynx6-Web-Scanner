"""Tests for core.rate_limit."""

from __future__ import annotations

import pytest

from asynx6.core.rate_limit import RateLimiter, TokenBucket


class TestTokenBucket:
    def test_acquire_returns_true(self):
        b = TokenBucket(rate=100.0, burst=5)
        assert b.acquire(blocking=False) is True

    def test_invalid_init(self):
        with pytest.raises(ValueError):
            TokenBucket(rate=0, burst=5)
        with pytest.raises(ValueError):
            TokenBucket(rate=1.0, burst=0)


class TestRateLimiter:
    def test_disabled_is_noop(self):
        rl = RateLimiter(enabled=False, rps=0.001, burst=1)
        assert rl.acquire("x.com") is True
        assert rl.acquire("y.com") is True
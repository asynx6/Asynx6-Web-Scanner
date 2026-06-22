"""Unit tests for asynx6.core.strategies (M3 of the V3 refactor)."""

from __future__ import annotations

import threading
import time
from typing import Any
from unittest.mock import MagicMock

import pytest

from asynx6.core.config import RateLimitConfig
from asynx6.core.rate_limit import RateLimiter
from asynx6.core.strategies import (
    DefaultStrategies,
    JitterStrategy,
    MorphingHeaderStrategy,
    RateLimitStrategy,
)


# -- MorphingHeaderStrategy --------------------------------------------------

def test_morphing_injects_headers() -> None:
    captured: dict[str, Any] = {}
    headers = {"User-Agent": "Test", "Accept": "*/*"}

    def fake_get_headers() -> dict[str, str]:
        return {"User-Agent": "Morphed/1.0", "X-Forwarded-For": "1.2.3.4"}

    strat = MorphingHeaderStrategy(fake_get_headers)
    kwargs: dict[str, Any] = {"headers": dict(headers)}
    strat.before_request("GET", "https://x", kwargs)
    assert kwargs["headers"]["User-Agent"] == "Morphed/1.0"
    assert kwargs["headers"]["X-Forwarded-For"] == "1.2.3.4"


def test_morphing_preserves_existing_headers() -> None:
    """User-supplied headers must NOT be dropped when morphing is added."""
    def fake_get_headers() -> dict[str, str]:
        return {"X-Forwarded-For": "1.2.3.4"}

    strat = MorphingHeaderStrategy(fake_get_headers)
    kwargs: dict[str, Any] = {"headers": {"Authorization": "Bearer xyz"}}
    strat.before_request("GET", "https://x", kwargs)
    assert kwargs["headers"]["Authorization"] == "Bearer xyz"
    assert kwargs["headers"]["X-Forwarded-For"] == "1.2.3.4"


def test_morphing_creates_headers_when_none() -> None:
    """If the caller didn't pass headers, the strategy must create the dict."""
    def fake_get_headers() -> dict[str, str]:
        return {"User-Agent": "x"}

    strat = MorphingHeaderStrategy(fake_get_headers)
    kwargs: dict[str, Any] = {}
    strat.before_request("GET", "https://x", kwargs)
    assert "headers" in kwargs
    assert kwargs["headers"]["User-Agent"] == "x"


def test_morphing_after_request_is_noop() -> None:
    strat = MorphingHeaderStrategy(lambda: {"User-Agent": "x"})
    # Must not raise, even with a real-looking response.
    fake_response = MagicMock()
    fake_response.status_code = 200
    fake_response.headers = {}
    strat.after_request("GET", "https://x", fake_response)
    strat.after_request("GET", "https://x", None)


# -- JitterStrategy ---------------------------------------------------------

def test_jitter_construction_rejects_invalid_range() -> None:
    with pytest.raises(ValueError):
        JitterStrategy(jitter_min=5.0, jitter_max=1.0)


def test_jitter_before_request_sleeps_within_range() -> None:
    strat = JitterStrategy(jitter_min=0.05, jitter_max=0.1)
    start = time.time()
    strat.before_request("GET", "https://x", {})
    elapsed = time.time() - start
    assert 0.03 <= elapsed <= 0.3, f"jitter sleep out of range: {elapsed}"


def test_jitter_zero_max_skips_sleep() -> None:
    """jitter_max == 0 means 'no jitter' — useful for tests."""
    strat = JitterStrategy(jitter_min=0, jitter_max=0)
    start = time.time()
    strat.before_request("GET", "https://x", {})
    assert time.time() - start < 0.05


def test_jitter_adapt_relaxes_on_200() -> None:
    strat = JitterStrategy(jitter_min=5.0, jitter_max=10.0)
    strat.adapt_jitter(200, {})
    assert strat.jitter_min < 1.0
    assert strat.jitter_max < 2.5


def test_jitter_adapt_strict_on_403() -> None:
    strat = JitterStrategy()
    strat.adapt_jitter(403, {"Server": "cloudflare"})
    assert strat.jitter_min >= 3.0


def test_jitter_adapt_strict_on_429() -> None:
    strat = JitterStrategy()
    strat.adapt_jitter(429, {})
    assert strat.jitter_min >= 3.0


def test_jitter_adapt_strict_on_sucuri() -> None:
    strat = JitterStrategy()
    strat.adapt_jitter(200, {"Server": "sucuri/1.0"})
    assert strat.jitter_min >= 3.0


def test_jitter_after_request_none_is_safe() -> None:
    """after_request with ``response=None`` (network error) must not crash."""
    strat = JitterStrategy()
    # Should not raise, and should not modify state.
    original_min = strat.jitter_min
    strat.after_request("GET", "https://x", None)
    assert strat.jitter_min == original_min


def test_jitter_thread_safe() -> None:
    """Concurrent adapt_jitter calls must not corrupt internal state."""
    strat = JitterStrategy()

    def worker() -> None:
        for _ in range(100):
            strat.adapt_jitter(200, {})
            strat.adapt_jitter(403, {})

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    # Min <= max invariant must hold.
    assert strat.jitter_min <= strat.jitter_max


# -- RateLimitStrategy ------------------------------------------------------

def test_rate_limit_disabled_is_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    """A disabled RateLimiter must NOT call acquire()."""
    limiter = RateLimiter(enabled=False, rps=10, burst=20)
    # Mock acquire to track calls.
    called = []
    monkeypatch.setattr(limiter, "acquire", lambda *a, **k: called.append(a))
    strat = RateLimitStrategy(limiter)
    strat.before_request("GET", "https://example.com/x", {})
    assert called == []


def test_rate_limit_enabled_acquires_token() -> None:
    limiter = RateLimiter(enabled=True, rps=100, burst=100)
    strat = RateLimitStrategy(limiter)
    # Must not raise; first call should consume a token from a fresh bucket.
    strat.before_request("GET", "https://example.com/x", {})


def test_rate_limit_extracts_host_from_url() -> None:
    limiter = RateLimiter(enabled=True, rps=100, burst=100)
    captured: list[str] = []
    original_acquire = limiter.acquire

    def fake_acquire(host: str, *args: Any, **kwargs: Any) -> bool:
        captured.append(host)
        return original_acquire(host, *args, **kwargs)

    limiter.acquire = fake_acquire  # type: ignore[method-assign]
    strat = RateLimitStrategy(limiter)
    strat.before_request("GET", "https://api.example.com/v1/x", {})
    assert captured == ["api.example.com"]


def test_rate_limit_after_request_is_noop() -> None:
    strat = RateLimitStrategy(RateLimiter(enabled=False, rps=10, burst=20))
    # Both success and failure responses are no-ops for the rate-limit strategy.
    strat.after_request("GET", "https://x", None)
    fake_response = MagicMock()
    fake_response.status_code = 200
    strat.after_request("GET", "https://x", fake_response)


# -- DefaultStrategies factory ---------------------------------------------

class _CfgStub:
    """Minimal stand-in for ScannerConfig to exercise the factory."""
    def __init__(self, jitter_min: float = 0.5, jitter_max: float = 2.0,
                 rate_limit: Any = None) -> None:
        self.jitter_min = jitter_min
        self.jitter_max = jitter_max
        self.rate_limit = rate_limit


def test_default_strategies_minimum_set() -> None:
    """No rate_limit config → 2 strategies (Jitter + Morphing)."""
    cfg = _CfgStub(rate_limit=None)
    strategies = DefaultStrategies(cfg)
    types = [type(s).__name__ for s in strategies]
    assert "JitterStrategy" in types
    assert "MorphingHeaderStrategy" in types


def test_default_strategies_includes_rate_limit_when_enabled() -> None:
    rl = RateLimitConfig(enabled=True, rps=10, burst=20)

    class _Rl:
        def __init__(self) -> None:
            self.enabled = True
            self.rps = 10
            self.burst = 20

    cfg = _CfgStub(rate_limit=_Rl())
    strategies = DefaultStrategies(cfg)
    types = [type(s).__name__ for s in strategies]
    assert "RateLimitStrategy" in types
    assert "JitterStrategy" in types
    assert "MorphingHeaderStrategy" in types


def test_default_strategies_skips_rate_limit_when_disabled() -> None:
    """When rate_limit.enabled is False, no RateLimitStrategy is created."""

    class _Rl:
        enabled = False
        rps = 10
        burst = 20

    cfg = _CfgStub(rate_limit=_Rl())
    strategies = DefaultStrategies(cfg)
    types = [type(s).__name__ for s in strategies]
    assert "RateLimitStrategy" not in types


def test_default_strategies_propagates_jitter_window() -> None:
    cfg = _CfgStub(jitter_min=1.5, jitter_max=4.0, rate_limit=None)
    strategies = DefaultStrategies(cfg)
    jitter = next(s for s in strategies if isinstance(s, JitterStrategy))
    assert jitter.jitter_min == 1.5
    assert jitter.jitter_max == 4.0


def test_default_strategies_uses_explicit_rate_limiter(monkeypatch: pytest.MonkeyPatch) -> None:
    """If an explicit ``rate_limiter`` is passed, the factory uses it as-is."""
    sentinel = RateLimiter(enabled=True, rps=42, burst=42)

    class _Rl:
        enabled = True
        rps = 1
        burst = 1

    cfg = _CfgStub(rate_limit=_Rl())
    strategies = DefaultStrategies(cfg, rate_limiter=sentinel)
    rl_strat = next(s for s in strategies if isinstance(s, RateLimitStrategy))
    assert rl_strat._limiter is sentinel
    # rps=42 confirms the sentinel, not the config-derived one.
    assert rl_strat._limiter.rps == 42


def test_default_strategies_uses_custom_header_func() -> None:
    cfg = _CfgStub(rate_limit=None)
    sentinel: dict[str, str] = {"User-Agent": "Sentinel/1.0"}
    strategies = DefaultStrategies(cfg, header_func=lambda: dict(sentinel))
    morph = next(s for s in strategies if isinstance(s, MorphingHeaderStrategy))
    # We can't easily inspect the closure, but exercising before_request
    # should expose the sentinel.
    kwargs: dict[str, Any] = {}
    morph.before_request("GET", "https://x", kwargs)
    assert kwargs["headers"]["User-Agent"] == "Sentinel/1.0"

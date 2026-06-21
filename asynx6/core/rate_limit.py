"""Adaptive per-host token-bucket rate limiter."""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from typing import Optional


class TokenBucket:
    """Classic token bucket. Refills at `rate` tokens/sec, capacity `burst`."""

    __slots__ = ("rate", "burst", "_tokens", "_last", "_lock")

    def __init__(self, rate: float, burst: int) -> None:
        if rate <= 0 or burst <= 0:
            raise ValueError("rate and burst must be positive")
        self.rate = rate
        self.burst = burst
        self._tokens = float(burst)
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self, blocking: bool = True, timeout: Optional[float] = None) -> bool:
        """Block until a token is available, or return False if non-blocking."""
        deadline: Optional[float] = None
        if timeout is not None:
            deadline = time.monotonic() + timeout
        while True:
            with self._lock:
                now = time.monotonic()
                elapsed = now - self._last
                self._tokens = min(self.burst, self._tokens + elapsed * self.rate)
                self._last = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return True
                wait = (1.0 - self._tokens) / self.rate
            if not blocking:
                return False
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                wait = min(wait, remaining)
            time.sleep(wait)


class RateLimiter:
    """Per-host rate limiter. Disabled mode is a fast no-op."""

    def __init__(self, enabled: bool, rps: float, burst: int) -> None:
        self.enabled = enabled
        self.rps = rps
        self.burst = burst
        self._buckets: dict[str, TokenBucket] = defaultdict(
            lambda: TokenBucket(self.rps, self.burst)
        )
        self._lock = threading.Lock()

    def acquire(self, host: str, blocking: bool = True, timeout: Optional[float] = None) -> bool:
        if not self.enabled:
            return True
        with self._lock:
            bucket = self._buckets[host]
        return bucket.acquire(blocking=blocking, timeout=timeout)

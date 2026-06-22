"""Request strategies for the HTTP client (M3 of the V3 refactor).

A *strategy* is a small object that hooks into the request lifecycle of
``HttpClient``. Each strategy implements two methods:

- ``before_request(method, url, kwargs)`` — runs just before the HTTP call.
  Use this to mutate headers, sleep for jitter, acquire rate-limit tokens, etc.
- ``after_request(method, url, response)`` — runs just after a successful
  response. Use this to adapt jitter based on status code or other signals.

The orchestrator (and any future caller) can compose a list of strategies and
hand them to ``HttpClient``. Each strategy is invoked in order, so multiple
concerns (e.g. headers + jitter + rate limit) layer cleanly without one
monolithic class.

Why strategies instead of a single ``HttpClient`` with all knobs?
---------------------------------------------------------------
- The previous implementation coupled morphing headers, jitter adaptation, and
  rate limiting inside ``HttpClient``. That made it impossible to disable one
  (e.g. for tests) without re-implementing the others.
- The single ``self._lock`` on the old ``HttpClient`` also created an
  artificial serialization point: any two strategies that didn't share state
  still had to wait on the same lock. Each strategy now owns its own lock,
  so unrelated work proceeds in parallel.

Per-strategy thread safety
--------------------------
Each strategy instance is responsible for guarding any internal mutable state
with its own ``threading.Lock``. ``HttpClient`` does not wrap the call in a
shared lock — strategies are independent units.

Why a Protocol instead of an ABC?
---------------------------------
We want ``RequestStrategy`` to be duck-typed. Any class with the right two
methods is a strategy; no inheritance required. ``typing.Protocol`` makes
this explicit at type-check time while keeping the runtime free of metaclass
machinery.
"""

from __future__ import annotations

import logging
import random
import threading
import time
from typing import Any, Callable, Optional, Protocol

import requests

from asynx6.core.rate_limit import RateLimiter

log = logging.getLogger(__name__)


# -- Protocol ----------------------------------------------------------------

class RequestStrategy(Protocol):
    """Hook into the HttpClient request lifecycle.

    Strategies are called in the order they appear in the ``strategies`` list.
    All exceptions raised by a strategy are caught and logged by ``HttpClient``
    so one bad strategy never breaks the request itself.
    """

    def before_request(self, method: str, url: str, kwargs: dict[str, Any]) -> None:
        """Run just before ``session.request(method, url, **kwargs)``."""
        ...

    def after_request(
        self,
        method: str,
        url: str,
        response: Optional[requests.Response],
    ) -> None:
        """Run just after the request. ``response`` is ``None`` on network failure."""
        ...


# -- Concrete strategies -----------------------------------------------------

class MorphingHeaderStrategy:
    """Refreshes ``User-Agent`` and fingerprint headers before each request.

    Wraps the existing ``get_morphing_headers`` helper from ``core.http``.
    Each request gets a freshly randomized browser profile plus spoofed
    ``X-Forwarded-For``/``X-Real-IP`` IPs.
    """

    # Late import to avoid a circular import (http imports strategies).
    _get_headers: Callable[[], dict[str, str]]

    def __init__(self, header_func: Callable[[], dict[str, str]]) -> None:
        self._get_headers = header_func
        self._lock = threading.Lock()

    def before_request(self, method: str, url: str, kwargs: dict[str, Any]) -> None:
        # Headers are read by requests.Session.request via the ``headers`` kwarg.
        # We don't mutate the session globally — that would race with other
        # requests in flight. Pass per-request instead.
        headers = dict(kwargs.get("headers") or {})
        with self._lock:
            headers.update(self._get_headers())
        kwargs["headers"] = headers

    def after_request(
        self,
        method: str,
        url: str,
        response: Optional[requests.Response],
    ) -> None:
        # No-op: morphing headers are stateless beyond a single request.
        return None


class JitterStrategy:
    """Sleep a random duration between min and max before each request.

    Mirrors the old ``HttpClient._jitter_sleep`` behavior, but as a strategy
    so jitter can be disabled (or replaced with a different schedule) without
    touching ``HttpClient``.

    ``adapt_jitter`` is exposed so callers (e.g. a future dynamic-jitter
    strategy) can widen the sleep window on 4xx/5xx responses.
    """

    def __init__(self, jitter_min: float = 0.5, jitter_max: float = 2.0) -> None:
        if jitter_max < jitter_min:
            raise ValueError(
                f"jitter_max ({jitter_max}) must be >= jitter_min ({jitter_min})"
            )
        self.jitter_min = jitter_min
        self.jitter_max = jitter_max
        self._lock = threading.Lock()

    def before_request(self, method: str, url: str, kwargs: dict[str, Any]) -> None:
        # Snapshot under lock to avoid reading torn values during adapt.
        with self._lock:
            lo, hi = self.jitter_min, self.jitter_max
        if hi <= 0:
            return
        time.sleep(random.uniform(lo, hi))

    def after_request(
        self,
        method: str,
        url: str,
        response: Optional[requests.Response],
    ) -> None:
        if response is None:
            return
        self.adapt_jitter(response.status_code, dict(response.headers))

    def adapt_jitter(self, status_code: int, headers: dict[str, str]) -> None:
        """Back off if we got blocked, otherwise relax jitter."""
        h_str = str(headers).lower()
        if status_code in (403, 429) or "cloudflare" in h_str or "sucuri" in h_str:
            new_min, new_max = 3.0, 7.0
        else:
            new_min, new_max = 0.5, 2.0
        with self._lock:
            self.jitter_min, self.jitter_max = new_min, new_max


class RateLimitStrategy:
    """Adapts ``RateLimiter`` to the strategy interface.

    Acquires a token from the rate limiter (if enabled) just before the
    request fires. A disabled ``RateLimiter`` is a fast no-op.
    """

    def __init__(self, rate_limiter: RateLimiter) -> None:
        self._limiter = rate_limiter

    def before_request(self, method: str, url: str, kwargs: dict[str, Any]) -> None:
        from urllib.parse import urlparse
        if not self._limiter.enabled:
            return
        host = urlparse(url).netloc
        # Blocking acquire — we want to actually wait for a token, not
        # skip the request. RateLimiter has its own internal lock.
        self._limiter.acquire(host, blocking=True)

    def after_request(
        self,
        method: str,
        url: str,
        response: Optional[requests.Response],
    ) -> None:
        # No-op: token is already consumed.
        return None


# -- Factory -----------------------------------------------------------------

def DefaultStrategies(
    config: Any,
    rate_limiter: Optional[RateLimiter] = None,
    header_func: Optional[Callable[[], dict[str, str]]] = None,
) -> list[RequestStrategy]:
    """Build the default strategy list for a given ScannerConfig.

    Args:
        config: A ``ScannerConfig`` (or anything with ``jitter_min`` /
            ``jitter_max`` attributes).
        rate_limiter: Optional ``RateLimiter``. If ``None`` and
            ``config.rate_limit.enabled``, a default ``RateLimiter`` is built
            from the config.
        header_func: Optional override for the morphing-headers function.
            Defaults to ``asynx6.core.http.get_morphing_headers``.

    Returns:
        A list of strategies in execution order:
        ``[RateLimitStrategy, JitterStrategy, MorphingHeaderStrategy]``.
    """
    if header_func is None:
        from asynx6.core.http import get_morphing_headers
        header_func = get_morphing_headers

    if rate_limiter is None and getattr(config, "rate_limit", None) is not None:
        rl_cfg = config.rate_limit
        # Only build a limiter when the config actually enables rate limiting.
        # A disabled limiter would otherwise show up as a useless no-op
        # strategy in the returned list.
        if getattr(rl_cfg, "enabled", False):
            rate_limiter = RateLimiter(
                enabled=rl_cfg.enabled,
                rps=rl_cfg.rps,
                burst=rl_cfg.burst,
            )

    strategies: list[RequestStrategy] = []
    if rate_limiter is not None:
        strategies.append(RateLimitStrategy(rate_limiter))
    strategies.append(JitterStrategy(
        jitter_min=getattr(config, "jitter_min", 0.5),
        jitter_max=getattr(config, "jitter_max", 2.0),
    ))
    strategies.append(MorphingHeaderStrategy(header_func))
    return strategies

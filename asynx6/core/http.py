"""HTTP client wrapping requests.Session.

V3 refactor (M3):
- The client is a thin facade. All cross-cutting concerns (morphing headers,
  jitter, rate limiting) live in :mod:`asynx6.core.strategies` and are
  composed via a ``strategies`` list passed to ``HttpClient``.
- ``proxies``, ``verify``, and ``allow_redirects`` from ``ScannerConfig`` are
  wired into ``session.request`` so they actually take effect (previously
  the ``proxies`` field was ignored). Per-request kwargs win via
  ``setdefault`` so callers like ``vuln.open_redirect`` can override
  ``allow_redirects=False`` to inspect 3xx Location headers.
- Backward compatibility: passing the old ``jitter_min``/``jitter_max``/
  ``rate_limiter`` kwargs still works — ``HttpClient`` builds a default
  strategy list internally.
"""

from __future__ import annotations

import logging
import random
import threading
import time
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from asynx6.core.rate_limit import RateLimiter
from asynx6.core.strategies import (
    JitterStrategy,
    MorphingHeaderStrategy,
    RateLimitStrategy,
    RequestStrategy,
)

log = logging.getLogger(__name__)


# V1 browser profiles — kept verbatim for behavioral parity.
_BROWSER_PROFILES: list[dict[str, str]] = [
    {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
                  "image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Sec-Ch-Ua": '"Google Chrome";v="119", "Chromium";v="119", "Not?A_Brand";v="24"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
    },
    {
        "User-Agent": (
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 "
            "Mobile/15E148 Safari/604.1"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-GB,en;q=0.9",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
    },
]


def get_morphing_headers() -> dict[str, str]:
    """Generate a randomized browser-like header set with spoofed IPs."""
    profile = random.choice(_BROWSER_PROFILES)
    spoofed_ip = (
        f"{random.randint(1, 254)}.{random.randint(1, 254)}."
        f"{random.randint(1, 254)}.{random.randint(1, 254)}"
    )
    profile = dict(profile)
    profile.update({
        "X-Forwarded-For": spoofed_ip,
        "X-Real-IP": spoofed_ip,
        "X-Client-IP": spoofed_ip,
        "X-Forwarded-Host": "localhost",
    })
    return profile


@dataclass
class HttpResponse:
    """Lightweight wrapper around requests.Response."""

    status_code: int
    headers: dict[str, str]
    text: str
    content: bytes
    url: str
    elapsed: float

    @classmethod
    def from_requests(cls, r: requests.Response) -> "HttpResponse":
        return cls(
            status_code=r.status_code,
            headers={k: v for k, v in r.headers.items()},
            text=r.text,
            content=r.content,
            url=r.url,
            elapsed=r.elapsed.total_seconds(),
        )


class HttpClient:
    """Thread-safe HTTP client driven by a list of request strategies.

    The strategy list is the primary extension point. Each strategy's
    ``before_request`` runs in order before the network call, and
    ``after_request`` runs in order after a successful response.

    For backward compatibility, you can still construct ``HttpClient`` with
    the legacy kwargs (``jitter_min``, ``jitter_max``, ``rate_limiter``).
    They are converted into a default strategy list internally.

    Per-strategy thread safety
    --------------------------
    This class intentionally has no top-level lock. Each strategy owns its
    own lock (e.g. ``JitterStrategy._lock``), so unrelated work proceeds
    in parallel. The only shared state is the ``requests.Session`` object,
    which is itself thread-safe for per-request use.
    """

    def __init__(
        self,
        timeout: int = 10,
        strategies: Optional[list[RequestStrategy]] = None,
        *,
        pool_connections: int = 50,
        pool_maxsize: int = 50,
        proxies: Optional[list[str]] = None,
        verify_ssl: bool = True,
        follow_redirects: bool = True,
        retry_total: int = 3,
        extra_headers: Optional[dict[str, str]] = None,
        # --- Backward-compat kwargs (used when ``strategies`` is None) ---
        jitter_min: float = 0.5,
        jitter_max: float = 2.0,
        rate_limiter: Optional[RateLimiter] = None,
    ) -> None:
        self.timeout = timeout

        # Build strategies: explicit list wins, otherwise construct defaults
        # from the legacy kwargs. This keeps the old call sites working.
        if strategies is None:
            strategies = []
            if rate_limiter is not None:
                strategies.append(RateLimitStrategy(rate_limiter))
            strategies.append(JitterStrategy(jitter_min=jitter_min,
                                             jitter_max=jitter_max))
            strategies.append(MorphingHeaderStrategy(get_morphing_headers))
        self.strategies: list[RequestStrategy] = strategies

        # Expose the jitter strategy at ``self._jitter_strategy`` for
        # backward-compat with callers that read ``client.jitter_min``/``max``
        # or call ``client._jitter_sleep()``/``client.adapt_jitter()``.
        self._jitter_strategy: JitterStrategy = next(
            (s for s in self.strategies if isinstance(s, JitterStrategy)),
            JitterStrategy(jitter_min=jitter_min, jitter_max=jitter_max),
        )

        # Network options — wired into session.request below.
        self.proxies: list[str] = list(proxies or [])
        self.verify_ssl: bool = verify_ssl
        self.follow_redirects: bool = follow_redirects
        self.retry_total: int = retry_total

        # Set up the requests session with retry + connection pooling.
        self.session = requests.Session()
        retries = Retry(
            total=retry_total, backoff_factor=0.1,
            status_forcelist=[500, 502, 503, 504],
        )
        adapter = HTTPAdapter(
            pool_connections=pool_connections,
            pool_maxsize=pool_maxsize,
            max_retries=retries,
        )
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        if extra_headers:
            self.session.headers.update(extra_headers)

    # -- Backward-compat attribute accessors --------------------------------
    # The old HttpClient exposed jitter_min/jitter_max as instance attributes
    # that callers could read AND write to adapt behavior at runtime. The new
    # implementation keeps that interface by proxying to the JitterStrategy.
    @property
    def jitter_min(self) -> float:  # type: ignore[override]
        return self._jitter_strategy.jitter_min

    @jitter_min.setter
    def jitter_min(self, value: float) -> None:
        with self._jitter_strategy._lock:
            self._jitter_strategy.jitter_min = value

    @property
    def jitter_max(self) -> float:  # type: ignore[override]
        return self._jitter_strategy.jitter_max

    @jitter_max.setter
    def jitter_max(self, value: float) -> None:
        with self._jitter_strategy._lock:
            self._jitter_strategy.jitter_max = value

    @property
    def rate_limiter(self) -> Optional[RateLimiter]:
        for s in self.strategies:
            if isinstance(s, RateLimitStrategy):
                return s._limiter
        return None

    def _jitter_sleep(self) -> None:
        """Backward-compat: delegate to the JitterStrategy."""
        self._jitter_strategy.before_request("GET", "", {})

    def adapt_jitter(self, status_code: int, headers: dict[str, str]) -> None:
        """Backward-compat: delegate to the JitterStrategy."""
        self._jitter_strategy.adapt_jitter(status_code, headers)

    # -- Request methods ------------------------------------------------------
    def request(
        self,
        method: str,
        url: str,
        *,
        rate_limit: bool = True,
        jitter: bool = True,
        **kwargs: Any,
    ) -> Optional[HttpResponse]:
        """Make an HTTP request. Returns None on retryable network failure.

        Args:
            method: HTTP verb ("GET", "POST", ...).
            url: Target URL.
            rate_limit: If False, skip the rate-limit strategy even if present.
            jitter: If False, skip the JitterStrategy even if present.
            **kwargs: Forwarded to ``requests.Session.request``.
        """
        kwargs.setdefault("timeout", self.timeout)

        # Build the per-request kwarg bag that strategies will read/mutate.
        strategy_kwargs = dict(kwargs)
        # Run ``before_request`` on each strategy in order. Each strategy may
        # mutate ``strategy_kwargs`` (e.g. MorphingHeaderStrategy injects
        # headers). Failures are logged and isolated.
        for strategy in self.strategies:
            if not rate_limit and isinstance(strategy, RateLimitStrategy):
                continue
            if not jitter and isinstance(strategy, JitterStrategy):
                continue
            try:
                strategy.before_request(method, url, strategy_kwargs)
            except Exception as exc:  # noqa: BLE001
                log.warning("strategy %s before_request failed: %s",
                            type(strategy).__name__, exc)

        # Compose the final session.request kwargs: per-request strategies +
        # the configured network options. ``setdefault`` here is critical:
        # callers like ``vuln.open_redirect`` pass ``allow_redirects=False``
        # to inspect the Location header on a 302. Unconditional assignment
        # would silently follow the redirect, losing the finding.
        session_kwargs = dict(strategy_kwargs)
        if self.proxies:
            session_kwargs["proxies"] = {urlparse(url).scheme: self.proxies[0]}
        session_kwargs.setdefault("verify", self.verify_ssl)
        session_kwargs.setdefault("allow_redirects", self.follow_redirects)

        try:
            r = self.session.request(method, url, **session_kwargs)
        except (requests.RequestException, ConnectionError) as exc:
            log.warning("%s %s failed: %s", method, url, exc)
            # Still notify strategies of failure (response is None).
            for strategy in self.strategies:
                if not rate_limit and isinstance(strategy, RateLimitStrategy):
                    continue
                if not jitter and isinstance(strategy, JitterStrategy):
                    continue
                try:
                    strategy.after_request(method, url, None)
                except Exception as exc2:  # noqa: BLE001
                    log.warning("strategy %s after_request failed: %s",
                                type(strategy).__name__, exc2)
            return None

        # Run ``after_request`` on each strategy in order.
        for strategy in self.strategies:
            if not rate_limit and isinstance(strategy, RateLimitStrategy):
                continue
            if not jitter and isinstance(strategy, JitterStrategy):
                continue
            try:
                strategy.after_request(method, url, r)
            except Exception as exc:  # noqa: BLE001
                log.warning("strategy %s after_request failed: %s",
                            type(strategy).__name__, exc)

        return HttpResponse.from_requests(r)

    def get(self, url: str, **kwargs: Any) -> Optional[HttpResponse]:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> Optional[HttpResponse]:
        return self.request("POST", url, **kwargs)

    def head(self, url: str, **kwargs: Any) -> Optional[HttpResponse]:
        return self.request("HEAD", url, **kwargs)

    def close(self) -> None:
        self.session.close()

"""HTTP client wrapping requests.Session with retry, jitter, morphing headers,
and optional rate limiting.

V1 fix: replaces `utils.JITTER_MIN/MAX` global mutation and dual session creation.
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
    """Thread-safe HTTP client with per-instance jitter (V1 bug fix)."""

    def __init__(
        self,
        timeout: int = 10,
        jitter_min: float = 0.5,
        jitter_max: float = 2.0,
        pool_connections: int = 50,
        pool_maxsize: int = 50,
        rate_limiter: Optional[RateLimiter] = None,
        extra_headers: Optional[dict[str, str]] = None,
    ) -> None:
        self.timeout = timeout
        self.jitter_min = jitter_min
        self.jitter_max = jitter_max
        self.rate_limiter = rate_limiter
        self._lock = threading.Lock()

        self.session = requests.Session()
        retries = Retry(
            total=3, backoff_factor=0.1, status_forcelist=[500, 502, 503, 504]
        )
        adapter = HTTPAdapter(
            pool_connections=pool_connections,
            pool_maxsize=pool_maxsize,
            max_retries=retries,
        )
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.session.headers.update(get_morphing_headers())
        if extra_headers:
            self.session.headers.update(extra_headers)

    # -- Jitter helpers (per-instance, no global state) ----------------------
    def _jitter_sleep(self) -> None:
        time.sleep(random.uniform(self.jitter_min, self.jitter_max))

    def adapt_jitter(self, status_code: int, headers: dict[str, str]) -> None:
        """Back off if we got blocked, otherwise relax jitter."""
        h_str = str(headers).lower()
        if status_code in (403, 429) or "cloudflare" in h_str or "sucuri" in h_str:
            self.jitter_min, self.jitter_max = 3.0, 7.0
        else:
            self.jitter_min, self.jitter_max = 0.5, 2.0

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

        Applies: rate limit -> jitter -> morphing-headers refresh -> request.
        """
        kwargs.setdefault("timeout", self.timeout)
        host = urlparse(url).netloc
        if rate_limit and self.rate_limiter is not None:
            self.rate_limiter.acquire(host)
        if jitter:
            self._jitter_sleep()
        with self._lock:
            self.session.headers.update(get_morphing_headers())
        try:
            r = self.session.request(method, url, **kwargs)
        except (requests.RequestException, ConnectionError) as exc:
            log.warning("%s %s failed: %s", method, url, exc)
            return None
        self.adapt_jitter(r.status_code, r.headers)
        return HttpResponse.from_requests(r)

    def get(self, url: str, **kwargs: Any) -> Optional[HttpResponse]:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> Optional[HttpResponse]:
        return self.request("POST", url, **kwargs)

    def head(self, url: str, **kwargs: Any) -> Optional[HttpResponse]:
        return self.request("HEAD", url, **kwargs)

    def close(self) -> None:
        self.session.close()

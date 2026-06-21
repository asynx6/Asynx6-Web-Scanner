"""Wayback Machine historical endpoint discovery. New in V2.

Fetches archived URLs from web.archive.org for the target domain. Useful for
finding forgotten admin panels, debug endpoints, and old JS files that still
hold secrets.
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

import requests

log = logging.getLogger(__name__)

CDX_URL = "https://web.archive.org/cdx/search/cdx"


def _filter_interesting(urls: set[str]) -> set[str]:
    """Drop boring asset URLs and the homepage; keep admin/api/debug paths."""
    junk = ("/static/", "/assets/", "/css/", "/js/", "/img/", "/images/",
            "/fonts/", "/favicon")
    interesting: set[str] = set()
    for u in urls:
        if any(j in u for j in junk):
            continue
        parsed = urlparse(u)
        if not parsed.path or parsed.path in ("/", "/index.html"):
            continue
        interesting.add(u)
    return interesting


def run(url: str, *, limit: int = 500, **_kwargs: Any) -> set[str]:
    """Return a set of historical URLs from Wayback for `url`."""
    from asynx6.core.validators import extract_domain
    domain = extract_domain(url)
    params = {
        "url": f"*.{domain}",
        "output": "json",
        "fl": "original",
        "limit": str(limit),
        "collapse": "urlkey",
    }
    try:
        r = requests.get(CDX_URL, params=params, timeout=20)
        if r.status_code != 200:
            log.warning("Wayback CDX returned %d for %s", r.status_code, domain)
            return set()
        data = r.json()
    except (requests.RequestException, ValueError) as exc:
        log.warning("Wayback query failed for %s: %s", domain, exc)
        return set()
    if not data or len(data) < 2:
        return set()
    rows = data[1:]  # first row is header
    urls = {row[0] for row in rows if row and row[0]}
    return _filter_interesting(urls)

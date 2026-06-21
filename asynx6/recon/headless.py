"""Headless browser engine: render SPAs with Playwright, harvest links + API calls.

V1 fix: `random` import is now top-level; no print() inside module — Rich sink.
"""

from __future__ import annotations

import logging
import random
from typing import Any
from urllib.parse import urlparse

log = logging.getLogger(__name__)

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:  # pragma: no cover
    PLAYWRIGHT_AVAILABLE = False

_VIEWPORTS = [
    {"width": 1920, "height": 1080},
    {"width": 1366, "height": 768},
    {"width": 1536, "height": 864},
    {"width": 1440, "height": 900},
]
_COOKIE_BTNS = ["#login", ".btn-login", "#accept", ".cookie-accept"]


def run(url: str, **_kwargs: Any) -> dict[str, Any]:
    """Render `url` in a headless browser. Return discovered links + content.

    On any failure or absent Playwright, returns an empty result dict.
    """
    if not PLAYWRIGHT_AVAILABLE:
        log.warning("Playwright not installed; headless phase skipped")
        return {"links": set(), "content": "", "api_endpoints": []}

    result: dict[str, Any] = {"links": set(), "content": "", "api_endpoints": []}
    try:
        from asynx6.core.http import get_morphing_headers

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            headers = get_morphing_headers()
            context = browser.new_context(
                user_agent=headers["User-Agent"],
                viewport=random.choice(_VIEWPORTS),
            )
            page = context.new_page()
            domain = urlparse(url).netloc
            api_calls: list[str] = []

            def _on_request(req: Any) -> None:
                if req.resource_type in ("fetch", "xhr"):
                    if domain in req.url or "/api/" in req.url.lower():
                        api_calls.append(req.url)

            page.on("request", _on_request)
            page.goto(url, wait_until="networkidle", timeout=60_000)

            for btn in _COOKIE_BTNS:
                try:
                    if page.is_visible(btn):
                        page.click(btn)
                        page.wait_for_timeout(1000)
                except Exception:  # noqa: BLE001
                    pass

            result["content"] = page.content()
            result["api_endpoints"] = sorted(set(api_calls))
            for link in page.query_selector_all("a"):
                href = link.get_attribute("href")
                if href and href.startswith("http"):
                    result["links"].add(href.split("#")[0])
            browser.close()
    except Exception as exc:  # noqa: BLE001
        log.error("Headless engine error for %s: %s", url, exc)
    return result

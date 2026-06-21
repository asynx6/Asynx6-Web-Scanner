"""Stack detection (Chameleon).

Refactored from V1 scanner_chameleon.py. Returns a dict of detected attributes
instead of mutating a single dict; uses HttpClient instead of building its
own session.
"""

from __future__ import annotations

import logging
from typing import Any

from asynx6.core.http import HttpClient

log = logging.getLogger(__name__)


def detect_stack(url: str, *, client: HttpClient) -> dict[str, str]:
    """Probe `url` and return best-effort language/framework/cms/server guess."""
    stack: dict[str, str] = {
        "language": "Unknown",
        "framework": "Unknown",
        "cms": "None",
        "server": "Unknown",
    }
    try:
        r = client.get(url, rate_limit=False, jitter=False)
    except Exception as exc:  # noqa: BLE001
        log.warning("Stack probe failed: %s", exc)
        return stack
    if r is None:
        return stack
    headers = r.headers
    content = r.text.lower()
    cookies = client.session.cookies.get_dict()
    stack["server"] = headers.get("Server", "Unknown")

    if "php" in headers.get("X-Powered-By", "").lower() \
            or ".php" in content or "phpsessid" in cookies:
        stack["language"] = "PHP"
        if "wp-content" in content or "wp-includes" in content:
            stack["cms"] = "WordPress"

    if "react" in content or "next.js" in content or "_next/" in content:
        stack["language"] = "JavaScript (Node.js)"
        stack["framework"] = "React/Next.js"
    elif "vue" in content:
        stack["language"] = "JavaScript"
        stack["framework"] = "Vue.js"
    elif "express" in headers.get("X-Powered-By", "").lower():
        stack["language"] = "Node.js"
        stack["framework"] = "Express"

    if "jsessionid" in cookies:
        stack["language"] = "Java"
    elif "django" in content or "csrftoken" in cookies:
        stack["language"] = "Python (Django)"

    return stack
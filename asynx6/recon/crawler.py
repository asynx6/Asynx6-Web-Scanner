"""Recursive crawler with secret extraction and hidden-endpoint discovery.

V1 fix: replaces `utils.is_junk_secret` / `log_sensitive_loot` calls with the
new core validators and a typed `LootItem` payload.
"""

from __future__ import annotations

import logging
import re
from collections import deque
from typing import Any
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from asynx6.core.http import HttpClient
from asynx6.core.validators import is_junk_secret, mask_secret

log = logging.getLogger(__name__)

# (name, regex) — V1 patterns preserved.
_SECRET_PATTERNS: dict[str, str] = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Stripe API Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Auth Token": r"(?:Bearer|Token|JWT)\s+([a-zA-Z0-9\._\-]{20,})",
    "Generic Secret": r"(?:password|pwd|secret|key|auth)\s*[:=]\s*[\"']([^\"']{6,})[\"']",
    "Database Connection": r"(?:mongodb|mysql|postgresql|redis)://[a-zA-Z0-9_]+:[a-zA-Z0-9_]+@[a-zA-Z0-9_.-]+",
}
_JS_EXT = (".js", ".jsx", ".ts", ".tsx", ".css")
_BORING_PARAMS = {"id", "page", "s", "lang", "v"}


def _log_secret(output_dir: str, url: str, name: str, value: str) -> None:
    """Append raw secret to findings.md (caller opts in by passing output_dir)."""
    if not output_dir:
        return
    from datetime import datetime
    from pathlib import Path
    log_path = Path(output_dir) / "findings.md"
    if not log_path.exists():
        log_path.write_text(
            "# Findings Log\n"
            "> Raw secrets discovered during the scan. Handle with care.\n\n"
            "| Timestamp | URL | Type | Value (Raw) |\n|---|---|---|---|\n",
            encoding="utf-8",
        )
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with log_path.open("a", encoding="utf-8") as f:
        f.write(f"| {ts} | {url} | {name} | `{value}` |\n")
    log.warning("Sensitive loot: %s (%s) at %s", name, mask_secret(value), url)


def run(
    url: str,
    *,
    client: HttpClient,
    max_pages: int = 40,
    output_dir: str = "",
) -> dict[str, Any]:
    """BFS-crawl `url`, extract secrets + forms + hidden endpoints.

    Returns dict with keys: visited, urls_with_params, forms,
    hidden_endpoints, sensitive_info.
    """
    domain = urlparse(url).netloc
    visited: set[str] = set()
    queue: deque[str] = deque([url])
    params: set[str] = set()
    forms: list[dict[str, Any]] = []
    hidden: set[str] = set()
    secrets: list[dict[str, str]] = []

    def is_internal(u: str) -> bool:
        return urlparse(u).netloc == domain

    def _extract_secrets(text: str, page_url: str) -> None:
        for name, pattern in _SECRET_PATTERNS.items():
            for m in re.findall(pattern, text, re.I):
                value = m if isinstance(m, str) else m[0] if m else ""
                if not value or is_junk_secret(value):
                    continue
                _log_secret(output_dir, page_url, name, value)
                secrets.append({"type": name, "value": value, "location": page_url})

    def _extract_endpoints(text: str, base: str) -> None:
        for match in re.findall(r'"\'((?:/[a-zA-Z0-9_\-\.]+)+/?(?:\?[^"\']*)?)["\']', text):
            full = urljoin(base, match)
            if is_internal(full):
                hidden.add(full)
                if "?" in full:
                    params.add(full)
        for p in re.findall(r"(?:[?&])([a-zA-Z0-9_\-]+)=", text):
            if p not in _BORING_PARAMS:
                params.add(f"{base.split('?')[0]}?{p}=FUZZ")

    count = 0
    while queue and count < max_pages:
        current = queue.popleft()
        if current in visited:
            continue
        r = client.get(current)
        if r is None or r.status_code != 200:
            continue
        visited.add(current)
        count += 1
        _extract_secrets(r.text, current)

        if any(current.endswith(ext) for ext in _JS_EXT):
            _extract_endpoints(r.text, current)
            for match in re.findall(
                r"(?:axios|fetch)\s*\.\s*(?:get|post|put|delete|patch)?"
                r"\s*\(\s*[\"']([^\"']+)[\"']",
                r.text,
            ):
                full = urljoin(current, match)
                if is_internal(full):
                    hidden.add(full)
            continue

        soup = BeautifulSoup(r.text, "html.parser")
        for tag, attr in (("a", "href"), ("script", "src"), ("link", "href"),
                          ("iframe", "src")):
            for el in soup.find_all(tag, **{attr: True}):
                link = urljoin(current, el[attr]).split("#")[0]
                if is_internal(link) and link not in visited:
                    if "?" in link:
                        params.add(link)
                    queue.append(link)

        for form in soup.find_all("form"):
            action = form.get("action")
            method = form.get("method", "get").lower()
            form_url = urljoin(current, action) if action else current
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if not name:
                    continue
                inputs.append({"name": name, "type": inp.get("type", "text")})
            if inputs:
                forms.append({"url": form_url, "method": method, "inputs": inputs})

    return {
        "visited": sorted(visited),
        "urls_with_params": sorted(params | hidden),
        "forms": forms,
        "hidden_endpoints": sorted(hidden),
        "sensitive_info": secrets,
    }

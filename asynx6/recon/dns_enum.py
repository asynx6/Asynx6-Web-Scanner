"""DNS enumeration: SPF, DMARC, MX, TXT records. New in V2."""

from __future__ import annotations

import logging
import shutil
import subprocess
from typing import Any

log = logging.getLogger(__name__)


def _query_txt(name: str) -> list[str]:
    if not shutil.which("dig"):
        return []
    try:
        out = subprocess.run(
            ["dig", "+short", "TXT", name], capture_output=True, text=True, timeout=5
        )
        return [line.strip().strip('"') for line in out.stdout.splitlines() if line.strip()]
    except (OSError, subprocess.TimeoutExpired) as exc:
        log.debug("TXT query for %s failed: %s", name, exc)
        return []


def _query_mx(name: str) -> list[str]:
    if not shutil.which("dig"):
        return []
    try:
        out = subprocess.run(
            ["dig", "+short", "MX", name], capture_output=True, text=True, timeout=5
        )
        return [line.strip() for line in out.stdout.splitlines() if line.strip()]
    except (OSError, subprocess.TimeoutExpired) as exc:
        log.debug("MX query for %s failed: %s", name, exc)
        return []


def run(url: str, **_kwargs: Any) -> dict[str, list[str]]:
    """Enumerate SPF / DMARC / MX / TXT records for the target domain.

    Returns dict with keys: spf, dmarc, mx, txt. Each is a list of strings.
    If `dig` is not available, returns empty lists (graceful degradation).
    """
    from asynx6.core.validators import extract_domain
    domain = extract_domain(url)
    return {
        "spf": [r for r in _query_txt(domain) if r.startswith("v=spf1")],
        "dmarc": _query_txt(f"_dmarc.{domain}"),
        "mx": _query_mx(domain),
        "txt": _query_txt(domain),
    }
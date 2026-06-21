"""MySQL/MariaDB weak-credential audit.

Refactored from V1's exploit_db.py: creds are loaded from a JSON file (not
hardcoded), connect_timeout is exposed, every branch is logged.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from asynx6.core.exceptions import ExfilError
from asynx6.core.models import Finding, Severity

log = logging.getLogger(__name__)

DEFAULT_CREDS_FILE = Path(__file__).parent.parent.parent / "data" / "default_creds.json"

# V1 creds preserved as last-resort fallback.
_FALLBACK_CREDS: list[tuple[str, str]] = [
    ("root", ""), ("root", "root"), ("root", "123456"),
    ("admin", "admin"), ("mysql", "mysql"),
    ("admin123", "admin123"), ("admin", "123456"),
]


def _load_creds(path: Path | None) -> list[tuple[str, str]]:
    if path and path.is_file():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return [(c["user"], c["password"]) for c in data if "user" in c]
        except (OSError, json.JSONDecodeError, KeyError) as exc:
            log.warning("Could not load creds from %s: %s", path, exc)
    return _FALLBACK_CREDS


def run(
    ip: str,
    port: int = 3306,
    *,
    creds_file: Path | str | None = None,
    **_kwargs: Any,
) -> list[Finding]:
    """Try default creds against MySQL `ip:port`. Return a Finding if successful."""
    try:
        import mysql.connector
    except ImportError as exc:
        raise ExfilError("mysql-connector-python not installed") from exc

    creds_path = Path(creds_file) if creds_file else DEFAULT_CREDS_FILE
    creds = _load_creds(creds_path)
    findings: list[Finding] = []

    found: tuple[str, str] | None = None
    for user, pwd in creds:
        try:
            conn = mysql.connector.connect(
                host=ip, user=user, password=pwd, port=port, connect_timeout=2
            )
            if conn.is_connected():
                found = (user, pwd)
                conn.close()
                break
        except Exception as exc:  # noqa: BLE001
            log.debug("MySQL auth %s:%s failed: %s", user, pwd, exc)
            continue

    if not found:
        findings.append(Finding(
            type="Exposed MySQL port",
            severity=Severity.HIGH,
            location=f"{ip}:{port}",
            description=("Port 3306 is open but protected by password. "
                         "Vulnerable to brute force."),
        ))
        return findings

    # Deep inspection
    try:
        conn = mysql.connector.connect(
            host=ip, user=found[0], password=found[1], port=port
        )
        cur = conn.cursor()
        cur.execute("SELECT user(), current_user(), @@version, @@version_compile_os")
        user_info = cur.fetchone()
        cur.execute("SELECT @@secure_file_priv")
        file_priv = cur.fetchone()[0]
        can_write = ("YES (UNRESTRICTED)" if file_priv == ""
                     else "NO" if file_priv else "NO (DISABLED)")
        cur.execute("""
            SELECT table_schema, table_name FROM information_schema.tables
            WHERE table_name LIKE '%user%' OR table_name LIKE '%admin%' LIMIT 5
        """)
        targets = [f"{t[0]}.{t[1]}" for t in cur.fetchall()]
        conn.close()
        findings.append(Finding(
            type="SQL Direct Access — BREACHED",
            severity=Severity.CRITICAL,
            confidence=100,
            location=f"{ip}:{port}",
            payload=f"Creds: {found[0]}:{found[1]}",
            description=(
                f"Full breach! User: {user_info[0]} | OS: {user_info[3]} | "
                f"Write access: {can_write} | Targets: {', '.join(targets)}"
            ),
            remediation="Disable passwordless accounts; firewall port 3306.",
        ))
    except Exception as exc:  # noqa: BLE001
        log.error("Post-auth MySQL inspection failed: %s", exc)
    return findings

"""SQLite-backed scan history storage.

New in V3. Stores scan metadata + findings to `~/.asynx6/history.db` by default
(override with `ASYNX6_DB_PATH` env var). Provides:
- Persistent scan history
- Diff between two scans (new/removed findings)
- Query interface for trend analysis

Uses stdlib `sqlite3` only — no SQLAlchemy dependency.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Iterator

from asynx6.storage.models import DiffResult, FindingRecord, ScanRecord

log = logging.getLogger(__name__)


DEFAULT_DB_PATH = Path(
    os.environ.get("ASYNX6_DB_PATH")
    or (Path.home() / ".asynx6" / "history.db")
)


SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    aggressive INTEGER NOT NULL DEFAULT 0,
    findings_count INTEGER NOT NULL DEFAULT 0,
    subdomains_count INTEGER NOT NULL DEFAULT 0,
    loot_count INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'running'
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    type TEXT NOT NULL,
    severity TEXT NOT NULL,
    location TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    confidence INTEGER NOT NULL DEFAULT 0,
    payload TEXT,
    cvss_score REAL,
    extra_json TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(type);
"""


def init_db(path: Path | str = DEFAULT_DB_PATH) -> Path:
    """Create the schema. Idempotent. Returns the resolved db path."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(p) as conn:
        conn.executescript(SCHEMA)
    log.debug("Initialized storage at %s", p)
    return p


@contextmanager
def _connect(path: Path | str) -> Iterator[sqlite3.Connection]:
    p = Path(path)
    if not p.exists():
        init_db(p)
    conn = sqlite3.connect(p)
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


class Storage:
    """High-level interface for storing and querying scan history."""

    def __init__(self, path: Path | str = DEFAULT_DB_PATH) -> None:
        self.path = Path(path)
        self._closed = False
        init_db(self.path)

    def close(self) -> None:
        """No-op for API symmetry — connections are per-call."""
        self._closed = True

    # -- Scan lifecycle -------------------------------------------------------
    def start_scan(self, target: str, aggressive: bool = False) -> ScanRecord:
        rec = ScanRecord(target=target, aggressive=aggressive)
        with _connect(self.path) as conn:
            cur = conn.execute(
                "INSERT INTO scans (target, started_at, aggressive, status) "
                "VALUES (?, ?, ?, ?)",
                (rec.target, rec.started_at.isoformat(), int(rec.aggressive),
                 rec.status),
            )
            rec.id = cur.lastrowid
        return rec

    def finish_scan(self, scan: ScanRecord, *,
                    findings_count: int = 0,
                    subdomains_count: int = 0,
                    loot_count: int = 0,
                    status: str = "completed") -> None:
        scan.finished_at = datetime.now()
        scan.findings_count = findings_count
        scan.subdomains_count = subdomains_count
        scan.loot_count = loot_count
        scan.status = status
        with _connect(self.path) as conn:
            conn.execute(
                "UPDATE scans SET finished_at=?, findings_count=?, "
                "subdomains_count=?, loot_count=?, status=? WHERE id=?",
                (scan.finished_at.isoformat(), findings_count,
                 subdomains_count, loot_count, status, scan.id),
            )

    # -- Findings -------------------------------------------------------------
    def save_finding(self, scan_id: int, finding: FindingRecord) -> int:
        with _connect(self.path) as conn:
            cur = conn.execute(
                "INSERT INTO findings (scan_id, type, severity, location, "
                "description, confidence, payload, cvss_score, extra_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (scan_id, finding.type, finding.severity, finding.location,
                 finding.description, finding.confidence, finding.payload,
                 finding.cvss_score, finding.extra_json),
            )
            return cur.lastrowid or 0

    def save_findings(self, scan_id: int,
                      findings: list[FindingRecord]) -> None:
        with _connect(self.path) as conn:
            conn.executemany(
                "INSERT INTO findings (scan_id, type, severity, location, "
                "description, confidence, payload, cvss_score, extra_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [(scan_id, f.type, f.severity, f.location, f.description,
                  f.confidence, f.payload, f.cvss_score, f.extra_json)
                 for f in findings],
            )

    # -- Queries --------------------------------------------------------------
    def list_scans(self, target: str | None = None,
                   limit: int = 50) -> list[ScanRecord]:
        with _connect(self.path) as conn:
            if target:
                rows = conn.execute(
                    "SELECT id, target, started_at, finished_at, aggressive, "
                    "findings_count, subdomains_count, loot_count, status "
                    "FROM scans WHERE target=? ORDER BY id DESC LIMIT ?",
                    (target, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT id, target, started_at, finished_at, aggressive, "
                    "findings_count, subdomains_count, loot_count, status "
                    "FROM scans ORDER BY id DESC LIMIT ?",
                    (limit,),
                ).fetchall()
        return [_scan_row(r) for r in rows]

    def get_findings(self, scan_id: int) -> list[FindingRecord]:
        with _connect(self.path) as conn:
            rows = conn.execute(
                "SELECT id, scan_id, type, severity, location, description, "
                "confidence, payload, cvss_score, extra_json "
                "FROM findings WHERE scan_id=? ORDER BY id",
                (scan_id,),
            ).fetchall()
        return [_finding_row(r) for r in rows]

    def latest_scan(self, target: str) -> ScanRecord | None:
        with _connect(self.path) as conn:
            row = conn.execute(
                "SELECT id, target, started_at, finished_at, aggressive, "
                "findings_count, subdomains_count, loot_count, status "
                "FROM scans WHERE target=? ORDER BY id DESC LIMIT 1",
                (target,),
            ).fetchone()
        return _scan_row(row) if row else None

    def diff_scans(self, scan_id_old: int,
                   scan_id_new: int) -> DiffResult:
        """Return findings that are new, removed, or unchanged between two scans."""
        old = self.get_findings(scan_id_old)
        new = self.get_findings(scan_id_new)
        old_keys = {_finding_key(f) for f in old}
        new_keys = {_finding_key(f) for f in new}
        return DiffResult(
            new=[f for f in new if _finding_key(f) not in old_keys],
            removed=[f for f in old if _finding_key(f) not in new_keys],
            unchanged=[f for f in new if _finding_key(f) in old_keys],
        )

    def stats(self) -> dict[str, int]:
        with _connect(self.path) as conn:
            total_scans = conn.execute(
                "SELECT COUNT(*) FROM scans"
            ).fetchone()[0]
            total_findings = conn.execute(
                "SELECT COUNT(*) FROM findings"
            ).fetchone()[0]
            crit_count = conn.execute(
                "SELECT COUNT(*) FROM findings WHERE severity='CRITICAL'"
            ).fetchone()[0]
        return {
            "total_scans": total_scans,
            "total_findings": total_findings,
            "critical_findings": crit_count,
        }


# --- Helpers ----------------------------------------------------------------


def _finding_key(f: FindingRecord) -> tuple[str, str, str]:
    """Fingerprint a finding for diff purposes."""
    return (f.type, f.location, f.severity)


def _to_hashable(d: FindingRecord) -> tuple:
    """Convert frozen dataclass into a fully-hashable tuple (in case any field is mutable)."""
    return (d.type, d.location, d.severity)


def _scan_row(row: tuple) -> ScanRecord:
    if not row:
        raise ValueError("empty scan row")
    (id_, target, started_at, finished_at, aggressive,
     findings_count, subdomains_count, loot_count, status) = row
    return ScanRecord(
        id=id_, target=target,
        started_at=datetime.fromisoformat(started_at) if started_at else datetime.now(),
        finished_at=datetime.fromisoformat(finished_at) if finished_at else None,
        aggressive=bool(aggressive),
        findings_count=findings_count,
        subdomains_count=subdomains_count,
        loot_count=loot_count,
        status=status,
    )


def _finding_row(row: tuple) -> FindingRecord:
    (id_, scan_id, type_, severity, location, description,
     confidence, payload, cvss_score, extra_json) = row
    return FindingRecord(
        id=id_, scan_id=scan_id, type=type_, severity=severity,
        location=location, description=description,
        confidence=confidence, payload=payload, cvss_score=cvss_score,
        extra_json=extra_json,
    )


def finding_from_dict(d: dict, scan_id: int = 0) -> FindingRecord:
    """Build a FindingRecord from a Finding.to_dict() payload."""
    return FindingRecord(
        scan_id=scan_id,
        type=d.get("type", ""),
        severity=d.get("severity", "INFO"),
        location=d.get("location", ""),
        description=d.get("description", ""),
        confidence=d.get("confidence", 0),
        payload=d.get("payload"),
        cvss_score=d.get("cvss_score"),
        extra_json=json.dumps(d.get("extra", {})),
    )
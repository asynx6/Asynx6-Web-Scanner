"""ORM-lite data classes for scan history (SQLite-backed)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class ScanRecord:
    """One row in the `scans` table."""
    id: int | None = None
    target: str = ""
    started_at: datetime = field(default_factory=datetime.now)
    finished_at: datetime | None = None
    aggressive: bool = False
    findings_count: int = 0
    subdomains_count: int = 0
    loot_count: int = 0
    status: str = "running"  # "running" | "completed" | "failed"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "target": self.target,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "aggressive": self.aggressive,
            "findings_count": self.findings_count,
            "subdomains_count": self.subdomains_count,
            "loot_count": self.loot_count,
            "status": self.status,
        }


@dataclass(frozen=True)
class FindingRecord:
    """One row in the `findings` table — persisted per-scan finding."""
    id: int | None = None
    scan_id: int = 0
    type: str = ""
    severity: str = "INFO"
    location: str = ""
    description: str = ""
    confidence: int = 0
    payload: str | None = None
    cvss_score: float | None = None
    extra_json: str = "{}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "type": self.type,
            "severity": self.severity,
            "location": self.location,
            "description": self.description,
            "confidence": self.confidence,
            "payload": self.payload,
            "cvss_score": self.cvss_score,
            "extra": json.loads(self.extra_json),
        }


@dataclass
class DiffResult:
    """Result of comparing two scans: new / removed / unchanged findings."""
    new: list[FindingRecord]
    removed: list[FindingRecord]
    unchanged: list[FindingRecord]

    def to_dict(self) -> dict[str, Any]:
        return {
            "new": [f.to_dict() for f in self.new],
            "removed": [f.to_dict() for f in self.removed],
            "unchanged_count": len(self.unchanged),
        }
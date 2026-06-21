"""Tests for storage.db."""

from __future__ import annotations

from asynx6.storage.db import Storage, init_db
from asynx6.storage.models import FindingRecord, ScanRecord


def test_init_db_creates_file(tmp_path):
    p = tmp_path / "h.db"
    out = init_db(p)
    assert out == p
    assert p.exists()


def test_start_and_finish_scan(tmp_path):
    s = Storage(tmp_path / "h.db")
    rec = s.start_scan("https://example.com", aggressive=True)
    assert rec.id is not None
    # Status immediately after start_scan (DB still shows running)
    fresh = s.list_scans()[0]
    assert fresh.status == "running"
    s.finish_scan(rec, findings_count=5, status="completed")
    assert rec.findings_count == 5
    rows = s.list_scans()
    assert len(rows) == 1
    assert rows[0].target == "https://example.com"
    assert rows[0].findings_count == 5
    assert rows[0].status == "completed"


def test_save_and_get_findings(tmp_path):
    s = Storage(tmp_path / "h.db")
    rec = s.start_scan("https://example.com")
    findings = [
        FindingRecord(type="SQLi", severity="CRITICAL", location="/x",
                       description="desc", confidence=90),
        FindingRecord(type="XSS", severity="HIGH", location="/y",
                       description="desc2", confidence=80),
    ]
    s.save_findings(rec.id or 0, findings)
    got = s.get_findings(rec.id or 0)
    assert len(got) == 2
    assert got[0].type == "SQLi"


def test_diff_scans(tmp_path):
    s = Storage(tmp_path / "h.db")
    s1 = s.start_scan("https://x.com")
    s.save_findings(s1.id or 0, [
        FindingRecord(type="A", severity="LOW", location="/a",
                       description=""),
        FindingRecord(type="B", severity="LOW", location="/b",
                       description=""),
    ])
    s2 = s.start_scan("https://x.com")
    s.save_findings(s2.id or 0, [
        FindingRecord(type="A", severity="LOW", location="/a",
                       description=""),  # unchanged
        FindingRecord(type="C", severity="HIGH", location="/c",
                       description=""),  # new
    ])
    diff = s.diff_scans(s1.id, s2.id)
    assert len(diff.new) == 1
    assert diff.new[0].type == "C"
    assert len(diff.removed) == 1
    assert diff.removed[0].type == "B"
    assert len(diff.unchanged) == 1


def test_stats(tmp_path):
    s = Storage(tmp_path / "h.db")
    rec = s.start_scan("https://x.com")
    s.save_findings(rec.id or 0, [
        FindingRecord(type="X", severity="CRITICAL", location="/a",
                       description=""),
        FindingRecord(type="Y", severity="LOW", location="/b",
                       description=""),
    ])
    stats = s.stats()
    assert stats["total_scans"] == 1
    assert stats["total_findings"] == 2
    assert stats["critical_findings"] == 1


def test_latest_scan(tmp_path):
    s = Storage(tmp_path / "h.db")
    s.start_scan("https://a.com")
    s.start_scan("https://b.com")
    s.start_scan("https://a.com")  # same target again
    latest = s.latest_scan("https://a.com")
    assert latest is not None
    assert latest.target == "https://a.com"
    assert latest.id is not None
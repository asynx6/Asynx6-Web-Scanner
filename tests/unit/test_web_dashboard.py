"""Tests for web dashboard (FastAPI)."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import pytest


def test_create_app_requires_fastapi(monkeypatch):
    """Verify ImportError surfaces when fastapi is missing."""
    import builtins
    original_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "fastapi":
            raise ImportError("No module named 'fastapi'")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    from asynx6.web import create_app
    with pytest.raises(ImportError, match="fastapi is required"):
        create_app()


def test_create_app_runs_when_fastapi_available():
    pytest.importorskip("fastapi")
    from asynx6.web import create_app
    tmp = tempfile.mkdtemp()
    try:
        app = create_app(Path(tmp) / "h.db")
        assert app.title == "Asynx6 Dashboard"
        assert app.version == "3.0.0"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_health_endpoint():
    pytest.importorskip("fastapi")
    from asynx6.web import create_app
    from fastapi.testclient import TestClient
    tmp = tempfile.mkdtemp()
    try:
        app = create_app(Path(tmp) / "h.db")
        client = TestClient(app)
        r = client.get("/api/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_stats_endpoint_with_data():
    pytest.importorskip("fastapi")
    from asynx6.web import create_app
    from asynx6.storage.db import Storage, FindingRecord
    from fastapi.testclient import TestClient
    tmp = tempfile.mkdtemp()
    try:
        db_path = Path(tmp) / "h.db"
        storage = Storage(db_path)
        rec = storage.start_scan("https://x.test/")
        storage.save_findings(rec.id, [
            FindingRecord(type="X", severity="CRITICAL", location="/a",
                          description=""),
        ])
        storage.finish_scan(rec, findings_count=1, status="completed")
        app = create_app(db_path)
        client = TestClient(app)
        r = client.get("/api/stats")
        assert r.status_code == 200
        data = r.json()
        assert data["total_scans"] == 1
        assert data["total_findings"] == 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
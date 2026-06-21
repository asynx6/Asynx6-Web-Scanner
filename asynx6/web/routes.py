"""Dashboard API routes."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse

router = APIRouter()


@router.get("/api/scans")
async def list_scans(request: Request, limit: int = 50) -> JSONResponse:
    """List recent scans, newest first."""
    storage = request.app.state.storage
    scans = storage.list_scans(limit=limit)
    return JSONResponse([s.to_dict() for s in scans])


@router.get("/api/scans/{scan_id}/findings")
async def scan_findings(request: Request, scan_id: int) -> JSONResponse:
    """Return all findings for one scan."""
    storage = request.app.state.storage
    findings = storage.get_findings(scan_id)
    return JSONResponse([f.to_dict() for f in findings])


@router.get("/api/dashboard", response_class=HTMLResponse)
async def dashboard_html(request: Request) -> str:
    """HTMX fragment for the dashboard cards."""
    storage = request.app.state.storage
    stats = storage.stats()
    cards = (
        f'<div class="card"><h3>Total scans</h3>{stats["total_scans"]}</div>'
        f'<div class="card"><h3>Total findings</h3>{stats["total_findings"]}</div>'
        f'<div class="card"><h3>Critical findings</h3>'
        f'<span class="crit">{stats["critical_findings"]}</span></div>'
    )
    return cards
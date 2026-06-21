"""FastAPI application factory + uvicorn launcher."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


def create_app(db_path: Path | str | None = None) -> Any:
    """Build the FastAPI app. Imports fastapi lazily so the dep is optional."""
    try:
        from fastapi import FastAPI
        from fastapi.responses import HTMLResponse, JSONResponse
        from fastapi.staticfiles import StaticFiles
    except ImportError as exc:
        raise ImportError(
            "fastapi is required for the web dashboard. "
            "Install with: pip install fastapi uvicorn"
        ) from exc

    from asynx6.storage.db import Storage
    from asynx6.web.routes import router as routes_router

    storage = Storage(db_path) if db_path else Storage()

    app = FastAPI(
        title="Asynx6 Dashboard",
        version="3.0.0",
        description="Web UI for Asynx6 Web Scanner V3",
    )
    app.state.storage = storage
    app.include_router(routes_router)

    @app.get("/", response_class=HTMLResponse)
    async def index() -> str:
        return _INDEX_HTML

    @app.get("/api/health")
    async def health() -> dict[str, Any]:
        return {"status": "ok", "version": "3.0.0"}

    @app.get("/api/stats")
    async def stats() -> JSONResponse:
        return JSONResponse(storage.stats())

    return app


_INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Asynx6 Dashboard</title>
<script src="https://unpkg.com/htmx.org@1.9.10"></script>
<style>
body { font: 14px/1.5 system-ui, sans-serif; max-width: 1100px;
       margin: 2em auto; padding: 0 1em; color: #111; }
h1 { border-bottom: 2px solid #6d28d9; padding-bottom: .25em; }
table { border-collapse: collapse; width: 100%; margin-top: 1em; }
th, td { border: 1px solid #d1d5db; padding: 6px 8px; text-align: left; }
th { background: #f3f4f6; }
.crit { color: #b91c1c; font-weight: bold; }
.high { color: #c2410c; }
.med { color: #a16207; }
.row { display: flex; gap: 2em; margin: 1em 0; }
.card { padding: 1em; border: 1px solid #d1d5db; border-radius: 8px; flex: 1; }
.card h3 { margin: 0 0 .25em 0; color: #6d28d9; }
</style>
</head>
<body>
<h1>🎯 Asynx6 Dashboard</h1>
<div class="row" hx-get="/api/dashboard" hx-trigger="load" hx-swap="innerHTML">
  <div class="card"><h3>Loading…</h3></div>
</div>
<p><a href="/api/scans">View scans (JSON)</a> · <a href="/api/health">Health</a></p>
</body>
</html>
"""


def run_server(host: str = "127.0.0.1", port: int = 8080,
               db_path: Path | str | None = None) -> None:
    """Launch the web dashboard via uvicorn."""
    try:
        import uvicorn
    except ImportError as exc:
        raise ImportError(
            "uvicorn is required for the web dashboard. "
            "Install with: pip install uvicorn"
        ) from exc
    app = create_app(db_path)
    log.info("Asynx6 dashboard on http://%s:%d", host, port)
    uvicorn.run(app, host=host, port=port, log_level="info")
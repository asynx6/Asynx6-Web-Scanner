# Web Dashboard

FastAPI + HTMX single-page dashboard for browsing scan history.

## Launch

```bash
# Run scan + auto-launch dashboard
python index.py https://example.com --persist --serve

# Or launch standalone
python -c "from asynx6.web import run_server; run_server()"
```

Open `http://127.0.0.1:8080` in your browser.

## Features

- Total scan count, finding count, critical count cards
- Recent scans list with target, time, finding count
- Per-scan finding details (JSON API at `/api/scans/<id>/findings`)
- HTMX-driven interactivity (no JS framework)

## Endpoints

| Path | Description |
|---|---|
| `GET /` | Dashboard UI |
| `GET /api/health` | Liveness probe |
| `GET /api/stats` | Aggregate counts |
| `GET /api/scans?limit=N` | Recent scans (newest first) |
| `GET /api/scans/<id>/findings` | Findings for one scan |
| `GET /api/dashboard` | HTMX fragment for cards |
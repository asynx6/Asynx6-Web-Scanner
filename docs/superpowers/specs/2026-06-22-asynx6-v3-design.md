---
name: asynx6-v3-design
description: V3 mega-build — collaborator, DB persistence, CI mode, web dashboard, notifications, profiles, i18n, docs
type: project
---

# Asynx6 Web Scanner V3 — Design Specification

**Date:** 2026-06-22
**Branch:** `v3` (from `v2` @ 76c6406)

## Goals

Build on top of V2 by adding all suggested features in a single mega-release:

### V2.5 — Quick wins (low effort, high value)
- **WebSocket security scanner** (`vuln/websocket.py`)
- **Notifications** (`notifications/` — Slack/Discord/Telegram)
- **i18n** (`i18n/` — English/Indonesian)
- **Scan profiles** (`profiles.py` — quick-triage, owasp-top10, deep)

### V3 — Major features
- **SSRF Collaborator server** (`collaborator/` — out-of-band SSRF detection)
- **DB persistence** (`storage/` — SQLite scan history + diff)
- **CI/CD mode** (`ci.py` — exit codes, baseline comparison, SARIF to stdout)
- **Web dashboard** (`web/` — FastAPI + HTMX, single binary)
- **Plugin system** (`plugins/` — entry-point discovery)
- **ML false-positive heuristic** (`ml_fp.py` — TF-IDF + LogReg, optional)
- **Documentation site** (`docs/` MkDocs with API reference + tutorials)

### V3 — Quality bar
- All new modules ≥80% test coverage
- Existing 129 tests still pass
- Total coverage target: ≥75%
- CI updated to test new layers

## Architecture additions

```
asynx6/
├── collaborator/        # NEW: SSRF OOB server
│   ├── server.py
│   ├── client.py
│   └── dns.py
├── storage/             # NEW: SQLite persistence
│   ├── db.py
│   └── models.py
├── web/                 # NEW: FastAPI dashboard
│   ├── app.py
│   ├── routes.py
│   └── templates/
├── plugins/             # NEW: entry-point loader
│   └── loader.py
├── notifications/       # NEW: webhook dispatchers
│   ├── base.py
│   ├── slack.py
│   ├── discord.py
│   └── telegram.py
├── i18n/                # NEW: translation strings
│   ├── en.py
│   └── id.py
├── ci.py                # NEW: CI-mode entry point
├── profiles.py          # NEW: scan profiles
└── ml_fp.py             # NEW: optional ML false-positive filter

docs/                    # NEW: MkDocs site
├── mkdocs.yml
├── index.md
├── install.md
├── usage.md
├── modules/
└── api/

.github/workflows/
├── ci.yml               # UPDATED: add storage/collaborator tests
└── release.yml          # NEW: tag-based PyPI release
```

## Out of scope (V4+)

- Distributed scanning (Redis queue)
- Mobile API scanner
- AD/network pentest modules
- VSCode extension

## Migration

- No breaking changes to V2 API
- New dependencies: `fastapi`, `uvicorn`, `aiosqlite`, `aiosmtpd` (for collaborator SMTP), `httpx`
- ML dep is optional (`scikit-learn`)
- All gated behind existing V2 entry points; new features opt-in via flags
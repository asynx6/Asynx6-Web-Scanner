# Changelog

## V3.0.0 (2026-06-22)

Major release. All features from V2 preserved, plus:

### Added — Quick wins
- **WebSocket security scanner** (`vuln/websocket.py`)
- **Notifications** — Slack, Discord, Telegram, generic webhook
- **i18n** — English + Indonesian output
- **5 scan profiles** — quick-triage, owasp-top10, deep, stealth, ci

### Added — Major features
- **SSRF Collaborator server** — OOB SSRF detection via DNS + HTTP callbacks
- **SQLite storage layer** — persistent scan history + diff between scans
- **CI/CD mode** — exit codes, baseline comparison, SARIF to stdout
- **Web dashboard** — FastAPI + HTMX single-binary deployment
- **Plugin system** — entry-point discovery via `importlib.metadata`
- **ML false-positive filter** — TF-IDF + LogReg (optional, requires sklearn)
- **MkDocs documentation site** — install, quickstart, CI, profiles, modules

### Changed
- `ScannerConfig` extended with V3 fields (locale, profile, notifiers, persist, ml_filter, collaborator_domain, web_dashboard)
- Orchestrator wires in V3 phases (notifications, persistence, ML filter)

## V2.0.0 (2026-06-21)

Major rewrite from V1:
- Clean 3-layer architecture (core / modules / engine)
- Fixed V1 bugs (global jitter, bare except, hardcoded creds)
- New vuln modules (JWT, GraphQL, SSRF, Open Redirect, CORS)
- New recon (DNS enum, Wayback)
- Nuclei-style template loader
- SARIF + JSON + HTML report formats
- CVSS v3.1 scoring
- Textual TUI dashboard
- 129 unit tests, 71.91% coverage
- GitHub Actions CI

## V1.0.0 (2026-06-20)

Initial release. Monolithic scanner in `modules/` with:
- Subdomain + network recon
- SQLi / XSS / LFI / Headers
- WAF detection, port scanning
- Markdown PoC report
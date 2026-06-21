# 🎯 Asynx6 Web Scanner

Advanced web security reconnaissance suite. Detects sensitive file leakage,
hidden directory structures, server misconfigurations, and modern web
vulnerabilities (JWT, GraphQL, SSRF, WebSocket) with high precision.

Equipped with **Apex Predator Logic**: filters false positives from WAF/CDN
protection, distinguishes real findings from SPA soft-404s, and applies
adaptive stealth with jitter + header morphing.

## V3 Highlights

- **SSRF Collaborator server** — out-of-band SSRF detection via DNS + HTTP callbacks
- **DB persistence** — SQLite-backed scan history with diff between scans
- **CI/CD mode** — exit codes, baseline comparison, SARIF for GitHub Code Scanning
- **Web dashboard** — FastAPI + HTMX, view scan history in browser
- **Notifications** — Slack, Discord, Telegram, generic webhook
- **Plugin system** — entry-point discovery for third-party modules
- **ML false-positive filter** — TF-IDF + LogReg (optional, requires scikit-learn)
- **WebSocket security scanner** — CSWSH detection
- **5 scan profiles** — quick-triage, owasp-top10, deep, stealth, ci
- **i18n** — English + Indonesian output

## Quick start

```bash
pip install -r requirements.txt
playwright install chromium
python index.py https://example.com
```

See [Getting Started](getting-started/install.md) for details.

## License

MIT © 2026 asynx6
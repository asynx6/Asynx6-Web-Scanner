# Asynx6 Web Scanner V3

Web security reconnaissance suite. Detects sensitive file leakage, hidden
directories, server misconfigurations, and modern web vulnerabilities (JWT,
GraphQL, SSRF, WebSocket). Produces structured PoC reports with WAF/CDN
bypass filtering, SPA soft-404 detection, and adaptive stealth (jitter +
header morphing).

## V3 Highlights (over V2)

### Major features
- **SSRF Collaborator server** — out-of-band SSRF detection via DNS + HTTP callbacks
- **SQLite storage layer** — persistent scan history with diff between scans
- **CI/CD mode** — exit codes, baseline comparison, SARIF for GitHub Code Scanning
- **Web dashboard** — FastAPI + HTMX, view scan history in browser
- **Plugin system** — entry-point discovery via `importlib.metadata`
- **ML false-positive filter** — TF-IDF + LogReg (optional, requires scikit-learn)
- **MkDocs documentation site** — install, quickstart, CI, profiles, modules

### Quick wins
- **WebSocket security scanner** — CSWSH + endpoint discovery
- **Notifications** — Slack, Discord, Telegram, generic webhook
- **i18n** — English + Indonesian output
- **5 scan profiles** — quick-triage, owasp-top10, deep, stealth, ci

### Internal refactor (3 cluster)

Quality-of-engineering pass. **Zero user-facing changes** — same CLI, same YAML schema,
same vuln modules. Targeted at testability, extensibility, and race-condition safety.

| Milestone | Scope | Commit |
|---|---|---|
| **M1** Config & Notifier | Pydantic discriminated union for notifiers, `apply_profile()` fix, typed notification phase | `1bf7439` |
| **M2** Phase registry | `asynx6/engine/phases.py` registry, orchestrator data-driven, plugin injection in `run()` | `eaf4bd7` |
| **M3** HttpClient facade | `RequestStrategy` Protocol + 3 strategies (morphing headers, jitter, rate-limit), per-strategy locks, **caller-kwarg precedence fix** for `verify`/`allow_redirects` | `cf28a95` |

Full breakdown in `docs/changelog.md`. Design rationale in
`docs/superpowers/specs/2026-06-22-asynx6-v3-refactor-3-cluster-design.md`.

Verification: **295 passed, 3 skipped** (`pytest`); zero regression.

## V2 Foundation (preserved)

- Clean 3-layer architecture (`core` / `recon-vuln-fuzz-exfil-reporting` / `engine`)
- New vuln modules: **JWT**, **GraphQL**, **SSRF**, **open redirect**, **CORS**
- New recon: **DNS enumeration**, **Wayback Machine** historical endpoints
- **Nuclei-style YAML templates** for custom checks
- **SARIF / JSON / HTML** export with **CVSS v3.1** scoring
- **Interactive TUI** dashboard (Textual)
- **Adaptive per-host rate limiting** (token bucket)
- **Comprehensive test suite** (pytest, ≥75% coverage, CI on GitHub Actions)
- Type hints throughout, structured logging, modern packaging (`pyproject.toml`)

## Installation

Requires **Python 3.10+**.

```bash
git clone https://github.com/asynx6/Asynx6-Web-Scanner.git
cd Asynx6-Web-Scanner
pip install -r requirements.txt
playwright install chromium   # for SPA crawling
```

For development (lint + test):

```bash
pip install -e ".[dev]"
pytest
ruff check .
mypy asynx6
```

## Usage

### Single target

```bash
python index.py https://example.com
```

### Scan profiles

```bash
python index.py https://example.com --profile quick-triage
python index.py https://example.com --profile owasp-top10
python index.py https://example.com --profile deep
python index.py https://example.com --profile stealth
python index.py https://example.com --profile ci
```

### Batch (file of targets)

```bash
python index.py list_target.txt --aggressive
```

### Interactive TUI / Web dashboard

```bash
python index.py --tui               # Textual terminal UI
python index.py https://x.test --serve   # Web dashboard on :8080
```

### CI/CD mode

```bash
python -m asynx6.ci https://target.com \
  --format sarif \
  --output results.sarif \
  --severity-threshold HIGH
```

### CLI flags

```
python index.py [TARGET] [OPTIONS]

TARGET               URL or path to .txt list of targets
-a, --aggressive     Enable aggressive fuzzing & discovery
--tui                Launch interactive Textual dashboard
--threads N          Worker threads (default 25)
--timeout SECONDS    HTTP timeout (default 10)
--output-dir PATH    Results directory (default ./results)
--format FMT         markdown | json | sarif | html | all (default markdown)
--config PATH        YAML config file
--no-banner          Suppress ASCII banner
--locale en|id       Output language (default: en)
--profile NAME       quick-triage | owasp-top10 | deep | stealth | ci
--serve              Launch web dashboard after scan
--persist            Save scan history to SQLite (~/.asynx6/history.db)
--ml-filter          Apply ML false-positive filter (requires scikit-learn)
```

### Config file (`config.yaml`)

```yaml
jitter_min: 0.5
jitter_max: 2.0
threads: 25
timeout: 10
aggressive: false
output_dir: results
report_format: markdown
locale: en
persist: false
ml_filter: false
collaborator_domain: collab.yourdomain.com
notifiers:
  - kind: slack
    webhook_url: https://hooks.slack.com/services/YOUR/WEBHOOK
    channel: "#security"
  - kind: discord
    webhook_url: https://discord.com/api/webhooks/YOUR/WEBHOOK
rate_limit:
  enabled: true
  rps: 10
  burst: 20
```

## Modules

### V3 new packages
- `collaborator/` — SSRF OOB detection (server + client)
- `storage/` — SQLite scan history
- `web/` — FastAPI dashboard
- `notifications/` — Slack/Discord/Telegram/webhook dispatch
- `plugins/` — entry-point plugin loader
- `i18n/` — translation strings (en, id)
- `ci.py` — CI/CD mode entry point
- `profiles.py` — scan profile registry
- `ml_fp.py` — TF-IDF + LogReg false-positive filter

### Layers

| Layer | Module | Purpose |
|---|---|---|
| core | `http.py` | HTTP client with retry + jitter + adaptive rate limit |
| core | `validators.py` | URL/secret/junk validators |
| core | `rate_limit.py` | Per-host token bucket |
| core | `strategies.py` | `RequestStrategy` Protocol + morphing/jitter/rate-limit strategies |
| core | `models.py` | Domain types (Finding, Subdomain, OriginIP, ...) |
| recon | `subdomain` | crt.sh + wordlist + wildcard detection |
| recon | `network` | Port scan, WAF detection, CDN bypass |
| recon | `dns_enum` | SPF / DMARC / MX / TXT |
| recon | `wayback` | Wayback Machine historical endpoints |
| recon | `headless` | Playwright SPA crawling |
| recon | `crawler` | Spidering + secret extraction |
| recon | `architect` | JS bundle entropy + JWT hints |
| vuln | `sqli` | Oracle time-based double-check |
| vuln | `xss` | Reflected XSS |
| vuln | `lfi` | Local file inclusion |
| vuln | `ssrf` | SSRF + IMDS + internal IP |
| vuln | `open_redirect` | Chain detection |
| vuln | `jwt` | none-alg / weak HS256 / RS256 confusion |
| vuln | `graphql` | Introspection + deep query |
| vuln | `cors` | CORS misconfiguration |
| vuln | `headers` | Security header audit |
| vuln | `idor` | Insecure direct object reference |
| vuln | `websocket` | CSWSH + endpoint discovery |
| fuzz | `directory` | Brute + 403 bypass + SPA baseline |
| fuzz | `api` | API endpoint fuzzing |
| fuzz | `templates` | Nuclei-style YAML templates |
| exfil | `db_mysql` | MySQL/MariaDB weak-creds audit |
| exfil | `secrets_archive` | Categorize findings log |
| reporting | `markdown` | PoC report (Markdown) |
| reporting | `json_export` | SARIF + custom JSON |
| reporting | `html_report` | Self-contained HTML with charts |
| reporting | `cvss` | CVSS v3.1 base score |
| engine | `orchestrator` | Phase orchestration |
| engine | `phases.py` | Phase registry (PhaseSpec, register_phase, get_phase, filter_active) |
| engine | `scheduler` | DAG-based phase scheduling |
| engine | `batch` | Multi-target multiprocessing pool |
| tui | `app` | Textual interactive dashboard |

## Architecture

Three-layer dependency rule:

```
core (zero deps)
  ↑
recon / vuln / fuzz / exfil / reporting  (depend only core)
  ↑
engine  (orchestrate all L2)
  ↑
tui  (consume engine events)
```

See `docs/superpowers/specs/2026-06-21-asynx6-v2-design.md` for the full spec.

## System Requirements

- Python 3.10+
- **Required**: `requests`, `rich`, `beautifulsoup4`, `urllib3`, `playwright` (+ `playwright install chromium`), `mysql-connector-python`, `pyyaml`, `pydantic`, `textual`
- **Optional — Dashboard**: `fastapi`, `uvicorn`
- **Optional — ML filter**: `scikit-learn`
- **Optional — Docs**: `mkdocs`, `mkdocs-material`

## Legal Disclaimer

This software is strictly for educational purposes and authorized security
auditing only. The author (`asynx6`) is not responsible for any misuse,
unauthorized access, or damage caused. Use only on targets where you have
explicit, written consent.

## License

MIT © 2026 asynx6

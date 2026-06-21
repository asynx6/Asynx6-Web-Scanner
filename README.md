# Asynx6 Web Scanner V2

Advanced web security reconnaissance suite. Detects sensitive file leakage, hidden
directories, server misconfigurations, modern web vulnerabilities (JWT, GraphQL,
SSRF), and produces structured PoC reports.

Equipped with **Apex Predator Logic**: filters false positives from WAF/CDN
protection (HCDN), distinguishes real findings from SPA soft-404s, and applies
adaptive stealth with jitter + header morphing.

## V2 Highlights

- Clean 3-layer architecture (`core` / `recon-vuln-fuzz-exfil-reporting` / `engine`)
- New vuln modules: **JWT**, **GraphQL**, **SSRF**, **open redirect**, **CORS**
- New recon: **DNS enumeration**, **Wayback Machine** historical endpoints
- **Nuclei-style YAML templates** for custom checks
- **SARIF / JSON / HTML** export with **CVSS v3.1** scoring
- **Interactive TUI** dashboard (Textual)
- **Adaptive per-host rate limiting** (token bucket)
- **Comprehensive test suite** (pytest, ≥70% coverage, CI on GitHub Actions)
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

### Batch (file of targets)

```bash
python index.py list_target.txt --aggressive
```

### Interactive TUI

```bash
python index.py --tui
```

### CLI flags

```
python index.py [TARGET] [OPTIONS]

TARGET               URL or path to .txt list of targets (positional, optional
                     if --tui is given)

-a, --aggressive     Enable aggressive fuzzing & discovery
--tui                Launch interactive Textual dashboard
--threads N          Worker threads (default 25)
--timeout SECONDS    HTTP timeout (default 10)
--output-dir PATH    Results directory (default ./results)
--format FMT         Report format: markdown | json | sarif | html (default markdown)
--config PATH        YAML config file
--no-banner          Suppress ASCII banner
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
user_agents:
  - Mozilla/5.0 ...
proxies: []
rate_limit:
  enabled: true
  rps: 10
  burst: 20
```

## Modules

| Layer | Module | Purpose |
|---|---|---|
| core | `http.py` | HTTP client with retry + jitter + adaptive rate limit |
| core | `validators.py` | URL/secret/junk validators |
| core | `rate_limit.py` | Per-host token bucket |
| core | `models.py` | Domain types (Finding, Subdomain, OriginIP, ...) |
| recon | `subdomain` | crt.sh + wordlist + wildcard detection |
| recon | `network` | Port scan, WAF detection, CDN bypass |
| recon | `dns_enum` | SPF / DMARC / MX / TXT |
| recon | `wayback` | Wayback Machine historical endpoints |
| recon | `headless` | Playwright SPA crawling |
| recon | `crawler` | Spidering + secret extraction |
| vuln | `sqli` | Oracle time-based double-check |
| vuln | `xss` | Reflected XSS |
| vuln | `lfi` | Local file inclusion |
| vuln | `ssrf` | SSRF + DNS rebinding |
| vuln | `open_redirect` | Chain detection |
| vuln | `jwt` | none-alg / weak HS256 / RS256 confusion |
| vuln | `graphql` | Introspection + deep query |
| vuln | `cors` | CORS misconfiguration |
| vuln | `headers` | Security header audit |
| vuln | `idor` | Insecure direct object reference |
| fuzz | `directory` | Brute + 403 bypass + SPA baseline |
| fuzz | `api` | API endpoint fuzzing |
| fuzz | `templates` | Nuclei-style YAML templates |
| exfil | `db_mysql` | MySQL/MariaDB weak-creds audit |
| exfil | `secrets_archive` | Categorize LOOT_VAULT findings |
| reporting | `markdown` | PoC report (Markdown) |
| reporting | `json_export` | SARIF + custom JSON |
| reporting | `html_report` | Self-contained HTML with charts |
| reporting | `cvss` | CVSS v3.1 base score |
| engine | `orchestrator` | Phase orchestration |
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
- `requests`, `rich`, `beautifulsoup4`, `urllib3`
- `playwright` (+ `playwright install chromium`)
- `mysql-connector-python` (for DB audit)
- `pyyaml` (template loader)
- `pydantic` (config validation)
- `textual` (optional, for TUI)

## Legal Disclaimer

This software is strictly for educational purposes and authorized security
auditing only. The author (`asynx6`) is not responsible for any misuse,
unauthorized access, or damage caused. Use only on targets where you have
explicit, written consent.

## License

MIT © 2026 asynx6

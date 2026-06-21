---
name: asynx6-v2-design
description: Upgrade V2 besar-besaran Asynx6 Web Scanner — refactor arsitektur, fitur baru, testing komprehensif
type: project
---

# Asynx6 Web Scanner V2 — Design Specification

**Date:** 2026-06-21
**Branch:** `v2`
**Status:** Approved (user delegated full authority)

## Goals

1. **Refactor arsitektur** dari monolitik `index.py` + `utils.py` jadi clean 3-lapis (core/recon-vuln-fuzz-exfil-reporting/engine/tui)
2. **Fix bug kritis** V1: global `JITTER_MIN/MAX` race condition, session shadowing, no error handling, code orphan `.pyc`
3. **Tambah fitur baru**: JWT attacks, GraphQL, SSRF, open redirect, DNS enum, Wayback, nuclei-style templates, SARIF export, CVSS scoring, interactive TUI
4. **Tambah testing** komprehensif: pytest + mocking + fixtures + CI GitHub Actions, target ≥70% coverage
5. **Modern packaging**: `pyproject.toml`, type hints, structured logging
6. **Push ke GitHub** `v2` branch dengan commit history rapi

## Arsitektur (3-Lapis)

- **L1 — Core** (`asynx6/core/`): zero-dependency types + HttpClient + validators + rate limiter
- **L2 — Modules** (`asynx6/{recon,vuln,fuzz,exfil,reporting}/`): depend only core
- **L3 — Engine** (`asynx6/engine/`): orchestrator, scheduler, batch
- **UI** (`asynx6/tui/`): Textual interactive dashboard

Lihat struktur direktori lengkap di section berikutnya.

## Bug Fix List (V1)

| Bug | Lokasi | Fix |
|---|---|---|
| Global `JITTER_MIN/MAX` mutation | `utils.py:6-14` | Pindah ke `HttpClient` instance attribute, immutable per client |
| Session shadowing (2 cara bikin session) | `index.py:42` + `utils.get_session()` | Single `HttpClient` injected via constructor |
| `try/except: pass` tanpa log | semua modul | `SafeError` hierarchy + `loguru` warning |
| `print()` campur `console.print()` | `scanner_subdomain`, `scanner_chameleon`, dll | Seragamkan ke Rich `console` |
| `index.py` import semua modul di top-level | `index.py:12` | Lazy import via `engine.orchestrator` |
| `.pyc` orphan `scanner_advanced.cpython-313.pyc` | `modules/__pycache__/` | Hapus saat refactor |
| Hardcoded creds di `exploit_db.py:8-11` | `exploit_db.py` | Load dari `data/default_creds.txt` |
| Tidak ada type hints | semua | Tambah `typing` + `@dataclass` |
| Tidak ada `__init__.py` proper | `modules/` | Replace dengan proper package |
| `log_file` opened but never closed if error | `index.py:52` | Context manager `with open(...)` |

## Fitur Baru (V2)

1. **JWT attacks** (`vuln/jwt.py`): alg=none, weak HS256 (top-1000 secret list), RS256→HS256 confusion
2. **GraphQL** (`vuln/graphql.py`): introspection, deep query DoS, field suggestion leak
3. **SSRF** (`vuln/ssrf.py`): parameter injection + internal IP detection + DNS rebinding
4. **Open redirect** (`vuln/open_redirect.py`): chain detection with allowlist bypass
5. **DNS enum** (`recon/dns_enum.py`): SPF, DMARC, MX, TXT records
6. **Wayback** (`recon/wayback.py`): historical endpoint discovery via web.archive.org
7. **Nuclei-style templates** (`fuzz/templates.py`): YAML template loader with custom engine
8. **CVSS v3.1** (`reporting/cvss.py`): base score calculator from findings
9. **SARIF export** (`reporting/json_export.py`): for IDE integration
10. **HTML report** (`reporting/html_report.py`): self-contained with chart.js
11. **Textual TUI** (`tui/app.py`): interactive dashboard (optional, --tui flag)
12. **Adaptive rate limit** (`core/rate_limit.py`): per-host token bucket
13. **Config file** (`config.py`): YAML config + CLI overrides
14. **CI/CD** (`.github/workflows/ci.yml`): ruff + mypy + pytest on PR

## Testing Strategy

- **Unit tests** (`tests/unit/`): 1 file per source module, mock HTTP via `responses` library
- **Integration tests** (`tests/integration/`): end-to-end against `httpbin` fixtures
- **Fixtures** (`tests/fixtures/`): recorded JSON of HTTP responses, sample findings, sample JWT tokens
- **Coverage target**: ≥70% line coverage (focus on core + vuln modules)
- **CI**: GitHub Actions on push/PR to v2 branch

## Constraints & Decisions

- **Backward compat**: keep `index.py` as entry point (calls into `asynx6.engine`)
- **Python**: 3.10+ (matches V1 requirement)
- **No new heavy deps** beyond V1 except: `pyyaml` (templates), `pydantic` (config), `textual` (TUI, optional), `responses` (test), `pytest`/`pytest-cov`/`pytest-mock` (test)
- **No DB**: use file-based results (keep V1 pattern)
- **One module = one purpose**: smaller files, clear boundaries

## Migration Path

1. V2 package `asynx6/` lives parallel to `modules/` during transition
2. V1 `modules/` re-exports through `asynx6.modules` for one release
3. V3 removes `modules/` entirely (not in this scope)

## Out of Scope (V2)

- Distributed scanning (Redis queue) — V3
- Plugin marketplace — V3
- Cloud native deployment — V3
- ML-based false positive — V3

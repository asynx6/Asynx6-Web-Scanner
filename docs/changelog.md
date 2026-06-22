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

### Added — Internal refactor (3 cluster)

Quality-of-engineering pass. Zero user-facing changes; same CLI, same YAML surface,
same vuln modules. Targeted at testability, extensibility, and race-condition safety.

**M1 — Config & Notifier (`1bf7439`)**
- `NotifierConfig` becomes a Pydantic discriminated union (`kind: slack | discord | telegram | webhook`)
- New Slack / Discord / Telegram / generic-webhook models with full field validation
- `ScannerConfig` extended with `proxies`, `verify_ssl`, `follow_redirects`, `retry_total`
- Fixed `apply_profile()` in `profiles.py` to use `model_dump(exclude_unset=True)` so partial
  profile overrides no longer clobber explicitly-set config fields
- Orchestrator `_phase_notifications` now consumes a typed Pydantic model, not raw dicts
- Test surface: discriminated-union dispatch, profile merge semantics, notifier contracts

**M2 — Phase registry & plugin injection (`eaf4bd7`)**
- New `asynx6/engine/phases.py` — `PhaseSpec`, `PHASE_REGISTRY`, `register_phase()`,
  `get_phase()`, `filter_active()` primitives. The orchestrator's 18 module-level
  `_phase_*` functions are now data, not scattered code.
- Orchestrator refactored: `_register_default_phases()` populates the registry on import;
  no `mkdir` happens at module import time (moved into `run()`)
- `ScanContext` gains `active_phases: set[str]` so plugins can introspect what is scheduled
- `discover_plugins().apply_to(self)` runs at the start of `run()` (after config load,
  before phase dispatch) — third-party entry-points can now register additional phases
- Test surface: registry CRUD, orchestrator wiring, plugin extension (9 cases), notification
  phase contract (8 cases)

**M3 — HttpClient strategy facade (`cf28a95`)**
- New `asynx6/core/strategies.py` — `RequestStrategy` Protocol with three concrete strategies:
  `MorphingHeaderStrategy` (User-Agent rotation), `JitterStrategy` (thread-safe
  `adapt_jitter()` via per-instance `_lock`), `RateLimitStrategy` (delegates to existing
  per-host token bucket). `DefaultStrategies` factory skips `RateLimitStrategy` when
  `rate_limit.enabled=False`.
- `HttpClient` rewritten as a thin facade composing the strategy chain. Each strategy owns
  its own lock — no top-level HttpClient lock, so rate-limit sleeps no longer block jitter
  or header morphing on other workers.
- Backward-compat property shims (`jitter_min`, `jitter_max`, `rate_limiter`) preserve the
  legacy public surface — old call sites still work unchanged.
- **Critical regression fix discovered during verification**: per-request kwargs now use
  `setdefault("verify", ...)` and `setdefault("allow_redirects", ...)` instead of
  unconditional assignment. This preserves caller precedence over `HttpClient` defaults.
  Without this fix, `vuln/open_redirect.py` would silently follow 3xx redirects on probe
  URLs, breaking 28 probes (7 parameters × 4 payloads) with `ConnectionError` against
  the `responses` mock. Caught only because the full 295-test suite exercises both the
  facade and the live integration path.

**Verification**
- `pytest`: **295 passed, 3 skipped** in 7m33s. Skips are environmental only
  (no localhost HTTP server, scikit-learn optional dep).
- Zero regression. No new vuln modules, no CLI flags, no YAML schema changes,
  no entry-point changes — strict adherence to the "3 cluster" refactor scope.

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
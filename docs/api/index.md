# API Reference

## Top-level

- `asynx6.engine.orchestrator.Orchestrator` — drives a scan
- `asynx6.cli.main(argv)` — entry point
- `asynx6.ci.run_ci(args)` — CI-mode entry point

## Core

- `asynx6.core.http.HttpClient` — HTTP client with retry + jitter + rate limit
- `asynx6.core.config.ScannerConfig` — Pydantic config model
- `asynx6.core.models.{Finding, ScanContext, Severity}` — domain types
- `asynx6.core.validators` — URL/secret/entropy utilities
- `asynx6.core.rate_limit.RateLimiter` — per-host token bucket
- `asynx6.core.exceptions` — custom exception hierarchy

## Modules

See [Recon](../modules/recon.md), [Vuln](../modules/vuln.md), [Fuzz](../modules/fuzz.md), [Reporting](../modules/reporting.md) for module-by-module API.

## V3 additions

- `asynx6.collaborator.{CollaboratorServer, CollaboratorClient}` — OOB SSRF
- `asynx6.storage.db.Storage` — SQLite persistence
- `asynx6.web.create_app(db_path)` — FastAPI dashboard
- `asynx6.notifications.{Slack, Discord, Telegram, Webhook}Notifier` — alert dispatch
- `asynx6.plugins.loader.discover_plugins` — entry-point discovery
- `asynx6.ml_fp.FalsePositiveFilter` — ML re-scoring
- `asynx6.profiles.{quick_triage, owasp_top10, deep, stealth, ci_pipeline}` — presets
- `asynx6.i18n.{t, set_locale, get_locale}` — translation
- `asynx6.vuln.websocket.run` — WebSocket scanner
# Asynx6 V3 — Refactor 3 Cluster (Config, Phase, HttpClient)

**Tanggal**: 2026-06-22
**Status**: Disetujui, in-eksekusi
**Pendekatan**: Bertahap (M1 → M2 → M3), internal-only, tidak ada perubahan API publik.

## Latar Belakang

Kritik tajam terhadap workspace V3 mengidentifikasi 3 cluster utang teknis:

1. **M1 — Config & Notifier**: `apply_profile` logika terbalik (line 124–127 `profiles.py`); `NotifierConfig` pydantic tanpa `extra='allow'`; `_phase_notifications` di `orchestrator.py` baca `cfg.get("kind")` pada `NotifierConfig` (pydantic), bukan dict — `AttributeError` saat notifier aktif.
2. **M2 — Phase Registry & Plugin**: 17 method `_phase_*` hardcoded di `Orchestrator`; `discover_plugins()` di `plugins/loader.py` tidak pernah dipanggil — plugin V3 adalah dead code.
3. **M3 — HttpClient Strategy**: morphing headers, jitter adaptif, dan rate limit ter-couple di `HttpClient`; `proxies: list[str]` di ScannerConfig diabaikan; race condition pada `adapt_jitter`.

Tujuan refactor: kode lebih **stabil, testable, powerfull** — bukan project abal-abal.

## Scope & Non-Scope

**In-scope**: refactor internal, fix bug, naikkan test coverage.
**Out-of-scope**: tambah modul vuln baru, ubah CLI, ubah output format, ubah konvensi config YAML publik.

## M1 — Config & Notifier

### Perubahan

**`asynx6/core/config.py`**:
- `NotifierConfig` jadi **discriminated union** via `Annotated` + `Field(discriminator="kind")`.
- Tambah model `SlackNotifierConfig`, `DiscordNotifierConfig`, `TelegramNotifierConfig`, `GenericWebhookNotifierConfig` dengan field spesifik per kind.
- `ScannerConfig.notifiers: list[NotifierConfig]` (tetap).
- Tambah `proxies: list[str] = []` (sudah ada, dipakai di M3) dan `verify_ssl: bool = True`, `follow_redirects: bool = True`.

**`asynx6/profiles.py`**:
- Fix `apply_profile`: precedence **CLI > profile > user config > default**. Perilaku baru: `return base.model_copy(update=profile.config.model_dump())` — **profile wins atas base**, lalu CLI override semuanya (di-handle `cli.py`).

**`asynx6/engine/orchestrator.py::_phase_notifications`**:
- Iterasi `cfg.notifiers` (pydantic model), bukan `cfg.get("kind")` di dict. Dispatch lewat `Notification` registry yang sudah ada.
- Filter unknown kind dengan log warning, jangan crash.

### Test M1

- `tests/unit/test_config.py` — tambah test discriminated union (4 kind, validasi field, kind unknown).
- `tests/unit/test_profiles.py` — tambah test: profile menang atas base; CLI flag tetap menang (test integrasi tipis di `cli.py`).
- `tests/unit/test_notifications.py` — tambah test `_phase_notifications` dengan mock notifier, pydantic model.

## M2 — Phase Registry & Plugin

### Perubahan

**`asynx6/engine/phases.py` (new)**:
- `PhaseSpec` dataclass: `name: str`, `label: str`, `func: Callable[..., None]`, `category: Literal["recon","vuln","fuzz","exfil","post"]`.
- `PHASE_REGISTRY: list[PhaseSpec]` — semua phase V3 (chameleon, subdomain, ..., persist) dideklarasi sebagai list.
- `enabled_phases: list[str]` di `Profile` memfilter registry; kalau kosong/None, semua phase jalan.

**`asynx6/engine/orchestrator.py`**:
- `__init__` tidak lagi punya 17 method `_phase_*`.
- `run()` jadi loop: `for spec in PHASE_REGISTRY: if spec.name in active_phases: spec.func(self, progress)`.
- Panggil `discover_plugins().apply_to(self)` di awal `run()`. Plugin yang mau inject phase bisa append ke `PHASE_REGISTRY` (ekspos `PHASE_REGISTRY` sebagai module-level mutable, atau lewat context API).
- Tambah `active_phases: set[str]` di `ScanContext` (default: semua phase).
- `Orchestrator.__init__` tidak `mkdir` — pindahkan ke `run()` setelah konfigurasi final.

**`asynx6/plugins/loader.py`**:
- Tambah `register_phase(name, func, **kw)` helper di `PluginRegistry` untuk plugin yang mau nyuntik phase.
- Dokumentasi plugin di docstring `discover_plugins()`.

### Test M2

- `tests/unit/test_engine_orchestrator.py` — tambah test `PHASE_REGISTRY` keutuhan, urutan, aktif/nonaktif.
- `tests/unit/test_plugins.py` — tambah test plugin dummy yang register phase, lalu scan lihat phase jalan.
- `tests/integration/test_phase_order.py` (jika belum ada) — verifikasi urutan eksekusi sesuai ekspektasi.

## M3 — HttpClient Strategy

### Perubahan

**`asynx6/core/strategies.py` (new)**:
- `RequestStrategy` Protocol: `before_request(method, url, kwargs) -> None`, `after_request(method, url, response) -> None`.
- `MorphingHeaderStrategy` — pindah dari `core/http.py::get_morphing_headers`.
- `JitterStrategy` — pindah dari `core/http.py::HttpClient._jitter_sleep` + `adapt_jitter`.
- `RateLimitStrategy` — adapt `RateLimiter` jadi strategy.
- `DefaultStrategies` factory: rakit list strategi default dari `ScannerConfig`.

**`asynx6/core/http.py`**:
- `HttpClient` jadi facade tipis: `__init__(timeout, strategies: list[RequestStrategy], **kwargs)`.
- `request()` panggil `strategy.before_request()` urut, lalu `session.request()`, lalu `strategy.after_request()` urut.
- `proxies`, `verify`, `allow_redirects` di-wire ke `session.request` (dari `ScannerConfig`).
- Thread-safety: pakai `threading.Lock` per strategy, bukan satu lock di HttpClient (race condition fix).

**`asynx6/core/rate_limit.py`**:
- `RateLimiter` tetap (sudah terisolasi), hanya adapt ke `RequestStrategy` interface.

### Test M3

- `tests/unit/test_http.py` — tambah test strategi hook dipanggil pada urutan benar, race condition bebas.
- `tests/unit/test_strategies.py` (new) — test masing-masing strategi secara independen.
- `tests/unit/test_config.py` — tambah test `proxies`/`verify_ssl`/`follow_redirects` field.

## Test Coverage Target

- Saat ini: ~70% (per `pyproject.toml` `fail_under`).
- Target setelah refactor: **≥75%**, terutama di area `engine/orchestrator.py`, `core/http.py`, `core/config.py`.

## Verifikasi Akhir

- `pytest` lulus 100%, coverage ≥75%.
- `ruff check .` lulus.
- `mypy asynx6` lulus (tidak ada regresi).
- Smoke test: `python index.py list_target.txt` (mode batch) tidak crash.
- Manual verification: fixture file di `tests/fixtures/` masih menghasilkan output yang valid (regressi test).

## Risiko

- **M1 rendah**: perubahan lokal di 3 file.
- **M2 sedang**: ubah arsitektur Orchestrator, plugin jadi hidup (resiko side effect pada plugin lama).
- **M3 sedang**: perubahan HttpClient bisa memengaruhi timeout/header di seluruh module L2. Testing M3 harus jalan integrasi ke vuln/.

## Out of Scope (Eksplisit)

- Tidak tambah modul vuln baru (JWT/GraphQL/SSRF/...) di refactor ini.
- Tidak ubah format report (markdown/SARIF/JSON/HTML).
- Tidak ubah CLI flag.
- Tidak ubah entry point script (`index.py`, `python -m asynx6`).
- Tidak ubah konvensi YAML config publik (field `notifiers:` tetap, hanya shape internal yang lebih ketat).

"""Top-level orchestrator: drives all phases and produces reports.

V2.5 / V3 enhancements:
- Optional DB persistence (via storage.Storage)
- Optional ML false-positive filter
- Optional plugin loading (now actually called from ``run``)
- Optional notification dispatch on CRITICAL findings

V3 refactor (M2):
- 18 hardcoded ``_phase_*`` methods replaced with a flat ``PHASE_REGISTRY``
  of :class:`asynx6.engine.phases.PhaseSpec`. Plugins can now inject or
  override phases at runtime.
- Output directories are created in ``run`` (post-config) rather than
  ``__init__`` so a partially-constructed orchestrator never leaves
  half-written output dirs on disk.
- ``ctx.active_phases`` carries the allowlist computed from the active profile.
"""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from rich.console import Console
from rich.progress import Progress, TextColumn

from asynx6.core.config import ScannerConfig
from asynx6.core.http import HttpClient
from asynx6.core.models import Finding, ScanContext, Severity
from asynx6.core.rate_limit import RateLimiter
from asynx6.core.validators import extract_domain, normalize_url

if TYPE_CHECKING:
    pass

log = logging.getLogger(__name__)
console = Console()


# ---------------------------------------------------------------------------
# Phase implementations (M2: module-level functions, not bound methods)
# ---------------------------------------------------------------------------
# Each function takes the orchestrator + a rich.Progress. Errors are caught
# and logged inside the function so a single bad phase never aborts the
# whole scan. The orchestrator does NOT wrap them in try/except itself.


def _phase_chameleon(orch: "Orchestrator", progress: Progress) -> None:
    from asynx6.recon.chameleon import detect_stack
    task = progress.add_task("[scan]stack detection", total=None)
    try:
        stack = detect_stack(orch.target, client=orch.client)
        orch.ctx.tech_stack = stack
    except Exception as exc:  # noqa: BLE001
        log.warning("chameleon phase failed: %s", exc)
        orch.ctx.tech_stack = {"language": "Unknown", "framework": "Unknown"}
    progress.update(task, completed=True)


def _phase_subdomain(orch: "Orchestrator", progress: Progress) -> None:
    from asynx6.recon.subdomain import run as subdomain_run
    task = progress.add_task("[green]Subdomain recon", total=None)
    try:
        orch.ctx.subdomains = subdomain_run(
            orch.target, client=orch.client, threads=orch.config.threads
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("subdomain phase failed: %s", exc)
    progress.update(task, completed=True)


def _phase_network(orch: "Orchestrator", progress: Progress) -> None:
    from asynx6.recon.network import run as network_run
    task = progress.add_task("[cyan]Network recon (port + WAF)", total=None)
    try:
        net = network_run(orch.target, orch.client, full_port_scan=False)
        orch.ctx.waf = net.get("waf", "None")
        orch.ctx.open_ports = net.get("ports", [])
        orch.ctx.origin_ips = net.get("origin_ips", [])
    except Exception as exc:  # noqa: BLE001
        log.warning("network phase failed: %s", exc)
    progress.update(task, completed=True)


def _phase_dns_enum(orch: "Orchestrator", progress: Progress) -> None:
    from asynx6.recon.dns_enum import run as dns_run
    task = progress.add_task("[blue]DNS enum", total=None)
    try:
        dns_run(orch.target)
    except Exception as exc:  # noqa: BLE001
        log.warning("dns_enum phase failed: %s", exc)
    progress.update(task, completed=True)


def _phase_wayback(orch: "Orchestrator", progress: Progress) -> None:
    from asynx6.recon.wayback import run as wayback_run
    task = progress.add_task("[yellow]Wayback historical", total=None)
    try:
        wayback_run(orch.target)
    except Exception as exc:  # noqa: BLE001
        log.warning("wayback phase failed: %s", exc)
    progress.update(task, completed=True)


def _phase_headless(orch: "Orchestrator", progress: Progress) -> None:
    from asynx6.recon.headless import run as headless_run
    task = progress.add_task("[purple]Headless SPA crawler", total=None)
    try:
        data = headless_run(orch.target)
        orch.ctx.dynamic_content = data.get("content", "")
        orch.ctx.pages_visited.update(data.get("links", set()))
    except Exception as exc:  # noqa: BLE001
        log.warning("headless phase failed: %s", exc)
    progress.update(task, completed=True)


def _phase_crawler(orch: "Orchestrator", progress: Progress) -> None:
    from asynx6.recon.crawler import run as crawler_run
    task = progress.add_task("[magenta]Spidering + secret extraction", total=None)
    try:
        result = crawler_run(
            orch.target, client=orch.client,
            max_pages=40, output_dir=str(orch.base_dir),
        )
        orch.ctx.pages_visited.update(result.get("visited", []))
        orch.ctx.hidden_endpoints.update(result.get("hidden_endpoints", []))
        orch.ctx.forms.extend(result.get("forms", []))
        for sec in result.get("sensitive_info", []):
            orch.ctx.add_finding(Finding(
                type=f"Secret leak: {sec['type']}",
                severity=Severity.HIGH,
                location=sec["location"],
                description=f"Exposed sensitive value at {sec['location']}",
                confidence=80,
            ))
    except Exception as exc:  # noqa: BLE001
        log.warning("crawler phase failed: %s", exc)
    progress.update(task, completed=True)


def _phase_architect(orch: "Orchestrator", progress: Progress) -> None:
    """Analyze crawled JS files for additional secrets (V2 architect)."""
    from asynx6.recon.architect import analyze
    task = progress.add_task("[cyan]JS Architect", total=None)
    js_files = [u for u in orch.ctx.pages_visited if u.endswith(".js")]
    for js_url in js_files[:20]:
        try:
            r = orch.client.get(js_url)
            if r is None or r.status_code != 200:
                continue
            findings = analyze(js_url, r.text, output_dir=str(orch.base_dir))
            orch.ctx.extend_findings(findings)
        except Exception as exc:  # noqa: BLE001
            log.warning("architect %s: %s", js_url, exc)
    progress.update(task, completed=True)


def _phase_vuln(orch: "Orchestrator", progress: Progress) -> None:
    from asynx6 import vuln
    phases = (
        ("sqli", vuln.sqli_run),
        ("xss", vuln.xss_run),
        ("lfi", vuln.lfi_run),
        ("ssrf", vuln.ssrf_run),
        ("open_redirect", vuln.open_redirect_run),
        ("jwt", vuln.jwt_run),
        ("graphql", vuln.graphql_run),
        ("cors", vuln.cors_run),
        ("headers", vuln.headers_run),
        ("idor", vuln.idor_run),
    )
    for name, fn in phases:
        task = progress.add_task(f"[yellow]vuln:{name}", total=None)
        try:
            orch.ctx.extend_findings(fn(orch.target, client=orch.client))
        except Exception as exc:  # noqa: BLE001
            log.warning("vuln %s failed: %s", name, exc)
        progress.update(task, completed=True)


def _phase_vuln_websocket(orch: "Orchestrator", progress: Progress) -> None:
    from asynx6.vuln.websocket import run as ws_run
    task = progress.add_task("[orange1]vuln:websocket", total=None)
    try:
        orch.ctx.extend_findings(ws_run(orch.target, client=orch.client))
    except Exception as exc:  # noqa: BLE001
        log.warning("vuln websocket failed: %s", exc)
    progress.update(task, completed=True)


def _phase_fuzz_directory(orch: "Orchestrator", progress: Progress) -> None:
    from asynx6.fuzz.directory import run as directory_run
    task = progress.add_task("[green]Directory fuzz", total=None)
    try:
        results = directory_run(
            orch.target, client=orch.client,
            aggressive=orch.config.aggressive,
            threads=orch.config.threads,
            content_baseline=orch.ctx.dynamic_content or None,
        )
        for r in results:
            if r["status"] == 200:
                fname = r["url"].rsplit("/", 1)[-1] or "loot.bin"
                safe = fname.replace(".", "_").replace("/", "_") or "loot.html"
                path = orch.loot_dir / safe
                path.write_bytes(r["content"])
                orch.ctx.add_finding(Finding(
                    type=f"Exposed file: {fname}",
                    severity=Severity.HIGH,
                    location=r["url"],
                    description=f"File {fname} returned HTTP 200",
                ))
    except Exception as exc:  # noqa: BLE001
        log.warning("directory fuzz failed: %s", exc)
    progress.update(task, completed=True)


def _phase_fuzz_api(orch: "Orchestrator", progress: Progress) -> None:
    from asynx6.fuzz.api import run as api_run
    task = progress.add_task("[green]API fuzz", total=None)
    try:
        orch.ctx.extend_findings(api_run(orch.target, client=orch.client))
    except Exception as exc:  # noqa: BLE001
        log.warning("api fuzz failed: %s", exc)
    progress.update(task, completed=True)


def _phase_exfil_db(orch: "Orchestrator", progress: Progress) -> None:
    from asynx6.exfil.db_mysql import run as db_run
    if not any(p.port == 3306 for p in orch.ctx.open_ports):
        return
    task = progress.add_task("[red]DB audit (3306)", total=None)
    try:
        orch.ctx.extend_findings(db_run(orch.domain, port=3306))
    except Exception as exc:  # noqa: BLE001
        log.warning("db audit failed: %s", exc)
    progress.update(task, completed=True)


def _phase_templates(orch: "Orchestrator", progress: Progress) -> None:
    from asynx6.fuzz.templates import load_templates, run_templates
    tmpl_dir = Path(__file__).parent.parent.parent / "templates"
    templates = load_templates(tmpl_dir)
    if not templates:
        return
    task = progress.add_task("[magenta]Custom templates", total=None)
    try:
        orch.ctx.extend_findings(run_templates(
            templates, orch.target, client=orch.client
        ))
    except Exception as exc:  # noqa: BLE001
        log.warning("templates phase failed: %s", exc)
    progress.update(task, completed=True)


def _phase_secrets_archive(orch: "Orchestrator", progress: Progress) -> None:
    from asynx6.exfil.secrets_archive import run as secrets_run
    vault = orch.base_dir / "findings.md"
    if not vault.exists():
        return
    task = progress.add_task("[yellow]Secrets archive", total=None)
    try:
        secrets_run(vault, orch.base_dir)
    except Exception as exc:  # noqa: BLE001
        log.warning("secrets archive failed: %s", exc)
    progress.update(task, completed=True)


def _phase_ml_filter(orch: "Orchestrator", progress: Progress) -> None:
    """V3: re-score findings with the ML false-positive filter."""
    if not getattr(orch.config, "ml_filter", False):
        return
    task = progress.add_task("[cyan]ML FP filter", total=None)
    try:
        from asynx6.ml_fp import FalsePositiveFilter
        flt = FalsePositiveFilter()
        if flt.fit_seed():
            for f in orch.ctx.findings:
                flt.adjust(f)
    except Exception as exc:  # noqa: BLE001
        log.warning("ml_fp phase failed: %s", exc)
    progress.update(task, completed=True)


def _phase_notifications(orch: "Orchestrator", progress: Progress) -> None:
    """V3: dispatch notifications for CRITICAL findings."""
    notifiers = list(getattr(orch.config, "notifiers", None) or [])
    if not notifiers:
        return
    task = progress.add_task("[bright_red]Notifications", total=None)
    crit = [f for f in orch.ctx.findings if f.severity == Severity.CRITICAL]
    if not crit:
        progress.update(task, completed=True)
        return
    try:
        from asynx6.notifications import Notification
        from asynx6.notifications.slack import SlackNotifier
        from asynx6.notifications.discord import DiscordNotifier
        from asynx6.notifications.telegram import TelegramNotifier
        from asynx6.notifications.webhook import WebhookNotifier

        def _build(cfg_obj):
            data = cfg_obj.model_dump()
            kind = data.pop("kind")
            cls = {
                "slack": SlackNotifier,
                "discord": DiscordNotifier,
                "telegram": TelegramNotifier,
                "webhook": WebhookNotifier,
            }.get(kind)
            if cls is None:
                log.warning("Unknown notifier kind: %s", kind)
                return None
            try:
                return cls(**data)
            except Exception as exc:  # noqa: BLE001
                log.warning("Notifier %s init failed: %s", kind, exc)
                return None

        payload = Notification(
            title=f"[Asynx6] {len(crit)} CRITICAL finding(s) on {orch.target}",
            message=f"Top finding: {crit[0].type} at {crit[0].location}",
            severity="CRITICAL",
            url=orch.target,
        )
        for cfg_obj in notifiers:
            notifier = _build(cfg_obj)
            if notifier is None:
                continue
            try:
                notifier.send(payload)
            except Exception as exc:  # noqa: BLE001
                log.warning("Notifier send failed: %s", exc)
    except Exception as exc:  # noqa: BLE001
        log.warning("notifications phase failed: %s", exc)
    progress.update(task, completed=True)


def _phase_persist(orch: "Orchestrator", progress: Progress) -> None:
    """V3: persist scan + findings to SQLite."""
    if not getattr(orch.config, "persist", False):
        return
    task = progress.add_task("[green]Persist to DB", total=None)
    try:
        from asynx6.storage.db import Storage, finding_from_dict
        storage = Storage()
        rec = storage.start_scan(orch.target, aggressive=orch.config.aggressive)
        storage.finish_scan(
            rec,
            findings_count=len(orch.ctx.findings),
            subdomains_count=len(orch.ctx.subdomains),
            loot_count=len(orch.ctx.loot),
        )
        records = [finding_from_dict(f.to_dict(), scan_id=rec.id or 0)
                   for f in orch.ctx.findings]
        storage.save_findings(rec.id or 0, records)
    except Exception as exc:  # noqa: BLE001
        log.warning("persist phase failed: %s", exc)
    progress.update(task, completed=True)


def _register_default_phases() -> None:
    """Populate ``PHASE_REGISTRY`` with the built-in V3 phases.

    Idempotent: safe to call multiple times (re-registration replaces by
    name). Lives in this module rather than in ``phases.py`` so the
    orchestrator owns its own phase set without forcing the phase registry
    to know about every business module.
    """
    from asynx6.engine.phases import register_phase

    builtins = (
        ("chameleon", "Stack detection", "recon", _phase_chameleon),
        ("subdomain", "Subdomain recon", "recon", _phase_subdomain),
        ("network", "Network recon (ports + WAF)", "recon", _phase_network),
        ("dns_enum", "DNS enum", "recon", _phase_dns_enum),
        ("wayback", "Wayback historical", "recon", _phase_wayback),
        ("headless", "Headless SPA crawler", "recon", _phase_headless),
        ("crawler", "Spidering + secret extraction", "recon", _phase_crawler),
        ("architect", "JS Architect", "recon", _phase_architect, ("crawler",)),
        ("vuln", "Vulnerability scan (10 modules)", "vuln", _phase_vuln),
        ("vuln_websocket", "WebSocket vuln", "vuln", _phase_vuln_websocket),
        ("fuzz_directory", "Directory fuzz", "fuzz", _phase_fuzz_directory),
        ("fuzz_api", "API fuzz", "fuzz", _phase_fuzz_api),
        ("fuzz_templates", "Custom templates", "fuzz", _phase_templates),
        ("exfil_db", "DB audit (3306)", "exfil", _phase_exfil_db),
        ("secrets_archive", "Secrets archive", "exfil", _phase_secrets_archive),
        ("ml_filter", "ML false-positive filter", "post", _phase_ml_filter),
        ("notifications", "Critical-finding notifications", "post", _phase_notifications),
        ("persist", "Persist scan to SQLite", "post", _phase_persist),
    )
    for entry in builtins:
        if len(entry) == 4:
            name, label, category, func = entry
            register_phase(name, label, category, func)
        else:
            name, label, category, func, requires = entry
            register_phase(name, label, category, func, requires=requires)


_register_default_phases()


class Orchestrator:
    """Drives a full scan. Build with a ScannerConfig, then call ``run()``."""

    def __init__(self, target: str, config: ScannerConfig) -> None:
        self.target = normalize_url(target)
        self.config = config
        self.domain = extract_domain(self.target)
        self.timestamp = _timestamp()
        self.base_dir = Path(config.output_dir) / f"{self.domain}_{self.timestamp}"
        self.loot_dir = self.base_dir / "loot"
        # NOTE: directory creation moved to ``run()`` so partially-built
        # orchestrators (e.g. failed plugin load) never leave empty dirs.

        self.ctx = ScanContext(
            target=self.target,
            base_url=self.target,
            domain=self.domain,
            aggressive=config.aggressive,
            output_dir=str(self.base_dir),
        )
        rate = RateLimiter(
            enabled=config.rate_limit.enabled,
            rps=config.rate_limit.rps,
            burst=config.rate_limit.burst,
        )
        self.client = HttpClient(
            timeout=config.timeout,
            jitter_min=config.jitter_min,
            jitter_max=config.jitter_max,
            rate_limiter=rate,
        )

    def run(self) -> ScanContext:
        """Execute all phases and write reports. Returns the populated context."""
        # M2 fix: only now — after config is finalized — create output dirs.
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.loot_dir.mkdir(parents=True, exist_ok=True)

        # Populate active_phases from profile (if any). Empty set = run all.
        self._load_active_phases_from_profile()

        # M2: plugin injection point. Plugins can call ``register_phase(...)``
        # to extend or override the built-in PHASE_REGISTRY.
        try:
            from asynx6.plugins.loader import discover_plugins
            discover_plugins().apply_to(self)
        except Exception as exc:  # noqa: BLE001
            log.warning("Plugin discovery failed: %s", exc)

        from asynx6.engine.phases import filter_active

        active = filter_active(self.ctx.active_phases or None)

        with Progress(TextColumn("[progress.description]{task.description}"),
                      console=console) as progress:
            for spec in active:
                log.debug("running phase: %s (%s)", spec.name, spec.category)
                spec.func(self, progress)

        self._write_reports()
        self._print_summary()
        return self.ctx

    def _load_active_phases_from_profile(self) -> None:
        """If a profile is set, copy its ``enabled_phases`` into the context.

        Unknown phase names in the profile are silently dropped — they may
        belong to plugins that have not been loaded yet.
        """
        profile_name = getattr(self.config, "profile", None)
        if not profile_name:
            self.ctx.active_phases = set()
            return
        try:
            from asynx6.profiles import get_profile
            profile = get_profile(profile_name)
        except (KeyError, ImportError) as exc:
            log.warning("Unknown profile %r: %s — running all phases", profile_name, exc)
            self.ctx.active_phases = set()
            return
        self.ctx.active_phases = set(profile.enabled_phases)

    # -- Reporting ------------------------------------------------------------
    def _write_reports(self) -> None:
        from asynx6.reporting import markdown, json_export, html_report
        fmt = self.config.report_format
        try:
            if fmt == "markdown":
                markdown.generate(self.target, self.ctx, self.base_dir)
            elif fmt == "json":
                json_export.generate_json(self.ctx, self.base_dir)
            elif fmt == "sarif":
                json_export.generate_sarif(self.ctx, self.base_dir)
            elif fmt == "html":
                html_report.generate(self.target, self.ctx, self.base_dir)
            elif fmt == "all":
                markdown.generate(self.target, self.ctx, self.base_dir)
                json_export.generate_json(self.ctx, self.base_dir)
                json_export.generate_sarif(self.ctx, self.base_dir)
                html_report.generate(self.target, self.ctx, self.base_dir)
        except Exception as exc:  # noqa: BLE001
            log.warning("report generation failed: %s", exc)

    def _print_summary(self) -> None:
        from rich.table import Table
        t = Table(title=f"Asynx6 V3 Summary — {self.target}", show_header=True)
        t.add_column("Metric", style="cyan")
        t.add_column("Count", style="white")
        t.add_row("Findings", str(len(self.ctx.findings)))
        t.add_row("Subdomains", str(len(self.ctx.subdomains)))
        t.add_row("Origin IPs", str(len(self.ctx.origin_ips)))
        t.add_row("Open Ports", str(len(self.ctx.open_ports)))
        t.add_row("Loot Items", str(len(self.ctx.loot)))
        crit = sum(1 for f in self.ctx.findings if f.severity == Severity.CRITICAL)
        t.add_row("CRITICAL", str(crit))
        console.print(t)


def _timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")
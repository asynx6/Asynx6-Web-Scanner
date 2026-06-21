"""Top-level orchestrator: runs all phases in order and produces reports.

Replaces V1's `LScanMaster` class with a typed, exception-safe pipeline.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.progress import Progress, TextColumn

from asynx6.core.config import ScannerConfig
from asynx6.core.http import HttpClient
from asynx6.core.models import Finding, ScanContext, Severity
from asynx6.core.rate_limit import RateLimiter
from asynx6.core.validators import extract_domain, normalize_url

log = logging.getLogger(__name__)
console = Console()


# Phase registry — each entry is (name, fn, optional: required condition)
# Order matters; later phases may depend on results of earlier ones.
class Orchestrator:
    """Drives a full scan. Build with a ScannerConfig, then call `run()`."""

    def __init__(self, target: str, config: ScannerConfig) -> None:
        self.target = normalize_url(target)
        self.config = config
        self.domain = extract_domain(self.target)
        self.timestamp = _timestamp()
        self.base_dir = Path(config.output_dir) / f"{self.domain}_{self.timestamp}"
        self.loot_dir = self.base_dir / "loot"
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.loot_dir.mkdir(parents=True, exist_ok=True)

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
        with Progress(TextColumn("[progress.description]{task.description}"),
                      console=console) as progress:
            self._phase_chameleon(progress)
            self._phase_subdomain(progress)
            self._phase_network(progress)
            self._phase_dns_enum(progress)
            self._phase_wayback(progress)
            self._phase_headless(progress)
            self._phase_crawler(progress)
            self._phase_vuln(progress)
            self._phase_fuzz_directory(progress)
            self._phase_fuzz_api(progress)
            self._phase_exfil_db(progress)
            self._phase_templates(progress)
            self._phase_secrets_archive(progress)

        self._write_reports()
        self._print_summary()
        return self.ctx

    # -- Phase implementations ------------------------------------------------
    def _phase_chameleon(self, progress: Progress) -> None:
        from asynx6.recon.chameleon import detect_stack
        task = progress.add_task("[omniscient]Chameleon: stack detection", total=None)
        try:
            stack = detect_stack(self.target, client=self.client)
            self.ctx.tech_stack = stack
        except Exception as exc:  # noqa: BLE001
            log.warning("chameleon phase failed: %s", exc)
            self.ctx.tech_stack = {"language": "Unknown", "framework": "Unknown"}
        progress.update(task, completed=True)

    def _phase_subdomain(self, progress: Progress) -> None:
        from asynx6.recon.subdomain import run as subdomain_run
        task = progress.add_task("[green]Subdomain recon", total=None)
        try:
            self.ctx.subdomains = subdomain_run(
                self.target, client=self.client, threads=self.config.threads
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("subdomain phase failed: %s", exc)
        progress.update(task, completed=True)

    def _phase_network(self, progress: Progress) -> None:
        from asynx6.recon.network import run as network_run
        task = progress.add_task("[cyan]Network recon (port + WAF)", total=None)
        try:
            net = network_run(self.target, self.client, full_port_scan=False)
            self.ctx.waf = net.get("waf", "None")
            self.ctx.open_ports = net.get("ports", [])
            self.ctx.origin_ips = net.get("origin_ips", [])
        except Exception as exc:  # noqa: BLE001
            log.warning("network phase failed: %s", exc)
        progress.update(task, completed=True)

    def _phase_dns_enum(self, progress: Progress) -> None:
        from asynx6.recon.dns_enum import run as dns_run
        task = progress.add_task("[blue]DNS enum", total=None)
        try:
            dns_run(self.target)
        except Exception as exc:  # noqa: BLE001
            log.warning("dns_enum phase failed: %s", exc)
        progress.update(task, completed=True)

    def _phase_wayback(self, progress: Progress) -> None:
        from asynx6.recon.wayback import run as wayback_run
        task = progress.add_task("[yellow]Wayback historical", total=None)
        try:
            wayback_run(self.target)
        except Exception as exc:  # noqa: BLE001
            log.warning("wayback phase failed: %s", exc)
        progress.update(task, completed=True)

    def _phase_headless(self, progress: Progress) -> None:
        from asynx6.recon.headless import run as headless_run
        task = progress.add_task("[purple]Headless SPA crawler", total=None)
        try:
            data = headless_run(self.target)
            self.ctx.dynamic_content = data.get("content", "")
            self.ctx.pages_visited.update(data.get("links", set()))
        except Exception as exc:  # noqa: BLE001
            log.warning("headless phase failed: %s", exc)
        progress.update(task, completed=True)

    def _phase_crawler(self, progress: Progress) -> None:
        from asynx6.recon.crawler import run as crawler_run
        task = progress.add_task("[magenta]Spidering + secret extraction", total=None)
        try:
            result = crawler_run(
                self.target, client=self.client,
                max_pages=40, output_dir=str(self.base_dir),
            )
            self.ctx.pages_visited.update(result.get("visited", []))
            self.ctx.hidden_endpoints.update(result.get("hidden_endpoints", []))
            self.ctx.forms.extend(result.get("forms", []))
            for sec in result.get("sensitive_info", []):
                self.ctx.add_finding(Finding(
                    type=f"Secret leak: {sec['type']}",
                    severity=Severity.HIGH,
                    location=sec["location"],
                    description=f"Exposed sensitive value at {sec['location']}",
                    confidence=80,
                ))
        except Exception as exc:  # noqa: BLE001
            log.warning("crawler phase failed: %s", exc)
        progress.update(task, completed=True)

    def _phase_vuln(self, progress: Progress) -> None:
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
                self.ctx.extend_findings(
                    fn(self.target, client=self.client)
                )
            except Exception as exc:  # noqa: BLE001
                log.warning("vuln %s failed: %s", name, exc)
            progress.update(task, completed=True)

    def _phase_fuzz_directory(self, progress: Progress) -> None:
        from asynx6.fuzz.directory import run as directory_run
        task = progress.add_task("[green]Directory fuzz", total=None)
        try:
            results = directory_run(
                self.target, client=self.client,
                aggressive=self.config.aggressive,
                threads=self.config.threads,
                content_baseline=self.ctx.dynamic_content or None,
            )
            for r in results:
                if r["status"] == 200:
                    fname = r["url"].rsplit("/", 1)[-1] or "loot.bin"
                    safe = fname.replace(".", "_").replace("/", "_") or "loot.html"
                    path = self.loot_dir / safe
                    path.write_bytes(r["content"])
                    self.ctx.loot.append(_make_loot(r["url"], safe, r["content"]))
                    self.ctx.add_finding(Finding(
                        type=f"Exposed file: {fname}",
                        severity=Severity.HIGH,
                        location=r["url"],
                        description=f"File {fname} returned HTTP 200",
                    ))
        except Exception as exc:  # noqa: BLE001
            log.warning("directory fuzz failed: %s", exc)
        progress.update(task, completed=True)

    def _phase_fuzz_api(self, progress: Progress) -> None:
        from asynx6.fuzz.api import run as api_run
        task = progress.add_task("[green]API fuzz", total=None)
        try:
            self.ctx.extend_findings(api_run(self.target, client=self.client))
        except Exception as exc:  # noqa: BLE001
            log.warning("api fuzz failed: %s", exc)
        progress.update(task, completed=True)

    def _phase_exfil_db(self, progress: Progress) -> None:
        from asynx6.exfil.db_mysql import run as db_run
        if not any(p.port == 3306 for p in self.ctx.open_ports):
            return
        task = progress.add_task("[red]DB audit (3306)", total=None)
        try:
            # Find an IP we have — fall back to the target's host
            host = self.ctx.open_ports[0].__class__.__name__  # noqa
            self.ctx.extend_findings(db_run(self.domain, port=3306))
        except Exception as exc:  # noqa: BLE001
            log.warning("db audit failed: %s", exc)
        progress.update(task, completed=True)

    def _phase_templates(self, progress: Progress) -> None:
        from asynx6.fuzz.templates import load_templates, run_templates
        from pathlib import Path as _P
        tmpl_dir = _P(__file__).parent.parent.parent / "templates"
        templates = load_templates(tmpl_dir)
        if not templates:
            return
        task = progress.add_task("[magenta]Custom templates", total=None)
        try:
            self.ctx.extend_findings(run_templates(
                templates, self.target, client=self.client
            ))
        except Exception as exc:  # noqa: BLE001
            log.warning("templates phase failed: %s", exc)
        progress.update(task, completed=True)

    def _phase_secrets_archive(self, progress: Progress) -> None:
        from asynx6.exfil.secrets_archive import run as secrets_run
        vault = self.base_dir / "LOOT_VAULT.md"
        if not vault.exists():
            return
        task = progress.add_task("[yellow]Secrets archive", total=None)
        try:
            secrets_run(vault, self.base_dir)
        except Exception as exc:  # noqa: BLE001
            log.warning("secrets archive failed: %s", exc)
        progress.update(task, completed=True)

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
        except Exception as exc:  # noqa: BLE001
            log.warning("report generation failed: %s", exc)

    def _print_summary(self) -> None:
        from rich.table import Table
        t = Table(title=f"Asynx6 V2 Summary — {self.target}", show_header=True)
        t.add_column("Metric", style="cyan")
        t.add_column("Count", style="white")
        t.add_row("Findings", str(len(self.ctx.findings)))
        t.add_row("Subdomains", str(len(self.ctx.subdomains)))
        t.add_row("Origin IPs", str(len(self.ctx.origin_ips)))
        t.add_row("Open Ports", str(len(self.ctx.open_ports)))
        t.add_row("Loot Items", str(len(self.ctx.loot)))
        console.print(t)


def _timestamp() -> str:
    from datetime import datetime
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _make_loot(url: str, filename: str, content: bytes) -> Any:
    import hashlib
    from asynx6.core.models import LootItem
    md5 = hashlib.md5(content).hexdigest()
    return LootItem(url=url, filename=filename, md5=md5,
                    content_type="application/octet-stream",
                    is_binary=False)
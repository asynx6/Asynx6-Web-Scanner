"""Markdown PoC report (V1-compatible, but driven by typed models)."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from asynx6.core.models import Finding, ScanContext, Severity


_ICON = {Severity.CRITICAL: "🔴", Severity.HIGH: "🟠", Severity.MEDIUM: "🟡",
         Severity.LOW: "🔵", Severity.INFO: "⚪"}


def generate(target: str, ctx: ScanContext, output_dir: Path | str) -> str:
    """Render the Markdown report. Returns the path to the written file."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    report = out / "BUG_BOUNTY_POC.md"

    lines: list[str] = []
    lines.append(f"# 🎯 Asynx6 PoC REPORT — {target}")
    lines.append(f"**Date:** `{time.strftime('%Y-%m-%d %H:%M:%S')}` "
                 f"| **Engine:** `Asynx6 V2.0`\n")

    if ctx.subdomains or ctx.origin_ips:
        lines.append("## 🔍 1. Reconnaissance Summary\n")
        if ctx.subdomains:
            lines.append("### Subdomains Discovered")
            lines.append("| Subdomain | IP |")
            lines.append("|---|---|")
            for s in ctx.subdomains:
                lines.append(f"| {s.subdomain} | {s.ip} |")
            lines.append("")
        if ctx.origin_ips:
            lines.append("### CDN Bypass: Potential Origin IPs")
            lines.append("| Subdomain | IP | Confidence |")
            lines.append("|---|---|---|")
            for o in ctx.origin_ips:
                lines.append(f"| {o.subdomain} | {o.ip} | {o.confidence} |")
            lines.append("")

    lines.append("## 📝 2. Executive Summary")
    crit = sum(1 for f in ctx.findings if f.severity == Severity.CRITICAL)
    high = sum(1 for f in ctx.findings if f.severity == Severity.HIGH)
    lines.append(f"During the security audit of `{target}`, **{len(ctx.findings)}** "
                 f"findings were produced (**{crit}** critical, **{high}** high).\n")

    lines.append("## 🚀 3. Technical Findings")
    if not ctx.findings:
        lines.append("*No findings during this audit cycle.*\n")
    else:
        for i, f in enumerate(ctx.findings, 1):
            lines.append(f"### {_ICON[f.severity]} {i}. {f.type}")
            lines.append(f"- **Severity:** `{f.severity.value}`")
            lines.append(f"- **Confidence:** `{f.confidence}%`")
            lines.append(f"- **Location:** `{f.location}`")
            if f.payload:
                lines.append(f"- **Payload:** `{f.payload}`")
            lines.append("\n#### Impact\n")
            lines.append(f"{f.description}\n")
            if f.remediation:
                lines.append(f"**Remediation:** {f.remediation}\n")
            lines.append("---\n")

    lines.append("## 🛡️ 4. Remediation Strategy")
    lines.append("- **Input Validation:** allow-list validation for all user input.")
    lines.append("- **Database Security:** prepared statements; block port 3306.")
    lines.append("- **Access Control:** server-side session validation; IP allowlist.")
    lines.append("- **Infrastructure:** WAF rules for SQLi/XSS/LFI/SSRF patterns.")
    lines.append("")

    report.write_text("\n".join(lines), encoding="utf-8")
    return str(report)

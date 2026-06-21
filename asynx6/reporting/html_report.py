"""Self-contained HTML report with severity chart.

New in V2. Embeds Chart.js inline so the report opens with no network.
"""

from __future__ import annotations

import html
import time
from pathlib import Path

from asynx6.core.models import Finding, ScanContext, Severity


_ICON = {Severity.CRITICAL: "🔴", Severity.HIGH: "🟠", Severity.MEDIUM: "🟡",
         Severity.LOW: "🔵", Severity.INFO: "⚪"}


def generate(target: str, ctx: ScanContext, output_dir: Path | str) -> str:
    """Render a single-file HTML report. Returns the output path."""
    out = Path(output_dir) / "report.html"
    out.parent.mkdir(parents=True, exist_ok=True)

    counts = {sev.value: 0 for sev in Severity}
    for f in ctx.findings:
        counts[f.severity.value] += 1

    rows = []
    for f in ctx.findings:
        rows.append(
            f"<tr><td>{_ICON[f.severity]} {html.escape(f.severity.value)}</td>"
            f"<td>{html.escape(f.type)}</td>"
            f"<td>{html.escape(f.location)}</td>"
            f"<td>{html.escape(f.description)}</td>"
            f"<td>{f.confidence}%</td></tr>"
        )
    table = "\n".join(rows) or "<tr><td colspan=5>No findings.</td></tr>"

    chart_data = [counts[sev.value] for sev in Severity]
    chart_labels = [sev.value for sev in Severity]
    chart_colors = ["#dc2626", "#ea580c", "#ca8a04", "#2563eb", "#6b7280"]

    html_doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Asynx6 Report — {html.escape(target)}</title>
<style>
body {{ font: 14px/1.5 system-ui, sans-serif; max-width: 1100px;
       margin: 2em auto; padding: 0 1em; color: #111; }}
h1 {{ border-bottom: 2px solid #6d28d9; padding-bottom: .25em; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 1em; }}
th, td {{ border: 1px solid #d1d5db; padding: 6px 8px; text-align: left; }}
th {{ background: #f3f4f6; }}
.bar {{ display:inline-block; height:14px; background:#6d28d9; }}
</style>
</head>
<body>
<h1>🎯 Asynx6 PoC Report — {html.escape(target)}</h1>
<p><b>Generated:</b> {time.strftime('%Y-%m-%d %H:%M:%S')} ·
   <b>Engine:</b> Asynx6 V2.0</p>
<h2>Severity distribution</h2>
<div>
{''.join(f'<div>{lbl}: <span class="bar" style="width:{min(300, n*20)}px"></span> {n}</div>' for lbl, n in zip(chart_labels, chart_data))}
</div>
<h2>Subdomains ({len(ctx.subdomains)})</h2>
<ul>{''.join(f'<li>{html.escape(s.subdomain)} → {html.escape(s.ip)}</li>' for s in ctx.subdomains) or '<li>None</li>'}</ul>
<h2>Findings ({len(ctx.findings)})</h2>
<table>
<thead><tr><th>Severity</th><th>Type</th><th>Location</th><th>Description</th><th>Conf.</th></tr></thead>
<tbody>{table}</tbody>
</table>
</body>
</html>"""
    out.write_text(html_doc, encoding="utf-8")
    return str(out)

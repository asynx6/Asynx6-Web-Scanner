"""JSON and SARIF export. New in V2.

SARIF (Static Analysis Results Interchange Format) is a OASIS standard consumed
by GitHub Code Scanning, VS Code, etc.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from asynx6.core.models import Finding, ScanContext, Severity


def _to_dict(f: Finding) -> dict[str, Any]:
    return f.to_dict()


def generate_json(ctx: ScanContext, output_dir: Path | str) -> str:
    """Write a flat JSON dump of all findings + recon. Returns output path."""
    out = Path(output_dir) / "findings.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "target": ctx.base_url,
        "subdomains": [vars(s) for s in ctx.subdomains],
        "origin_ips": [{"subdomain": o.subdomain, "ip": o.ip,
                         "confidence": o.confidence} for o in ctx.origin_ips],
        "findings": [_to_dict(f) for f in ctx.findings],
        "stats": {
            "total_findings": len(ctx.findings),
            "by_severity": {
                sev.value: sum(1 for f in ctx.findings if f.severity == sev)
                for sev in Severity
            },
        },
    }
    out.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return str(out)


_SARIF_LEVEL = {
    Severity.CRITICAL: "error", Severity.HIGH: "error",
    Severity.MEDIUM: "warning", Severity.LOW: "note", Severity.INFO: "none",
}


def generate_sarif(ctx: ScanContext, output_dir: Path | str,
                   tool_name: str = "Asynx6") -> str:
    """Write SARIF 2.1.0 JSON for IDE/CI integration."""
    out = Path(output_dir) / "findings.sarif.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, Any]] = []
    rules: dict[str, dict[str, Any]] = {}
    for f in ctx.findings:
        rule_id = re.sub(r"\W+", "-", f.type).lower().strip("-")
        rules[rule_id] = {
            "id": rule_id,
            "name": f.type,
            "shortDescription": {"text": f.type},
            "defaultConfiguration": {"level": _SARIF_LEVEL[f.severity]},
        }
        results.append({
            "ruleId": rule_id,
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": f.description},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.location}
                }
            }],
        })
    sarif = {
        "$schema": ("https://raw.githubusercontent.com/oasis-tcs/"
                    "sarif-spec/master/Schemata/sarif-schema-2.1.0.json"),
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "version": "2.0.0",
                    "informationUri": "https://github.com/asynx6/Asynx6-Web-Scanner",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }
    out.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    return str(out)


import re  # noqa: E402  (kept here to keep the regex local to sarif logic)

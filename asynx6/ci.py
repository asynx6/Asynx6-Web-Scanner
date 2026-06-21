"""CI/CD mode for Asynx6.

New in V3. Designed for integration into CI pipelines (GitHub Actions,
GitLab CI, Jenkins, etc.):

- Non-interactive (no TUI, no prompts)
- SARIF or JSON output to stdout (machine-readable)
- Exit codes:
    0 = clean (no findings, or only INFO/LOW)
    1 = findings present (MEDIUM/HIGH/CRITICAL)
    2 = scanner error
- Baseline comparison: fail only on NEW findings vs a saved baseline file
- GitHub Code Scanning integration: SARIF can be uploaded natively
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any

from asynx6.core.config import ScannerConfig, load_config
from asynx6.core.logging_setup import setup_logging
from asynx6.core.models import Finding, Severity
from asynx6.engine.orchestrator import Orchestrator
from asynx6.profiles import apply_profile, ci_pipeline
from asynx6.reporting.json_export import generate_sarif

log = logging.getLogger(__name__)

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="asynx6-ci",
        description="Asynx6 Web Scanner V3 — CI/CD mode",
    )
    p.add_argument("target", help="Target URL")
    p.add_argument("--baseline", type=Path, default=None,
                   help="Path to baseline findings JSON (from a previous scan)")
    p.add_argument("--output-baseline", type=Path, default=None,
                   help="Write current findings as baseline for next run")
    p.add_argument("--format", choices=["json", "sarif"], default="sarif",
                   help="Output format (default: sarif)")
    p.add_argument("--severity-threshold", default="MEDIUM",
                   choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
                   help="Minimum severity to fail the build (default: MEDIUM)")
    p.add_argument("--fail-on-new-only", action="store_true",
                   help="Only fail on findings not present in baseline")
    p.add_argument("--output", type=Path, default=None,
                   help="Write report to this file (default: stdout)")
    p.add_argument("--config", type=Path, default=None,
                   help="Path to YAML config file")
    return p


def _load_baseline(path: Path) -> list[dict[str, Any]]:
    """Load a baseline JSON file (list of finding dicts)."""
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and "items" in data:
            return data["items"]
        if isinstance(data, list):
            return data
    except (json.JSONDecodeError, OSError) as exc:
        log.warning("Baseline load failed: %s", exc)
    return []


def _finding_fingerprint(f: Finding) -> tuple[str, str]:
    return (f.type, f.location)


def _compare_to_baseline(
    findings: list[Finding], baseline: list[dict[str, Any]]
) -> tuple[list[Finding], list[Finding]]:
    """Return (new, matched) findings vs baseline."""
    base_keys = {(b.get("type", ""), b.get("location", "")) for b in baseline}
    new = [f for f in findings if _finding_fingerprint(f) not in base_keys]
    matched = [f for f in findings if _finding_fingerprint(f) in base_keys]
    return new, matched


def _severity_rank(sev: str) -> int:
    return {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(
        sev.upper(), 0
    )


def run_ci(args: argparse.Namespace) -> int:
    """Run a CI-mode scan. Returns process exit code."""
    cfg = load_config(args.config) if args.config else ci_pipeline().config
    cfg = cfg.model_copy(update={"show_banner": False})
    setup_logging(cfg.output_dir, level=logging.WARNING)

    threshold = _severity_rank(args.severity_threshold)

    try:
        ctx = Orchestrator(args.target, cfg).run()
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"asynx6-ci: scan failed: {exc}\n")
        return EXIT_ERROR

    findings = list(ctx.findings)

    baseline = _load_baseline(args.baseline) if args.baseline else []
    new_findings, matched = _compare_to_baseline(findings, baseline)

    if args.fail_on_new_only:
        relevant = new_findings
    else:
        relevant = findings

    failing = [f for f in relevant if _severity_rank(f.severity.value) >= threshold]

    if args.format == "sarif":
        report_text = generate_sarif(ctx, cfg.output_dir)
    else:
        payload = {
            "target": ctx.target,
            "findings": [f.to_dict() for f in findings],
            "new_findings": [f.to_dict() for f in new_findings],
            "stats": {
                "total": len(findings),
                "new": len(new_findings),
                "matched_baseline": len(matched),
                "failing_threshold": len(failing),
            },
        }
        report_text = json.dumps(payload, indent=2, default=str)

    if args.output:
        Path(args.output).write_text(report_text, encoding="utf-8")
    else:
        print(report_text)

    if args.output_baseline:
        baseline_payload = {"items": [f.to_dict() for f in findings]}
        args.output_baseline.write_text(
            json.dumps(baseline_payload, indent=2, default=str),
            encoding="utf-8",
        )

    if failing:
        sys.stderr.write(
            f"asynx6-ci: {len(failing)} finding(s) at or above "
            f"{args.severity_threshold}\n"
        )
        return EXIT_FINDINGS
    return EXIT_CLEAN


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    return run_ci(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
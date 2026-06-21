"""Command-line interface for Asynx6 V2.

Thin wrapper over the orchestrator: parses flags, loads config, dispatches to
either single-target scan, batch scan, or the TUI dashboard.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Sequence

from rich.console import Console
from rich.panel import Panel

from asynx6 import __version__
from asynx6.core.config import ScannerConfig, load_config
from asynx6.core.logging_setup import setup_logging
from asynx6.engine.orchestrator import Orchestrator

console = Console()


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="asynx6",
        description="Asynx6 Web Scanner V2 — Apex Predator Edition",
    )
    p.add_argument("target", nargs="?", help="Target URL or path to .txt list")
    p.add_argument("-a", "--aggressive", action="store_true",
                   help="Enable aggressive fuzzing & discovery")
    p.add_argument("--tui", action="store_true",
                   help="Launch interactive Textual dashboard")
    p.add_argument("--threads", type=int, default=25,
                   help="Worker threads (default 25)")
    p.add_argument("--timeout", type=int, default=10,
                   help="HTTP timeout in seconds (default 10)")
    p.add_argument("--output-dir", type=Path, default=Path("results"),
                   help="Results directory (default ./results)")
    p.add_argument("--format", dest="report_format", default="markdown",
                   choices=["markdown", "json", "sarif", "html"],
                   help="Report format (default markdown)")
    p.add_argument("--config", type=Path, default=None,
                   help="Path to YAML config file")
    p.add_argument("--no-banner", action="store_true",
                   help="Suppress ASCII banner")
    p.add_argument("--version", action="version",
                   version=f"Asynx6 V{__version__}")
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    cfg = load_config(args.config) if args.config else ScannerConfig()

    # CLI overrides
    overrides: dict[str, object] = {
        "aggressive": args.aggressive or cfg.aggressive,
        "threads": args.threads,
        "timeout": args.timeout,
        "output_dir": args.output_dir,
        "report_format": args.report_format,
        "show_banner": not args.no_banner,
    }
    cfg = cfg.model_copy(update=overrides)

    if cfg.show_banner:
        console.print(Panel(
            f"[bold white]ASYNX6 ENGINE V{__version__}[/]\n"
            "[dim]Apex Predator Security Audit Suite[/]",
            border_style="purple",
        ))
        console.print(
            "[bold red]LEGAL DISCLAIMER:[/] for educational and authorized "
            "security auditing only. Attacking targets without prior written "
            "consent is strictly prohibited.\n"
        )

    # TUI mode
    if args.tui:
        try:
            from asynx6.tui.app import Asynx6App, require_textual
            require_textual()
        except ImportError as exc:
            console.print(f"[danger]TUI unavailable: {exc}[/]")
            return 1
        Asynx6App(target=args.target or "", aggressive=args.aggressive).run()
        return 0

    # Resolve target
    if not args.target:
        target = console.input("[bold cyan]>> Enter Target URL or .txt list: [/]").strip()
    else:
        target = args.target
    if not target:
        console.print("[danger]No target specified. Exiting.[/]")
        return 1

    if not args.aggressive:
        choice = console.input("[bold yellow]>> Enable Aggressive Mode (y/n)? [/]").lower()
        if choice == "y":
            cfg = cfg.model_copy(update={"aggressive": True})

    setup_logging(cfg.output_dir)
    log = logging.getLogger("asynx6")

    if Path(target).is_file():
        from asynx6.engine.batch import run_batch
        targets = [t.strip() for t in Path(target).read_text().splitlines() if t.strip()]
        console.print(f"[info]Batch mode: {len(targets)} targets[/]")
        contexts = run_batch(targets, cfg)
        console.print(f"[success]Completed {len(contexts)} targets[/]")
        return 0

    try:
        ctx = Orchestrator(target, cfg).run()
    except Exception as exc:  # noqa: BLE001
        log.exception("Scan failed")
        console.print(f"[danger]Scan failed: {exc}[/]")
        return 2

    console.print(f"[success]Findings: {len(ctx.findings)}[/]")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
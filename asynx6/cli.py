"""Command-line interface for Asynx6 V3.

V3 additions:
- Locale flag (--locale en|id)
- Profile flag (--profile <name>)
- --serve (launch web dashboard after scan)
- --persist (save scan history to SQLite)
- --ml-filter (apply ML false-positive filter)
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
        description="Asynx6 Web Scanner V3 — web security reconnaissance suite",
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
                   choices=["markdown", "json", "sarif", "html", "all"],
                   help="Report format (default markdown)")
    p.add_argument("--config", type=Path, default=None,
                   help="Path to YAML config file")
    p.add_argument("--no-banner", action="store_true",
                   help="Suppress ASCII banner")
    p.add_argument("--version", action="version",
                   version=f"Asynx6 V{__version__}")
    # V3 additions
    p.add_argument("--locale", default="en", choices=["en", "id"],
                   help="Output language (default: en)")
    p.add_argument("--profile", default=None,
                   choices=["quick-triage", "owasp-top10", "deep", "stealth", "ci"],
                   help="Use a preset scan profile")
    p.add_argument("--serve", action="store_true",
                   help="Launch web dashboard after scan completes")
    p.add_argument("--persist", action="store_true",
                   help="Persist scan history to SQLite (~/.asynx6/history.db)")
    p.add_argument("--ml-filter", action="store_true",
                   help="Apply ML false-positive filter (requires scikit-learn)")
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    # Apply profile if specified
    if args.profile:
        from asynx6.profiles import apply_profile
        base = load_config(args.config) if args.config else ScannerConfig()
        cfg = apply_profile(base, args.profile)
    else:
        cfg = load_config(args.config) if args.config else ScannerConfig()

    # CLI overrides
    overrides: dict[str, object] = {
        "aggressive": args.aggressive or cfg.aggressive,
        "threads": args.threads,
        "timeout": args.timeout,
        "output_dir": args.output_dir,
        "report_format": args.report_format,
        "show_banner": not args.no_banner,
        "locale": args.locale,
        "persist": args.persist or cfg.persist,
        "ml_filter": args.ml_filter or cfg.ml_filter,
    }
    cfg = cfg.model_copy(update=overrides)

    # Apply locale
    try:
        from asynx6.i18n import set_locale
        set_locale(cfg.locale)
    except ImportError:
        pass

    if cfg.show_banner:
        console.print(Panel(
            f"[bold white]ASYNX6 ENGINE V{__version__}[/]\n"
            f"[dim]Profile: {args.profile or 'default'} | "
            f"Locale: {cfg.locale} | "
            f"Mode: {'Aggressive' if cfg.aggressive else 'Normal'}[/]",
            border_style="purple",
        ))
        console.print(
            "[bold red]LEGAL DISCLAIMER:[/] for educational and authorized "
            "security auditing only.\n"
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

    if not args.aggressive and not args.profile:
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
        if args.serve:
            from asynx6.web import run_server
            console.print("[cyan]Launching web dashboard on http://127.0.0.1:8080[/]")
            run_server()
        return 0

    try:
        ctx = Orchestrator(target, cfg).run()
    except Exception as exc:  # noqa: BLE001
        log.exception("Scan failed")
        console.print(f"[danger]Scan failed: {exc}[/]")
        return 2

    console.print(f"[success]Findings: {len(ctx.findings)}[/]")

    if args.serve:
        from asynx6.web import run_server
        console.print("[cyan]Launching web dashboard on http://127.0.0.1:8080[/]")
        run_server()

    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
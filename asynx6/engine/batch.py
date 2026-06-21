"""Batch (multi-target) scan runner using a multiprocessing pool."""

from __future__ import annotations

from multiprocessing import Pool
from typing import Any

from asynx6.core.config import ScannerConfig
from asynx6.core.models import ScanContext
from asynx6.engine.orchestrator import Orchestrator


def _worker(args: tuple[str, dict[str, Any]]) -> ScanContext:
    target, cfg_dict = args
    cfg = ScannerConfig(**cfg_dict)
    return Orchestrator(target, cfg).run()


def run_batch(targets: list[str], config: ScannerConfig,
              *, processes: int = 5) -> list[ScanContext]:
    """Run one Orchestrator per target in parallel. Returns contexts in input order."""
    cfg_dict = config.model_dump()
    with Pool(processes=min(processes, len(targets) or 1)) as pool:
        return pool.map(_worker, [(t, cfg_dict) for t in targets])
"""Tests for engine.batch."""

from __future__ import annotations

from unittest.mock import patch

from asynx6.core.config import ScannerConfig
from asynx6.core.models import ScanContext
from asynx6.engine.batch import _worker


def test_worker_creates_context():
    cfg = ScannerConfig(threads=1, jitter_min=0, jitter_max=0, timeout=1)

    fake_ctx = ScanContext(target="https://x.test/", base_url="https://x.test/",
                           domain="x.test")

    class FakeOrch:
        def __init__(self, target, config):
            pass

        def run(self):
            return fake_ctx

    with patch("asynx6.engine.batch.Orchestrator", FakeOrch):
        ctx = _worker(("https://x.test/", cfg.model_dump()))
    assert ctx.target == "https://x.test/"
"""Integration tests. Skipped by default; opt in with `pytest -m integration`."""

from __future__ import annotations

import socket

import pytest

from asynx6.core.config import ScannerConfig
from asynx6.engine.orchestrator import Orchestrator


def _localhost_has_server() -> bool:
    """Return True if something is listening on 127.0.0.1:80."""
    try:
        with socket.create_connection(("127.0.0.1", 80), timeout=0.5):
            return True
    except OSError:
        return False


@pytest.mark.integration
def test_smoke_against_localhost(tmp_path):
    if not _localhost_has_server():
        pytest.skip("no HTTP server on localhost:80")
    cfg = ScannerConfig(threads=1, timeout=2, jitter_min=0, jitter_max=0,
                        output_dir=tmp_path, show_banner=False)
    ctx = Orchestrator("http://127.0.0.1/", cfg).run()
    assert ctx is not None
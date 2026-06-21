"""Tests for engine.orchestrator."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from asynx6.core.config import ScannerConfig
from asynx6.engine.orchestrator import Orchestrator


def test_orchestrator_returns_context(tmp_path):
    cfg = ScannerConfig(threads=1, timeout=1, jitter_min=0, jitter_max=0,
                        output_dir=tmp_path, show_banner=False,
                        report_format="markdown")
    orch = Orchestrator("https://example.com", cfg)

    # Patch every phase to a no-op that returns None
    with patch.object(orch, "_phase_chameleon"), \
         patch.object(orch, "_phase_subdomain"), \
         patch.object(orch, "_phase_network"), \
         patch.object(orch, "_phase_dns_enum"), \
         patch.object(orch, "_phase_wayback"), \
         patch.object(orch, "_phase_headless"), \
         patch.object(orch, "_phase_crawler"), \
         patch.object(orch, "_phase_vuln"), \
         patch.object(orch, "_phase_fuzz_directory"), \
         patch.object(orch, "_phase_fuzz_api"), \
         patch.object(orch, "_phase_exfil_db"), \
         patch.object(orch, "_phase_templates"), \
         patch.object(orch, "_phase_secrets_archive"), \
         patch.object(orch, "_write_reports"), \
         patch.object(orch, "_print_summary"):
        ctx = orch.run()
    assert ctx.target == "https://example.com"
    assert ctx.domain == "example.com"
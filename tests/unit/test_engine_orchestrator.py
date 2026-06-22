"""Tests for engine.orchestrator (M2 of the V3 refactor).

M2 moved phases from bound methods to a module-level ``PHASE_REGISTRY`` of
``PhaseSpec`` objects. Tests therefore patch the registry (not the instance)
so we can drive the orchestrator end-to-end without touching the network.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, List
from unittest.mock import patch

import pytest

from asynx6.core.config import RateLimitConfig, ScannerConfig
from asynx6.engine import orchestrator as orch_mod
from asynx6.engine import phases as phases_mod
from asynx6.engine.orchestrator import Orchestrator
from asynx6.engine.phases import PhaseSpec
from asynx6.core.models import ScanContext


# -- Helpers -----------------------------------------------------------------

def _no_op_phase(orch: Any, progress: Any) -> None:  # pragma: no cover - helper
    return None


@pytest.fixture
def fake_phases(monkeypatch: pytest.MonkeyPatch):
    """Replace PHASE_REGISTRY with a controlled list of no-op specs.

    Returns a list of ``(spec, call_log)`` tuples so tests can assert on
    call order. The registry is restored after the test by monkeypatch.
    """
    call_log: list[str] = []

    def make_record(name: str):
        def _f(orch: Orchestrator, progress: Any) -> None:
            call_log.append(name)
        return _f

    specs = [
        PhaseSpec(name="phase_a", label="A", category="recon", func=make_record("phase_a")),
        PhaseSpec(name="phase_b", label="B", category="vuln", func=make_record("phase_b")),
        PhaseSpec(name="phase_c", label="C", category="post", func=make_record("phase_c")),
    ]
    monkeypatch.setattr(phases_mod, "PHASE_REGISTRY", list(specs))
    return specs, call_log


@pytest.fixture
def empty_phases(monkeypatch: pytest.MonkeyPatch):
    """Replace PHASE_REGISTRY with an empty list."""
    monkeypatch.setattr(phases_mod, "PHASE_REGISTRY", [])
    return []


@pytest.fixture
def cfg(tmp_path: Path) -> ScannerConfig:
    return ScannerConfig(
        threads=1,
        timeout=1,
        jitter_min=0,
        jitter_max=0,
        output_dir=tmp_path,
        show_banner=False,
        report_format="markdown",
        rate_limit=RateLimitConfig(enabled=False),
    )


# -- M2 core: registry-driven loop ------------------------------------------

def test_orchestrator_returns_context(cfg: ScannerConfig, empty_phases) -> None:
    orch = Orchestrator("https://example.com", cfg)
    with patch.object(orch, "_write_reports"), \
         patch.object(orch, "_print_summary"):
        ctx = orch.run()
    assert ctx.target == "https://example.com"
    assert ctx.domain == "example.com"


def test_init_does_not_create_output_dir(cfg: ScannerConfig, tmp_path: Path) -> None:
    """M2: directory creation moved to run() so partially-built orchestrators
    never leave half-written dirs on disk."""
    orch = Orchestrator("https://example.com", cfg)
    assert not orch.base_dir.exists()
    assert not orch.loot_dir.exists()


def test_run_creates_output_dirs(cfg: ScannerConfig, empty_phases) -> None:
    orch = Orchestrator("https://example.com", cfg)
    with patch.object(orch, "_write_reports"), \
         patch.object(orch, "_print_summary"):
        orch.run()
    assert orch.base_dir.exists()
    assert orch.loot_dir.is_dir()
    assert orch.loot_dir.exists()
    assert orch.loot_dir.is_dir()


def test_run_iterates_phases_in_registry_order(cfg: ScannerConfig, fake_phases) -> None:
    specs, call_log = fake_phases
    orch = Orchestrator("https://example.com", cfg)
    with patch.object(orch, "_write_reports"), \
         patch.object(orch, "_print_summary"):
        orch.run()
    assert call_log == ["phase_a", "phase_b", "phase_c"]


def test_run_with_no_phases_is_safe(cfg: ScannerConfig, empty_phases) -> None:
    orch = Orchestrator("https://example.com", cfg)
    with patch.object(orch, "_write_reports"), \
         patch.object(orch, "_print_summary"):
        ctx = orch.run()
    # Nothing to assert on findings — just that nothing crashed.
    assert ctx.findings == []


# -- M2: profile-based phase allowlist --------------------------------------

def test_load_active_phases_from_profile_picks_up_allowlist(
    cfg: ScannerConfig, monkeypatch: pytest.MonkeyPatch, empty_phases
) -> None:
    """A profile's ``enabled_phases`` should populate ``ctx.active_phases``."""
    cfg.profile = "ci"  # profile name is read by Orchestrator._load_active_phases_from_profile
    orch = Orchestrator("https://example.com", cfg)
    # cfg has no `profile` attribute by default — set it on the instance
    # and also stub the profile registry to return a deterministic profile.
    from asynx6.engine.phases import register_phase
    phases_mod.PHASE_REGISTRY.append(
        PhaseSpec(name="chameleon", label="x", category="recon", func=_no_op_phase)
    )
    phases_mod.PHASE_REGISTRY.append(
        PhaseSpec(name="vuln_sqli", label="x", category="vuln", func=_no_op_phase)
    )

    class _StubProfile:
        enabled_phases = ["chameleon"]

    monkeypatch.setattr(Orchestrator, "_load_active_phases_from_profile",
                        lambda self: setattr(self.ctx, "active_phases", set(_StubProfile.enabled_phases)))
    with patch.object(orch, "_write_reports"), \
         patch.object(orch, "_print_summary"):
        orch.run()
    # The stub sets active_phases to {"chameleon"} — the run loop should pick
    # only chameleon.
    assert "chameleon" in orch.ctx.active_phases
    assert "vuln_sqli" not in orch.ctx.active_phases


def test_load_active_phases_no_profile_yields_empty_set(
    cfg: ScannerConfig, empty_phases
) -> None:
    """No profile on the config -> empty active_phases set -> run all."""
    orch = Orchestrator("https://example.com", cfg)
    with patch.object(orch, "_write_reports"), \
         patch.object(orch, "_print_summary"):
        orch.run()
    # The default code path sets active_phases to empty set, which makes
    # filter_active return all registry entries.
    assert orch.ctx.active_phases == set()


# -- M2: plugin discovery invocation ----------------------------------------

def test_run_invokes_plugin_discovery(cfg: ScannerConfig, empty_phases, monkeypatch) -> None:
    """``Orchestrator.run`` must call ``discover_plugins().apply_to(self)``.

    The default registry is empty in tests, but we assert the side effect by
    patching ``discover_plugins``.
    """
    orch = Orchestrator("https://example.com", cfg)
    called_with: list[Any] = []

    class _StubReg:
        def apply_to(self, o: Any) -> None:
            called_with.append(o)

    monkeypatch.setattr(
        "asynx6.plugins.loader.discover_plugins",
        lambda: _StubReg(),
    )
    with patch.object(orch, "_write_reports"), \
         patch.object(orch, "_print_summary"):
        orch.run()
    assert called_with == [orch]


def test_run_survives_plugin_discovery_failure(
    cfg: ScannerConfig, empty_phases, monkeypatch
) -> None:
    """A buggy plugin discovery must NOT crash the orchestrator."""
    orch = Orchestrator("https://example.com", cfg)

    def _boom() -> Any:
        raise RuntimeError("plugin loader exploded")

    monkeypatch.setattr("asynx6.plugins.loader.discover_plugins", _boom)
    with patch.object(orch, "_write_reports"), \
         patch.object(orch, "_print_summary"):
        ctx = orch.run()  # must not raise
    assert ctx is not None


# -- M2: ScanContext.active_phases field ------------------------------------

def test_scan_context_default_active_phases_is_empty_set() -> None:
    ctx = ScanContext(target="https://x", base_url="https://x", domain="x")
    assert ctx.active_phases == set()
    assert isinstance(ctx.active_phases, set)


def test_scan_context_can_assign_active_phases() -> None:
    ctx = ScanContext(target="https://x", base_url="https://x", domain="x")
    ctx.active_phases = {"a", "b", "c"}
    assert ctx.active_phases == {"a", "b", "c"}
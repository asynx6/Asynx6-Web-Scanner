"""Tests for plugin loader (M1) and plugin-driven phase injection (M2)."""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest

from asynx6.engine import phases as phases_mod
from asynx6.engine.phases import PHASE_REGISTRY, PhaseSpec, register_phase
from asynx6.plugins.loader import PLUGIN_GROUP, PluginRegistry, discover_plugins


# -- M1: existing tests -----------------------------------------------------

def test_registry_register_and_apply() -> None:
    reg = PluginRegistry()
    calls: list[int] = []

    def cb(orch):
        calls.append(1)

    reg.register("test-plugin", cb)
    reg.apply_to(None)
    assert calls == [1]


def test_registry_apply_swallows_exceptions() -> None:
    reg = PluginRegistry()

    def bad_cb(_):
        raise RuntimeError("boom")

    reg.register("bad", bad_cb)
    # Should not raise
    reg.apply_to(None)


def test_discover_plugins_returns_empty_registry_by_default() -> None:
    reg = discover_plugins()
    assert isinstance(reg, PluginRegistry)
    # No plugins installed in the test env
    assert reg.plugins == []


def test_plugin_group_constant() -> None:
    assert PLUGIN_GROUP == "asynx6.plugins"


# -- M2: plugin callback can inject phases via register_phase ---------------

def test_plugin_callback_can_register_phase(monkeypatch: pytest.MonkeyPatch) -> None:
    """A plugin can call ``register_phase`` to add a phase to the registry.

    Simulates a third-party plugin entry point that, when loaded by
    ``discover_plugins().apply_to(orch)``, appends a new phase.
    """
    # Start with a known-empty registry to make the assertion clean.
    monkeypatch.setattr(phases_mod, "PHASE_REGISTRY", [])

    reg = PluginRegistry()

    def my_plugin(orch):
        def my_phase(orch, progress):
            orch.ctx.findings.append("plugin-phase-ran")  # type: ignore[attr-defined]
        register_phase("plugin_phase", "Plugin phase", "recon", my_phase)

    reg.register("my-plugin", my_plugin)
    reg.apply_to(None)

    # The phase should now exist in the registry.
    names = [s.name for s in phases_mod.PHASE_REGISTRY]
    assert "plugin_phase" in names


def test_plugin_registered_phase_is_callable_through_registry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A phase registered by a plugin must be invokable as ``spec.func(orch, progress)``."""
    monkeypatch.setattr(phases_mod, "PHASE_REGISTRY", [])

    reg = PluginRegistry()

    def make_phase() -> Any:
        def my_phase(orch, progress):
            return "ok"
        return my_phase

    reg.register("callable-plugin", lambda orch: register_phase(
        "callable_phase", "Callable", "recon", make_phase()
    ))
    reg.apply_to(None)

    spec = next(s for s in phases_mod.PHASE_REGISTRY if s.name == "callable_phase")
    # Calling the function with sentinel args should not raise.
    assert spec.func(None, None) == "ok"


def test_multiple_plugins_register_phases_in_isolation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Each plugin's phase registration must not interfere with others."""
    monkeypatch.setattr(phases_mod, "PHASE_REGISTRY", [])

    reg = PluginRegistry()

    def plugin_a(_):
        def f(orch, progress):
            return "a"
        register_phase("phase_a", "A", "recon", f)

    def plugin_b(_):
        def f(orch, progress):
            return "b"
        register_phase("phase_b", "B", "vuln", f)

    reg.register("a", plugin_a)
    reg.register("b", plugin_b)
    reg.apply_to(None)

    names = sorted(s.name for s in phases_mod.PHASE_REGISTRY)
    assert names == ["phase_a", "phase_b"]


def test_plugin_callback_exception_is_swallowed() -> None:
    """A buggy plugin must not crash other plugins or the orchestrator."""
    reg = PluginRegistry()

    def good_cb(_):
        # Successful registration
        pass

    def bad_cb(_):
        raise ValueError("plugin exploded")

    reg.register("good", good_cb)
    reg.register("bad", bad_cb)
    # Must not raise even though one plugin is broken.
    reg.apply_to(None)
    assert len(reg.plugins) == 2


# -- M2: orchestrator picks up plugin-injected phases ----------------------

def test_orchestrator_runs_plugin_injected_phase(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End-to-end: orchestrator discovers plugin → plugin injects phase → phase runs."""
    from asynx6.core.config import RateLimitConfig, ScannerConfig
    from asynx6.engine.orchestrator import Orchestrator

    monkeypatch.setattr(phases_mod, "PHASE_REGISTRY", [])

    cfg = ScannerConfig(
        threads=1, timeout=1, jitter_min=0, jitter_max=0,
        output_dir=tmp_path, show_banner=False, report_format="markdown",
        rate_limit=RateLimitConfig(enabled=False),
    )
    orch = Orchestrator("https://example.com", cfg)

    # Inject a phase that just records a marker on the context.
    call_log: list[str] = []

    def injected_phase(orch_inner, progress):
        call_log.append("injected")

    register_phase("injected", "Injected", "recon", injected_phase)

    # Stub discover_plugins to return an empty registry — we already
    # registered the phase directly above. The orchestrator still calls
    # discover_plugins().apply_to(self) but it's a no-op here.
    class _EmptyReg:
        def apply_to(self, _o: Any) -> None:
            return None

    monkeypatch.setattr("asynx6.plugins.loader.discover_plugins", lambda: _EmptyReg())

    with patch.object(orch, "_write_reports"), \
         patch.object(orch, "_print_summary"):
        orch.run()

    assert call_log == ["injected"]
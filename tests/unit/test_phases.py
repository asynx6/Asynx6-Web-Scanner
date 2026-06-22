"""Tests for asynx6.engine.phases — the phase registry and helpers.

Covers M2 of the V3 refactor (3-cluster): the registry that powers
``Orchestrator.run`` and lets plugins inject/override phases.
"""

from __future__ import annotations

from typing import Any, List

import pytest

from asynx6.engine import phases
from asynx6.engine.phases import (
    PHASE_REGISTRY,
    PhaseCategory,
    PhaseSpec,
    filter_active,
    get_phase,
    register_phase,
)


# -- Fixtures ----------------------------------------------------------------

@pytest.fixture
def isolated_registry(monkeypatch: pytest.MonkeyPatch) -> List[PhaseSpec]:
    """Replace PHASE_REGISTRY with a fresh empty list for the test.

    The global registry is populated at import time by the orchestrator's
    ``_register_default_phases``. Tests that need to assert on the default
    registry (e.g. integrity) should NOT use this fixture.
    """
    fresh: list[PhaseSpec] = []
    monkeypatch.setattr(phases, "PHASE_REGISTRY", fresh)
    return fresh


def _noop(orch: Any, progress: Any) -> None:  # pragma: no cover - helper
    return None


# -- PhaseSpec ---------------------------------------------------------------

def test_phasespec_is_frozen() -> None:
    spec = PhaseSpec(name="x", label="X", category="recon", func=_noop)
    with pytest.raises((AttributeError, Exception)):
        spec.name = "y"  # type: ignore[misc]


def test_phasespec_default_requires_is_empty_tuple() -> None:
    spec = PhaseSpec(name="x", label="X", category="recon", func=_noop)
    assert spec.requires == ()


def test_phasespec_carries_callable_directly() -> None:
    spec = PhaseSpec(name="x", label="X", category="recon", func=_noop)
    assert spec.func is _noop


# -- register_phase ----------------------------------------------------------

def test_register_phase_appends_to_registry(isolated_registry: List[PhaseSpec]) -> None:
    spec = register_phase("alpha", "Alpha", "recon", _noop)
    assert spec in isolated_registry
    assert spec.name == "alpha"
    assert spec.label == "Alpha"
    assert spec.category == "recon"


def test_register_phase_is_idempotent_on_name(isolated_registry: List[PhaseSpec]) -> None:
    register_phase("dup", "First", "recon", _noop)
    register_phase("dup", "Second", "recon", _noop)
    matching = [s for s in isolated_registry if s.name == "dup"]
    assert len(matching) == 1
    # Last-writer-wins: the latest call replaces the entry in place.
    assert matching[0].label == "Second"


def test_register_phase_preserves_order(isolated_registry: List[PhaseSpec]) -> None:
    register_phase("a", "A", "recon", _noop)
    register_phase("b", "B", "recon", _noop)
    register_phase("c", "C", "recon", _noop)
    assert [s.name for s in isolated_registry] == ["a", "b", "c"]


def test_register_phase_with_requires(isolated_registry: List[PhaseSpec]) -> None:
    spec = register_phase(
        "post", "Post", "post", _noop, requires=("recon_a", "recon_b")
    )
    assert spec.requires == ("recon_a", "recon_b")


def test_register_phase_accepts_all_documented_categories(isolated_registry: List[PhaseSpec]) -> None:
    # Categories are validated at static type-check time (mypy), not at
    # runtime. The dataclass field is just a string. We assert that all
    # documented categories round-trip cleanly.
    for cat in ("recon", "vuln", "fuzz", "exfil", "post"):
        spec = register_phase(f"phase_{cat}", f"Phase {cat}", cat, _noop)
        assert spec.category == cat


# -- get_phase ---------------------------------------------------------------

def test_get_phase_returns_registered(isolated_registry: List[PhaseSpec]) -> None:
    spec = register_phase("alpha", "Alpha", "recon", _noop)
    assert get_phase("alpha") is spec


def test_get_phase_returns_none_when_missing(isolated_registry: List[PhaseSpec]) -> None:
    assert get_phase("does_not_exist") is None


# -- filter_active ------------------------------------------------------------

def test_filter_active_none_returns_all(isolated_registry: List[PhaseSpec]) -> None:
    a = register_phase("a", "A", "recon", _noop)
    b = register_phase("b", "B", "vuln", _noop)
    out = filter_active(None)
    assert a in out and b in out
    assert len(out) == 2


def test_filter_active_empty_set_returns_all(isolated_registry: List[PhaseSpec]) -> None:
    a = register_phase("a", "A", "recon", _noop)
    b = register_phase("b", "B", "vuln", _noop)
    out = filter_active(set())
    assert a in out and b in out


def test_filter_active_allowlist_returns_subset(isolated_registry: List[PhaseSpec]) -> None:
    a = register_phase("a", "A", "recon", _noop)
    register_phase("b", "B", "vuln", _noop)
    c = register_phase("c", "C", "fuzz", _noop)
    out = filter_active({"a", "c"})
    assert a in out
    assert c in out
    assert len(out) == 2
    # Order preserved.
    assert [s.name for s in out] == ["a", "c"]


def test_filter_active_preserves_registry_order(isolated_registry: List[PhaseSpec]) -> None:
    for n in ("first", "second", "third", "fourth"):
        register_phase(n, n.title(), "recon", _noop)
    out = filter_active({"fourth", "second"})
    assert [s.name for s in out] == ["second", "fourth"]


def test_filter_active_with_empty_registry(isolated_registry: List[PhaseSpec]) -> None:
    assert filter_active(None) == []
    assert filter_active(set()) == []
    assert filter_active({"x"}) == []


# -- Default registry integrity ---------------------------------------------

def test_default_registry_is_non_empty() -> None:
    # The orchestrator populates the registry at import time. We assert the
    # baseline so a refactor that drops defaults would surface here.
    assert len(PHASE_REGISTRY) >= 1


def test_default_registry_names_are_unique() -> None:
    names = [s.name for s in PHASE_REGISTRY]
    assert len(names) == len(set(names)), f"duplicate phase names: {names}"


def test_default_registry_categories_are_known() -> None:
    allowed: set[PhaseCategory] = {"recon", "vuln", "fuzz", "exfil", "post"}
    for spec in PHASE_REGISTRY:
        assert spec.category in allowed, f"unknown category: {spec.category}"


def test_default_registry_each_callable_is_invokable() -> None:
    for spec in PHASE_REGISTRY:
        assert callable(spec.func), f"{spec.name} func not callable"

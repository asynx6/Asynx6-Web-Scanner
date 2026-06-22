"""Phase registry for the V3 orchestrator.

A phase is a discrete unit of work the orchestrator runs in order (recon → vuln
→ fuzz → exfil → post). Each phase is a plain callable with the signature::

    def phase(orch: "Orchestrator", progress: Progress) -> None

The function is expected to mutate ``orch.ctx`` and surface findings via
``ctx.add_finding`` / ``ctx.extend_findings``. Errors must be caught and logged
so one bad phase does not break the whole scan.

Why a registry?
---------------
- 17 hardcoded ``_phase_*`` methods in the previous orchestrator made it
  impossible to register phases from plugins (the dead-code problem that
  motivated this refactor).
- A list of ``PhaseSpec`` objects is trivially filterable, reorderable, and
  extensible from the outside (plugins, profiles, ad-hoc CLI flags).

This module is intentionally tiny. Plugin injection lives in
``asynx6.plugins.loader``; per-phase business logic lives in the
recon/vuln/fuzz/exfil submodules and is wired into ``PHASE_REGISTRY`` below.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Callable, Literal

from rich.progress import Progress

if TYPE_CHECKING:
    from asynx6.engine.orchestrator import Orchestrator


PhaseCategory = Literal["recon", "vuln", "fuzz", "exfil", "post"]


@dataclass(frozen=True)
class PhaseSpec:
    """Declarative description of a single scan phase.

    Attributes:
        name: Stable identifier (used by profile ``enabled_phases`` filter and
            by plugin overrides). Must be unique across ``PHASE_REGISTRY``.
        label: Human-readable label shown in progress bars and reports.
        category: Coarse classification used for ordering and reporting.
        func: The callable that performs the work. Receives the orchestrator
            and the rich Progress instance; must not raise on partial failure
            (catch and log internally).
        requires: Names of other phases that must have run first. Reserved for
            future use — not enforced yet, but documents intent.
    """

    name: str
    label: str
    category: PhaseCategory
    func: Callable[["Orchestrator", Progress], None]
    requires: tuple[str, ...] = field(default_factory=tuple)


# Phase ordering matters: recon must precede vuln, vuln before exfil, etc.
# The list is the single source of truth for what the orchestrator runs.
PHASE_REGISTRY: list[PhaseSpec] = []


def register_phase(
    name: str,
    label: str,
    category: PhaseCategory,
    func: Callable[["Orchestrator", Progress], None],
    *,
    requires: tuple[str, ...] = (),
) -> PhaseSpec:
    """Create a PhaseSpec and append it to ``PHASE_REGISTRY``.

    Idempotent on ``name``: re-registering with the same name replaces the
    existing entry (last writer wins). This lets plugins override built-in
    phases without having to mutate the list directly.

    Args:
        name: Stable identifier. Must be unique.
        label: Human-readable description.
        category: Coarse classification.
        func: Callable ``(orch, progress) -> None``.
        requires: Optional tuple of phase names that must run first.

    Returns:
        The newly-registered PhaseSpec.
    """
    spec = PhaseSpec(
        name=name,
        label=label,
        category=category,
        func=func,
        requires=tuple(requires),
    )
    for i, existing in enumerate(PHASE_REGISTRY):
        if existing.name == name:
            PHASE_REGISTRY[i] = spec
            return spec
    PHASE_REGISTRY.append(spec)
    return spec


def get_phase(name: str) -> PhaseSpec | None:
    """Look up a phase by name. Returns ``None`` if not found."""
    for spec in PHASE_REGISTRY:
        if spec.name == name:
            return spec
    return None


def filter_active(
    active_names: set[str] | None,
) -> list[PhaseSpec]:
    """Return registry entries filtered by an allowed-name set.

    If ``active_names`` is ``None`` or empty, all registered phases run.
    The original registry order is preserved.
    """
    if not active_names:
        return list(PHASE_REGISTRY)
    return [spec for spec in PHASE_REGISTRY if spec.name in active_names]

"""Simple DAG scheduler for orchestrator phases.

Allows declaring phase dependencies without forcing a fixed execution order
in the orchestrator. Each phase declares which named outputs it produces; a
phase can only run once all its inputs are produced.
"""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Any, Callable, Iterable


class Phase:
    """A unit of work in the DAG.

    Args:
        name: Unique identifier.
        fn: Callable that returns nothing (mutates shared state).
        needs: Names of phases that must finish first.
        provides: Outputs this phase produces (consumed by others).
    """

    __slots__ = ("name", "fn", "needs", "provides")

    def __init__(self, name: str, fn: Callable[[], Any],
                 needs: Iterable[str] = (),
                 provides: Iterable[str] = ()) -> None:
        self.name = name
        self.fn = fn
        self.needs = tuple(needs)
        self.provides = tuple(provides)


def schedule(phases: list[Phase]) -> Iterable[Phase]:
    """Yield phases in a topologically valid order.

    Raises:
        ValueError: on cyclic dependency or unknown need.
    """
    by_name = {p.name: p for p in phases}
    # Validate needs
    for p in phases:
        for n in p.needs:
            if n not in by_name:
                raise ValueError(f"Phase {p.name!r} needs unknown {n!r}")

    # Detect cycle via Kahn's algorithm
    indeg: dict[str, int] = {p.name: len(p.needs) for p in phases}
    children: dict[str, list[str]] = defaultdict(list)
    for p in phases:
        for n in p.needs:
            children[n].append(p.name)

    queue = deque([n for n, d in indeg.items() if d == 0])
    while queue:
        name = queue.popleft()
        yield by_name[name]
        for child in children[name]:
            indeg[child] -= 1
            if indeg[child] == 0:
                queue.append(child)

    if any(d > 0 for d in indeg.values()):
        raise ValueError("Cyclic dependency detected in phase DAG")
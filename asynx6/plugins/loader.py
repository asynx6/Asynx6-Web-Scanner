"""Plugin loader using importlib.metadata entry points.

New in V3. Plugins are Python packages that register themselves under the
`asynx6.plugins` entry-point group. The orchestrator loads them at startup.

Example plugin (`pyproject.toml`):

    [project.entry-points."asynx6.plugins"]
    shopify_checks = "asynx6_shopify:register"

Then `asynx6_shopify.register(orchestrator)` is called when the scanner starts.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from importlib import metadata as importlib_metadata
from typing import Any, Callable

log = logging.getLogger(__name__)

PLUGIN_GROUP = "asynx6.plugins"


@dataclass
class PluginRegistry:
    """Holds registered plugins and exposes them to the orchestrator."""

    plugins: list[dict[str, Any]] = field(default_factory=list)

    def register(self, name: str, callback: Callable[..., Any]) -> None:
        """Register a plugin callback.

        Args:
            name: Plugin identifier.
            callback: Callable invoked with the Orchestrator at startup.
        """
        self.plugins.append({"name": name, "callback": callback})
        log.debug("Registered plugin: %s", name)

    def apply_to(self, orchestrator: Any) -> None:
        """Invoke all registered callbacks with the orchestrator."""
        for plugin in self.plugins:
            try:
                plugin["callback"](orchestrator)
                log.info("Plugin loaded: %s", plugin["name"])
            except Exception as exc:  # noqa: BLE001
                log.warning("Plugin %s failed: %s", plugin["name"], exc)


def _all_entry_points() -> Any:
    """Return all entry points (Python 3.10+ API)."""
    try:
        return importlib_metadata.entry_points()
    except Exception as exc:  # noqa: BLE001
        log.debug("entry_points() failed: %s", exc)
        return []


def _select(eps: Any, group: str) -> list:
    """Select entry points for a group, handling API differences."""
    try:
        return list(eps.select(group=group))
    except AttributeError:
        # Older API
        try:
            return list(eps.get(group, []))
        except Exception:  # noqa: BLE001
            return []
    except Exception:  # noqa: BLE001
        return []


def discover_plugins() -> PluginRegistry:
    """Discover plugins registered under the `asynx6.plugins` group.

    Returns an empty registry if no plugins are installed or if importlib
    metadata is unavailable.
    """
    registry = PluginRegistry()
    try:
        eps = _all_entry_points()
        for ep in _select(eps, PLUGIN_GROUP):
            try:
                cb = ep.load()
                registry.register(ep.name, cb)
            except Exception as exc:  # noqa: BLE001
                log.warning("Failed to load plugin %s: %s", ep.name, exc)
    except Exception as exc:  # noqa: BLE001
        log.debug("Plugin discovery unavailable: %s", exc)
    return registry
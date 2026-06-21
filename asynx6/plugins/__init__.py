"""Plugin system — discover third-party Asynx6 modules via Python entry points.

New in V3. Plugins are Python packages that register themselves under the
`asynx6.plugins` entry-point group. The orchestrator loads them at startup.

Example plugin (`pyproject.toml`):

    [project.entry-points."asynx6.plugins"]
    shopify_checks = "asynx6_shopify:register"

Then `asynx6_shopify.register(orchestrator)` is called when the scanner starts.
"""

from asynx6.plugins.loader import discover_plugins, PluginRegistry

__all__ = ["discover_plugins", "PluginRegistry"]
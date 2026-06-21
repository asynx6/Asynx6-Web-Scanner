"""Tests for plugin discovery with mocked entry points."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from asynx6.plugins import loader
from asynx6.plugins.loader import discover_plugins


def test_discover_plugins_loads_registered_callbacks():
    """Patch importlib.metadata.entry_points to return our fake EP."""
    fake_ep = MagicMock()
    fake_ep.name = "my-plugin"
    fake_ep.load.return_value = lambda orch: None

    fake_eps = MagicMock()
    fake_eps.select.return_value = [fake_ep]

    with patch("importlib.metadata.entry_points", return_value=fake_eps):
        reg = discover_plugins()
    assert len(reg.plugins) == 1
    assert reg.plugins[0]["name"] == "my-plugin"


def test_discover_plugins_swallows_load_failures():
    fake_ep = MagicMock()
    fake_ep.name = "broken-plugin"
    fake_ep.load.side_effect = RuntimeError("boom")

    fake_eps = MagicMock()
    fake_eps.select.return_value = [fake_ep]

    with patch("importlib.metadata.entry_points", return_value=fake_eps):
        reg = discover_plugins()
    # Plugin failed to load — should be silently dropped, not crash
    assert reg.plugins == []


def test_discover_plugins_handles_missing_metadata():
    """If entry_points raises, return empty registry."""
    with patch("importlib.metadata.entry_points",
               side_effect=ImportError("no metadata")):
        reg = discover_plugins()
    assert reg.plugins == []


def test_apply_to_invokes_callbacks():
    reg = loader.PluginRegistry()
    calls = []
    reg.register("p1", lambda orch: calls.append(1))
    reg.register("p2", lambda orch: calls.append(2))
    reg.apply_to(None)
    assert calls == [1, 2]
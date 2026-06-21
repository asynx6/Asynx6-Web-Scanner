"""Tests for plugin loader."""

from __future__ import annotations

from asynx6.plugins.loader import PLUGIN_GROUP, PluginRegistry, discover_plugins


def test_registry_register_and_apply():
    reg = PluginRegistry()
    calls: list[int] = []

    def cb(orch):
        calls.append(1)

    reg.register("test-plugin", cb)
    reg.apply_to(None)
    assert calls == [1]


def test_registry_apply_swallows_exceptions():
    reg = PluginRegistry()

    def bad_cb(_):
        raise RuntimeError("boom")

    reg.register("bad", bad_cb)
    # Should not raise
    reg.apply_to(None)


def test_discover_plugins_returns_empty_registry_by_default():
    reg = discover_plugins()
    assert isinstance(reg, PluginRegistry)
    # No plugins installed in the test env
    assert reg.plugins == []


def test_plugin_group_constant():
    assert PLUGIN_GROUP == "asynx6.plugins"
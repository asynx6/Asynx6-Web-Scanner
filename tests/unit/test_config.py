"""Tests for core.config."""

from __future__ import annotations

import pytest
import yaml
from pydantic import ValidationError

from asynx6.core.config import ScannerConfig, load_config, merge_overrides
from asynx6.core.exceptions import ConfigError


class TestLoadConfig:
    def test_defaults(self):
        cfg = load_config(None)
        assert cfg.threads == 25
        assert cfg.jitter_max >= cfg.jitter_min

    def test_from_yaml(self, tmp_path):
        p = tmp_path / "cfg.yaml"
        p.write_text(yaml.dump({"threads": 5, "aggressive": True}))
        cfg = load_config(p)
        assert cfg.threads == 5
        assert cfg.aggressive is True

    def test_missing_file(self, tmp_path):
        with pytest.raises(ConfigError):
            load_config(tmp_path / "missing.yaml")

    def test_invalid_yaml(self, tmp_path):
        p = tmp_path / "bad.yaml"
        p.write_text(":\n- :")
        with pytest.raises(ConfigError):
            load_config(p)

    def test_invalid_values(self):
        with pytest.raises(ValidationError):
            ScannerConfig(threads=0)


class TestMergeOverrides:
    def test_overrides_win(self):
        base = ScannerConfig(threads=10)
        out = merge_overrides(base, {"threads": 50})
        assert out.threads == 50
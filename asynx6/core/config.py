"""Pydantic-validated configuration for Asynx6 V2."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator


class RateLimitConfig(BaseModel):
    enabled: bool = True
    rps: float = Field(default=10.0, gt=0.0)
    burst: int = Field(default=20, gt=0)


class ScannerConfig(BaseModel):
    """Top-level scanner configuration."""

    jitter_min: float = Field(default=0.5, ge=0.0)
    jitter_max: float = Field(default=2.0, ge=0.0)
    threads: int = Field(default=25, gt=0, le=500)
    timeout: int = Field(default=10, gt=0, le=120)
    aggressive: bool = False
    output_dir: Path = Field(default_factory=lambda: Path("results"))
    report_format: str = "markdown"
    user_agents: list[str] = Field(default_factory=list)
    proxies: list[str] = Field(default_factory=list)
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)
    show_banner: bool = True

    @field_validator("report_format")
    @classmethod
    def _validate_format(cls, value: str) -> str:
        allowed = {"markdown", "json", "sarif", "html"}
        if value not in allowed:
            raise ValueError(f"report_format must be one of {allowed}, got {value!r}")
        return value

    @field_validator("jitter_max")
    @classmethod
    def _validate_jitter(cls, value: float, info: Any) -> float:
        jmin = info.data.get("jitter_min", 0.5)
        if value < jmin:
            raise ValueError(f"jitter_max ({value}) must be >= jitter_min ({jmin})")
        return value


def load_config(path: Path | str | None = None) -> ScannerConfig:
    """Load config from a YAML file, or return defaults.

    Args:
        path: Path to a YAML config file. If `None`, returns default config.

    Raises:
        ConfigError: if the file is malformed or validation fails.
    """
    if path is None:
        return ScannerConfig()
    p = Path(path)
    if not p.is_file():
        from asynx6.core.exceptions import ConfigError

        raise ConfigError(f"Config file not found: {p}")
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        from asynx6.core.exceptions import ConfigError

        raise ConfigError(f"Invalid YAML in {p}: {exc}") from exc
    try:
        return ScannerConfig(**data)
    except Exception as exc:
        from asynx6.core.exceptions import ConfigError

        raise ConfigError(f"Config validation failed: {exc}") from exc


def merge_overrides(base: ScannerConfig, overrides: dict[str, Any]) -> ScannerConfig:
    """Merge CLI overrides into a ScannerConfig (CLI wins)."""
    return base.model_copy(update=overrides)

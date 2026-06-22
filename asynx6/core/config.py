"""Pydantic-validated configuration for Asynx6 V2/V3.

V3 additions:
- Discriminated union for notifiers (slack | discord | telegram | webhook)
- proxies / verify_ssl / follow_redirects fields
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any, Literal, Union

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator


class RateLimitConfig(BaseModel):
    enabled: bool = True
    rps: float = Field(default=10.0, gt=0.0)
    burst: int = Field(default=20, gt=0)


# --- Notifier configs (discriminated union on `kind`) -----------------------

NotifierKind = Literal["slack", "discord", "telegram", "webhook"]


class _BaseNotifierConfig(BaseModel):
    """Base for all notifier configs."""

    model_config = ConfigDict(extra="forbid")
    kind: str


class SlackNotifierConfig(_BaseNotifierConfig):
    kind: Literal["slack"] = "slack"
    webhook_url: str
    channel: str | None = None
    username: str = "Asynx6"

    @field_validator("webhook_url")
    @classmethod
    def _validate_url(cls, value: str) -> str:
        if not value.startswith("https://hooks.slack.com/"):
            raise ValueError(
                "Slack webhook_url must start with https://hooks.slack.com/"
            )
        return value


class DiscordNotifierConfig(_BaseNotifierConfig):
    kind: Literal["discord"] = "discord"
    webhook_url: str
    username: str = "Asynx6"


class TelegramNotifierConfig(_BaseNotifierConfig):
    kind: Literal["telegram"] = "telegram"
    bot_token: str
    chat_id: str | int


class GenericWebhookNotifierConfig(_BaseNotifierConfig):
    kind: Literal["webhook"] = "webhook"
    url: str


# Discriminated union: pydantic uses `kind` to pick the right model.
NotifierConfig = Annotated[
    Union[
        SlackNotifierConfig,
        DiscordNotifierConfig,
        TelegramNotifierConfig,
        GenericWebhookNotifierConfig,
    ],
    Field(discriminator="kind"),
]


class ScannerConfig(BaseModel):
    """Top-level scanner configuration."""

    model_config = ConfigDict(extra="forbid")

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
    # V3 additions
    locale: str = "en"
    profile: str | None = None
    notifiers: list[NotifierConfig] = Field(default_factory=list)  # type: ignore[valid-type]
    persist: bool = False
    ml_filter: bool = False
    collaborator_domain: str | None = None
    web_dashboard: bool = False
    # Network options
    verify_ssl: bool = True
    follow_redirects: bool = True
    retry_total: int = Field(default=3, ge=0, le=10)

    @field_validator("report_format")
    @classmethod
    def _validate_format(cls, value: str) -> str:
        allowed = {"markdown", "json", "sarif", "html", "all"}
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
    if not isinstance(data, dict):
        from asynx6.core.exceptions import ConfigError

        raise ConfigError(f"Top-level YAML in {p} must be a mapping, got {type(data).__name__}")
    try:
        return ScannerConfig(**data)
    except Exception as exc:
        from asynx6.core.exceptions import ConfigError

        raise ConfigError(f"Config validation failed: {exc}") from exc


def merge_overrides(base: ScannerConfig, overrides: dict[str, Any]) -> ScannerConfig:
    """Merge CLI overrides into a ScannerConfig (CLI wins).

    Precedence (highest first): CLI overrides > profile > user config > defaults.
    This helper is the final step in the chain, so `overrides` always win.
    """
    return base.model_copy(update=overrides)

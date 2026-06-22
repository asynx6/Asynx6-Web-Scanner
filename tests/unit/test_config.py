"""Tests for core.config (V3 notifier discriminated union)."""

from __future__ import annotations

import pytest
import yaml
from pydantic import ValidationError

from asynx6.core.config import (
    DiscordNotifierConfig,
    GenericWebhookNotifierConfig,
    ScannerConfig,
    SlackNotifierConfig,
    TelegramNotifierConfig,
    load_config,
    merge_overrides,
)
from asynx6.core.exceptions import ConfigError


class TestLoadConfig:
    def test_defaults(self):
        cfg = load_config(None)
        assert cfg.threads == 25
        assert cfg.jitter_max >= cfg.jitter_min
        # V3 defaults
        assert cfg.verify_ssl is True
        assert cfg.follow_redirects is True
        assert cfg.retry_total == 3
        assert cfg.notifiers == []

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

    def test_top_level_must_be_mapping(self, tmp_path):
        p = tmp_path / "list.yaml"
        p.write_text("- one\n- two\n")
        with pytest.raises(ConfigError):
            load_config(p)


class TestMergeOverrides:
    def test_overrides_win(self):
        base = ScannerConfig(threads=10)
        out = merge_overrides(base, {"threads": 50})
        assert out.threads == 50

    def test_extra_field_rejected(self):
        with pytest.raises(ValidationError):
            ScannerConfig(threads=10, unknown_field="x")


class TestNotifierDiscriminatedUnion:
    def test_slack_valid(self):
        n = SlackNotifierConfig(
            webhook_url="https://hooks.slack.com/services/x",
            channel="#sec",
        )
        assert n.kind == "slack"
        assert n.channel == "#sec"

    def test_slack_invalid_url(self):
        with pytest.raises(ValidationError) as exc:
            SlackNotifierConfig(webhook_url="http://evil.com/x")
        assert "slack" in str(exc.value).lower()

    def test_discord_valid(self):
        n = DiscordNotifierConfig(webhook_url="https://discord.com/api/webhooks/x")
        assert n.kind == "discord"

    def test_telegram_valid(self):
        n = TelegramNotifierConfig(bot_token="TOKEN", chat_id=123)
        assert n.kind == "telegram"
        assert isinstance(n.chat_id, str | int)

    def test_webhook_valid(self):
        n = GenericWebhookNotifierConfig(url="https://example.com/h")
        assert n.kind == "webhook"

    def test_unknown_kind_rejected(self):
        with pytest.raises(ValidationError):
            ScannerConfig(
                notifiers=[{"kind": "pagerduty", "service_key": "x"}],
            )

    def test_missing_required_field_rejected(self):
        # slack needs webhook_url
        with pytest.raises(ValidationError):
            ScannerConfig(
                notifiers=[{"kind": "slack"}],
            )

    def test_extra_field_rejected(self):
        with pytest.raises(ValidationError):
            ScannerConfig(
                notifiers=[{
                    "kind": "slack",
                    "webhook_url": "https://hooks.slack.com/services/x",
                    "evil": "x",
                }],
            )

    def test_yaml_round_trip(self, tmp_path):
        p = tmp_path / "cfg.yaml"
        p.write_text(yaml.dump({
            "notifiers": [
                {
                    "kind": "slack",
                    "webhook_url": "https://hooks.slack.com/services/x",
                    "channel": "#sec",
                },
                {"kind": "discord", "webhook_url": "https://discord.com/api/webhooks/x"},
                {"kind": "telegram", "bot_token": "T", "chat_id": 1},
                {"kind": "webhook", "url": "https://example.com/h"},
            ],
        }))
        cfg = load_config(p)
        assert len(cfg.notifiers) == 4
        assert cfg.notifiers[0].kind == "slack"
        assert cfg.notifiers[1].kind == "discord"
        assert cfg.notifiers[2].kind == "telegram"
        assert cfg.notifiers[3].kind == "webhook"


class TestNetworkOptions:
    def test_proxies_parsed(self):
        cfg = ScannerConfig(proxies=["http://127.0.0.1:8080", "socks5://127.0.0.1:9050"])
        assert len(cfg.proxies) == 2

    def test_verify_ssl_disabled(self):
        cfg = ScannerConfig(verify_ssl=False)
        assert cfg.verify_ssl is False

    def test_follow_redirects_disabled(self):
        cfg = ScannerConfig(follow_redirects=False)
        assert cfg.follow_redirects is False

    def test_retry_total_validation(self):
        with pytest.raises(ValidationError):
            ScannerConfig(retry_total=-1)
        with pytest.raises(ValidationError):
            ScannerConfig(retry_total=999)

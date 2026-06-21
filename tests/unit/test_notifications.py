"""Tests for notifications package."""

from __future__ import annotations

from unittest.mock import patch

import pytest
import responses

from asynx6.notifications import Notification
from asynx6.notifications.discord import DiscordNotifier
from asynx6.notifications.slack import SlackNotifier
from asynx6.notifications.telegram import TelegramNotifier
from asynx6.notifications.webhook import WebhookNotifier


def _notif(severity: str = "CRITICAL") -> Notification:
    return Notification(
        title="[Asynx6] SQLi found",
        message="Critical SQLi at /x",
        severity=severity,
        url="https://example.com",
    )


class TestSlack:
    def test_url_validation(self):
        with pytest.raises(ValueError):
            SlackNotifier(webhook_url="http://evil.com/x")

    @responses.activate
    def test_send(self):
        responses.add(responses.POST, "https://hooks.slack.com/services/x",
                      status=200, body="ok")
        n = SlackNotifier(webhook_url="https://hooks.slack.com/services/x",
                          channel="#sec")
        assert n.send(_notif())


class TestDiscord:
    @responses.activate
    def test_send(self):
        responses.add(responses.POST, "https://discord.com/api/webhooks/x",
                      status=204)
        n = DiscordNotifier(webhook_url="https://discord.com/api/webhooks/x")
        assert n.send(_notif())


class TestTelegram:
    @responses.activate
    def test_send(self):
        responses.add(responses.POST,
                      "https://api.telegram.org/botTOKEN/sendMessage",
                      status=200, json={"ok": True})
        n = TelegramNotifier(bot_token="TOKEN", chat_id=123)
        assert n.send(_notif())


class TestWebhook:
    @responses.activate
    def test_send(self):
        responses.add(responses.POST, "https://example.com/hook",
                      status=200)
        n = WebhookNotifier(url="https://example.com/hook")
        assert n.send(_notif("HIGH"))
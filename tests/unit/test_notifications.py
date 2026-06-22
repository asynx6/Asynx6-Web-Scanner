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


class TestOrchestratorNotifications:
    """Tests for the orchestrator's notification dispatch (M1 + M2).

    M1: pydantic notifier configs are read with model_dump, not dict .get().
    M2: ``_phase_notifications`` is a module-level function. The test class
        still builds a minimal Orchestrator instance via ``__new__`` to skip
        network calls, then invokes the function explicitly with the
        orchestrator as the first argument.
    """

    def test_phase_notifications_dispatches_pydantic_config(self, tmp_path):
        """M1 fix: pydantic notifier configs are read with model_dump, not dict .get()."""
        from asynx6.core.config import (
            RateLimitConfig,
            ScannerConfig,
            SlackNotifierConfig,
        )
        from asynx6.core.models import Finding, ScanContext, Severity
        from asynx6.engine.orchestrator import Orchestrator, _phase_notifications
        from rich.progress import Progress

        responses.start()
        try:
            responses.add(
                responses.POST,
                "https://hooks.slack.com/services/abc",
                status=200,
                body="ok",
            )
            cfg = ScannerConfig(
                notifiers=[
                    SlackNotifierConfig(
                        webhook_url="https://hooks.slack.com/services/abc",
                        channel="#sec",
                    ),
                ],
                show_banner=False,
                output_dir=tmp_path,
                jitter_min=0.0,
                jitter_max=0.0,
                rate_limit=RateLimitConfig(enabled=False),
            )
            # Build a minimal context via direct construction (skip full Orchestrator
            # which would try to make network calls).
            orch = Orchestrator.__new__(Orchestrator)
            orch.target = "https://example.com"
            orch.config = cfg
            orch.ctx = ScanContext(
                target="https://example.com",
                base_url="https://example.com",
                domain="example.com",
            )
            orch.ctx.findings = [
                Finding(
                    type="Test critical",
                    severity=Severity.CRITICAL,
                    location="https://example.com/x",
                    description="x",
                ),
            ]
            with Progress() as p:
                _phase_notifications(orch, p)
        finally:
            responses.stop()
            responses.reset()

    def test_phase_notifications_empty_config(self, tmp_path):
        """No notifiers configured → phase is a no-op."""
        from asynx6.core.config import ScannerConfig
        from asynx6.core.models import ScanContext
        from asynx6.engine.orchestrator import Orchestrator, _phase_notifications
        from rich.progress import Progress

        cfg = ScannerConfig(notifiers=[], show_banner=False, output_dir=tmp_path)
        orch = Orchestrator.__new__(Orchestrator)
        orch.target = "https://example.com"
        orch.config = cfg
        orch.ctx = ScanContext(
            target="https://example.com",
            base_url="https://example.com",
            domain="example.com",
        )
        with Progress() as p:
            # Should not raise
            _phase_notifications(orch, p)

    def test_phase_notifications_unknown_kind(self, tmp_path):
        """An unknown notifier kind should log a warning, not crash."""
        from asynx6.core.config import ScannerConfig
        from asynx6.core.models import Finding, ScanContext, Severity
        from asynx6.engine.orchestrator import Orchestrator, _phase_notifications
        from rich.progress import Progress

        # pydantic will reject unknown kind at config-build time, so build a
        # config with a valid kind then mutate kind to test runtime resilience.
        cfg = ScannerConfig(
            notifiers=[],
            show_banner=False,
            output_dir=tmp_path,
        )
        orch = Orchestrator.__new__(Orchestrator)
        orch.target = "https://example.com"
        orch.config = cfg
        orch.ctx = ScanContext(
            target="https://example.com",
            base_url="https://example.com",
            domain="example.com",
        )
        orch.ctx.findings = [
            Finding(
                type="x", severity=Severity.CRITICAL,
                location="https://example.com/", description="x",
            ),
        ]
        # Inject a fake notifier object whose kind is unknown
        class _BogusCfg:
            def model_dump(self):
                return {"kind": "pagerduty", "service_key": "x"}

        cfg.notifiers = [_BogusCfg()]
        with Progress() as p:
            # Must not raise
            _phase_notifications(orch, p)
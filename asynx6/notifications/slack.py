"""Slack incoming-webhook notifier."""

from __future__ import annotations

from typing import Any

from asynx6.notifications.base import Notification, Notifier, _post_json


_COLOR = {
    "INFO": "#36a64f", "LOW": "#3aa3e3", "MEDIUM": "#daa038",
    "HIGH": "#dd5533", "CRITICAL": "#a72b2b",
}


class SlackNotifier(Notifier):
    """Send findings to a Slack channel via incoming webhook."""

    def __init__(self, webhook_url: str, channel: str | None = None,
                 username: str = "Asynx6") -> None:
        super().__init__(webhook_url=webhook_url, channel=channel, username=username)
        if not webhook_url.startswith("https://hooks.slack.com/"):
            raise ValueError(
                "Slack webhook_url must start with https://hooks.slack.com/"
            )

    def send(self, notification: Notification) -> bool:
        color = _COLOR.get(notification.severity, "#999999")
        attachment: dict[str, Any] = {
            "fallback": notification.title,
            "color": color,
            "title": notification.title,
            "text": notification.message,
            "fields": [
                {"title": "Severity", "value": notification.severity, "short": True},
            ],
        }
        if notification.url:
            attachment["title_link"] = notification.url
        payload: dict[str, Any] = {
            "username": self.config["username"],
            "attachments": [attachment],
        }
        if self.config.get("channel"):
            payload["channel"] = self.config["channel"]
        return _post_json(self.config["webhook_url"], payload)
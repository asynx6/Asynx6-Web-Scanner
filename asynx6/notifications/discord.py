"""Discord webhook notifier."""

from __future__ import annotations

from typing import Any

from asynx6.notifications.base import Notification, Notifier, _post_json


_COLOR = {
    "INFO": 0x36A64F, "LOW": 0x3AA3E3, "MEDIUM": 0xDAA038,
    "HIGH": 0xDD5533, "CRITICAL": 0xA72B2B,
}


class DiscordNotifier(Notifier):
    """Send findings to a Discord channel via webhook."""

    def __init__(self, webhook_url: str, username: str = "Asynx6") -> None:
        super().__init__(webhook_url=webhook_url, username=username)

    def send(self, notification: Notification) -> bool:
        color = _COLOR.get(notification.severity, 0x999999)
        embed: dict[str, Any] = {
            "title": notification.title,
            "description": notification.message,
            "color": color,
            "fields": [
                {"name": "Severity", "value": notification.severity, "inline": True},
            ],
        }
        if notification.url:
            embed["url"] = notification.url
        payload = {
            "username": self.config["username"],
            "embeds": [embed],
        }
        return _post_json(self.config["webhook_url"], payload)
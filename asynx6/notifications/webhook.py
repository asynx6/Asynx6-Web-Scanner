"""Generic webhook notifier (JSON POST)."""

from __future__ import annotations

from asynx6.notifications.base import Notification, Notifier, _post_json


class WebhookNotifier(Notifier):
    """Send a JSON payload to an arbitrary URL."""

    def __init__(self, url: str) -> None:
        super().__init__(url=url)

    def send(self, notification: Notification) -> bool:
        payload = {
            "title": notification.title,
            "message": notification.message,
            "severity": notification.severity,
            "url": notification.url,
            "extra": notification.extra or {},
        }
        return _post_json(self.config["url"], payload)
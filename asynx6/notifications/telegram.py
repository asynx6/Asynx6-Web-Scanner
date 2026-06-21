"""Telegram bot notifier."""

from __future__ import annotations

import json
from urllib.parse import urljoin

from asynx6.notifications.base import Notification, Notifier, _post_json


class TelegramNotifier(Notifier):
    """Send findings to a Telegram chat via bot API.

    Config:
        bot_token: Bot token issued by @BotFather
        chat_id: Target chat ID (channel or user)
    """

    API_BASE = "https://api.telegram.org"

    def __init__(self, bot_token: str, chat_id: str | int) -> None:
        super().__init__(bot_token=bot_token, chat_id=str(chat_id))
        self._url = urljoin(f"{self.API_BASE}/bot{bot_token}/", "sendMessage")

    def send(self, notification: Notification) -> bool:
        text = (
            f"*{notification.title}*\n"
            f"`{notification.severity}` — {notification.message}"
        )
        if notification.url:
            text += f"\n{notification.url}"
        payload = {
            "chat_id": self.config["chat_id"],
            "text": text,
            "parse_mode": "Markdown",
            "disable_web_page_preview": True,
        }
        return _post_json(self._url, payload)
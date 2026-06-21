"""Notification base class + registry."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

import requests

log = logging.getLogger(__name__)


@dataclass
class Notification:
    """A notification payload."""
    title: str
    message: str
    severity: str = "INFO"  # INFO | LOW | MEDIUM | HIGH | CRITICAL
    url: str | None = None
    extra: dict[str, Any] | None = None


class Notifier(ABC):
    """Base class for all notifiers."""

    def __init__(self, **config: Any) -> None:
        self.config = config

    @abstractmethod
    def send(self, notification: Notification) -> bool:
        """Send the notification. Returns True on success."""

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.config!r})"


def _post_json(url: str, payload: dict[str, Any], timeout: int = 10) -> bool:
    """Helper: POST JSON, return True on 2xx."""
    try:
        r = requests.post(url, json=payload, timeout=timeout)
        if r.status_code >= 400:
            log.warning("%s returned %d: %s", url, r.status_code, r.text[:200])
            return False
        return True
    except requests.RequestException as exc:
        log.warning("Notifier POST failed: %s", exc)
        return False
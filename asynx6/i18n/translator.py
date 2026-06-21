"""Tiny translator — no gettext dependency."""

from __future__ import annotations

from typing import Any

from asynx6.i18n.strings import EN, ID, SUPPORTED


class Translator:
    """Lookup helper for translation keys. Falls back to English."""

    def __init__(self, locale: str = "en") -> None:
        self.locale = locale if locale in SUPPORTED else "en"
        self._tables: dict[str, dict[str, str]] = {"en": EN, "id": ID}

    def t(self, key: str, **fmt: Any) -> str:
        """Translate `key`. Missing keys return the key itself."""
        text = self._tables.get(self.locale, EN).get(key)
        if text is None:
            text = EN.get(key, key)
        if fmt:
            try:
                return text.format(**fmt)
            except (KeyError, IndexError):
                return text
        return text


_current: Translator = Translator("en")


def set_locale(locale: str) -> None:
    global _current
    _current = Translator(locale)


def get_locale() -> str:
    return _current.locale


def t(key: str, **fmt: Any) -> str:
    return _current.t(key, **fmt)
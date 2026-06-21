"""Token generation for SSRF collaborator payloads."""

from __future__ import annotations

import secrets
import string
from typing import Final


_TOKEN_ALPHABET: Final[str] = string.ascii_lowercase + string.digits
_TOKEN_LENGTH: Final[int] = 16


def generate_token() -> str:
    """Generate a unique collaboration token (16 chars, URL-safe)."""
    return "".join(secrets.choice(_TOKEN_ALPHABET) for _ in range(_TOKEN_LENGTH))


def build_payload_url(domain: str, token: str, scheme: str = "http",
                      path: str = "/") -> str:
    """Build a payload URL pointing to the collaborator.

    Example:
        >>> build_payload_url("collab.asynx6.id", "abc123", path="/")
        'http://abc123.collab.asynx6.id/'
    """
    if not domain or not token:
        raise ValueError("domain and token must be non-empty")
    return f"{scheme}://{token}.{domain}{path}"
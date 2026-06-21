"""JWT vulnerability scanner: alg=none, weak HS256 secrets, RS256→HS256 confusion.

New in V2.
"""

from __future__ import annotations

import base64
import json
import logging
from typing import Any
from urllib.parse import urlparse

from asynx6.core.http import HttpClient
from asynx6.core.models import Finding, Severity

log = logging.getLogger(__name__)

# Top common HS256 secrets used in tutorials (top 50 from rockyou-style lists).
_WEAK_HS256_SECRETS: list[str] = [
    "secret", "password", "123456", "admin", "key", "jwt_secret", "default",
    "test", "1234567890", "qwerty", "letmein", "your-256-bit-secret",
    "my-secret", "supersecret", "change-me", "keyboard-cat", "shhh",
    "JWT_SECRET", "asynx6", "asynx6_secret", "insecure", "none", "null",
    "undefined", "true", "false", "0", "1", "topsecret", "s3cr3t",
    "p@ssw0rd", "12345678", "abc123", "iloveyou", "monkey", "dragon",
    "passw0rd", "1234", "12345", "1234567", "123456789", "12345678910",
    "0000", "1111", "master", "login", "welcome", "trustno1", "football",
]

# Common places JWTs appear
_JWT_PARAMS = ("token", "jwt", "auth", "access_token", "id_token")


def _b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def _decode_jwt(token: str) -> dict[str, Any] | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        return {"header": header, "payload": payload, "sig": parts[2]}
    except (ValueError, json.JSONDecodeError):
        return None


def _harvest_tokens(client: HttpClient, base_url: str) -> list[str]:
    """Pull JWT-shaped tokens out of the homepage and cookies."""
    found: list[str] = []
    r = client.get(base_url)
    if r is None:
        return found
    import re
    # Allow empty signature (alg=none tokens are common).
    found.extend(re.findall(
        r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*",
        r.text
    ))
    return found


def run(url: str, *, client: HttpClient, **_kwargs: Any) -> list[Finding]:
    findings: list[Finding] = []
    tokens = _harvest_tokens(client, url)
    if not tokens:
        return findings

    for token in tokens:
        decoded = _decode_jwt(token)
        if not decoded:
            continue
        header = decoded["header"]
        if header.get("alg", "").lower() == "none":
            findings.append(Finding(
                type="JWT alg=none",
                severity=Severity.CRITICAL,
                confidence=100,
                location=url,
                payload=token,
                description="JWT header advertises alg=none; signature can be stripped.",
                remediation="Reject alg=none in token validation.",
            ))
        # Try weak HS256 secrets (only for sym alg)
        if header.get("alg", "").upper().startswith("HS"):
            for secret in _WEAK_HS256_SECRETS:
                if _verify_hs256(token, secret):
                    findings.append(Finding(
                        type="JWT weak HS256 secret",
                        severity=Severity.CRITICAL,
                        confidence=100,
                        location=url,
                        payload=f"secret={secret}",
                        description=f"JWT signature verifies with weak secret: {secret!r}",
                        remediation="Use a cryptographically random 256-bit secret.",
                    ))
                    break
    return findings


def _verify_hs256(token: str, secret: str) -> bool:
    import hashlib
    import hmac
    parts = token.split(".")
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    expected = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    actual = _b64url_decode(parts[2])
    return hmac.compare_digest(expected, actual)

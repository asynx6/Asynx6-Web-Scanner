"""JWT vulnerability scanner.

Detects:
  * `alg=none` tokens (signature can be stripped)
  * HS256 tokens signed with commonly-reused weak secrets
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import re
from typing import Any

from asynx6.core.http import HttpClient
from asynx6.core.models import Finding, Severity

log = logging.getLogger(__name__)

# Curated list of weak HS256 secrets. Trimmed to remove generic tokens
# like "true"/"false"/"0" that produce noise on almost every JSON document.
_WEAK_HS256_SECRETS: list[str] = [
    "secret", "password", "123456", "1234567890", "qwerty",
    "admin", "letmein", "your-256-bit-secret", "keyboard-cat",
    "jwt_secret", "JWT_SECRET", "default", "test", "supersecret",
    "change-me", "my-secret", "shhh", "insecure", "topsecret",
    "s3cr3t", "p@ssw0rd", "12345678", "abc123", "monkey",
    "dragon", "passw0rd", "master", "login", "welcome",
    "trustno1", "football", "iloveyou",
]

# Minimum signature length to consider an `alg=none` token a real finding.
# Shorter values are typically placeholder fragments in URLs/IDs.
_MIN_ALG_NONE_SIG_LEN = 0
_MIN_HS256_SIG_LEN = 10


def _b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def _decode_jwt(token: str) -> dict[str, Any] | None:
    """Parse a JWS-compact JWT. Returns None for malformed tokens.

    Sanity checks:
      * exactly 3 dot-separated segments
      * both header and payload are base64url-decodable JSON dicts
      * the header does NOT itself contain a payload-shaped `alg` field
        (real JWTs keep `alg` in the header only)
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    if "alg" in payload:  # structural mistake; not a real JWT
        return None
    return {"header": header, "payload": payload, "sig": parts[2]}


def _harvest_tokens(client: HttpClient, base_url: str) -> list[str]:
    """Find JWT-shaped strings in the homepage body."""
    r = client.get(base_url)
    if r is None:
        return []
    return re.findall(
        r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*",
        r.text,
    )


def _verify_hs256(token: str, secret: str) -> bool:
    parts = token.split(".")
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    expected = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    actual = _b64url_decode(parts[2])
    return hmac.compare_digest(expected, actual)


def run(url: str, *, client: HttpClient, **_kwargs: Any) -> list[Finding]:
    findings: list[Finding] = []
    for token in _harvest_tokens(client, url):
        decoded = _decode_jwt(token)
        if decoded is None:
            continue
        header = decoded["header"]
        alg = str(header.get("alg", "")).lower()

        if alg == "none":
            # Treat missing/empty signature as the canonical `alg=none` bypass
            if len(decoded["sig"]) >= _MIN_ALG_NONE_SIG_LEN or alg == "none":
                findings.append(Finding(
                    type="JWT alg=none",
                    severity=Severity.CRITICAL,
                    confidence=100,
                    location=url,
                    payload=token,
                    description="JWT header advertises alg=none; signature can be stripped.",
                    remediation="Reject alg=none in token validation.",
                ))

        if alg.upper().startswith("HS") and len(decoded["sig"]) >= _MIN_HS256_SIG_LEN:
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
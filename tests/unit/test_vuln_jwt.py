"""Tests for vuln.jwt."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json

import responses

from asynx6.vuln.jwt import run


def _make_jwt(alg: str = "HS256", secret: str = "secret") -> str:
    def b64(d: bytes) -> str:
        return base64.urlsafe_b64encode(d).rstrip(b"=").decode()
    header = b64(json.dumps({"alg": alg, "typ": "JWT"}).encode())
    payload = b64(json.dumps({"sub": "1"}).encode())
    sig = b64(hmac.new(secret.encode(),
                       f"{header}.{payload}".encode(),
                       hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"


@responses.activate
def test_detects_alg_none(client):
    def b64(d: bytes) -> str:
        return base64.urlsafe_b64encode(d).rstrip(b"=").decode()
    header = b64(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = b64(json.dumps({"sub": "1"}).encode())
    token = f"{header}.{payload}."
    responses.add(responses.GET, "https://x.test/",
                  body=f"token={token}", status=200)
    out = run("https://x.test/", client=client)
    assert any("alg=none" in f.type for f in out)


@responses.activate
def test_detects_weak_hs256(client):
    token = _make_jwt(secret="secret")
    responses.add(responses.GET, "https://x.test/",
                  body=f"token={token}", status=200)
    out = run("https://x.test/", client=client)
    assert any("weak HS256" in f.type for f in out)


@responses.activate
def test_unknown_token_ignored(client):
    responses.add(responses.GET, "https://x.test/", body="no jwt here",
                  status=200)
    assert run("https://x.test/", client=client) == []


def test_weak_secret_list_excludes_obvious_noise():
    """Generic 1-char / literal-bool tokens must NOT be in the weak list."""
    from asynx6.vuln.jwt import _WEAK_HS256_SECRETS
    forbidden = {"0", "1", "true", "false", "null", "undefined", "asynx6"}
    overlap = set(_WEAK_HS256_SECRETS) & forbidden
    assert not overlap, f"Weak secret list still contains noise: {overlap}"


@responses.activate
def test_hs256_short_signature_skipped(client):
    """An HS256 token with a too-short signature should not be flagged,
    because short signatures usually mean a malformed/placeholder token."""
    def b64(d: bytes) -> str:
        import base64
        return base64.urlsafe_b64encode(d).rstrip(b"=").decode()
    header = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = b64(json.dumps({"sub": "1"}).encode())
    # Truncated signature (4 chars) — should be rejected as too short.
    token = f"{header}.{payload}.{b64(b'abcd')}"
    responses.add(responses.GET, "https://x.test/",
                  body=f"token={token}", status=200)
    assert run("https://x.test/", client=client) == []


@responses.activate
def test_token_with_payload_alg_key_ignored(client):
    """Structural invalidity: a 'JWT' whose payload also contains an 'alg'
    field is not a real JWT (real JWTs put alg in header only)."""
    def b64(d: bytes) -> str:
        import base64
        return base64.urlsafe_b64encode(d).rstrip(b"=").decode()
    header = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = b64(json.dumps({"sub": "1", "alg": "HS256"}).encode())
    sig = b64(hmac.new(b"secret", f"{header}.{payload}".encode(),
                       hashlib.sha256).digest())
    token = f"{header}.{payload}.{sig}"
    responses.add(responses.GET, "https://x.test/",
                  body=f"token={token}", status=200)
    # The structural-check rejects the token before any secret verification.
    assert run("https://x.test/", client=client) == []
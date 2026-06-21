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
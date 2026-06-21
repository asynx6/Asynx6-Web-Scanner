"""Tests for recon.architect."""

from __future__ import annotations

from asynx6.recon.architect import analyze


def test_finds_aws_key():
    js = 'const k = "AKIAEXAMPLE0000000000";'
    out = analyze("https://x.test/app.js", js)
    types = {f.type for f in out}
    assert any("AWS Access Key" in t for t in types)


def test_finds_internal_ip():
    js = "var ip = '10.0.0.5';"
    out = analyze("https://x.test/app.js", js)
    assert any("Internal IP" in f.type for f in out)


def test_ignores_junk():
    js = 'function init() { return "reset"; }'
    out = analyze("https://x.test/app.js", js)
    # Junk tokens shouldn't be reported as secrets
    for f in out:
        assert f.severity.value != "CRITICAL"
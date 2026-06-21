"""Tests for exfil.secrets_archive."""

from __future__ import annotations

from asynx6.exfil.secrets_archive import run


SAMPLE_VAULT = """# 🗝️ LOOT VAULT
> RAW SECRETS

| Timestamp | URL | Type | Value |
|---|---|---|---|
| 2026-01-01 00:00:00 | https://x/ | AWS Access Key | `AKIAEXAMPLE0000000000` |
| 2026-01-01 00:00:01 | https://x/ | Stripe API Key | `sk_test_PLACEHOLDER000000000000` |
"""


def test_archives_categorized(tmp_path):
    vault = tmp_path / "vault.md"
    vault.write_text(SAMPLE_VAULT, encoding="utf-8")
    out = run(vault, tmp_path)
    assert out["total"] == 2
    assert "AWS Access Key" in out["by_type"]
    json_path = tmp_path / "secrets.json"
    assert json_path.exists()
    import json
    data = json.loads(json_path.read_text())
    assert data["total"] == 2


def test_missing_vault(tmp_path):
    out = run(tmp_path / "nope.md", tmp_path)
    assert out["total"] == 0
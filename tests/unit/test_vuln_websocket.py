"""Tests for config V3 additions."""

from __future__ import annotations

from asynx6.core.config import ScannerConfig, SlackNotifierConfig


def test_v3_locale_field():
    cfg = ScannerConfig(locale="id")
    assert cfg.locale == "id"


def test_v3_notifiers_list():
    cfg = ScannerConfig(notifiers=[
        SlackNotifierConfig(webhook_url="https://hooks.slack.com/x"),
    ])
    assert len(cfg.notifiers) == 1
    assert cfg.notifiers[0].kind == "slack"


def test_v3_persist_flag():
    cfg = ScannerConfig(persist=True)
    assert cfg.persist is True


def test_v3_ml_filter_flag():
    cfg = ScannerConfig(ml_filter=True)
    assert cfg.ml_filter is True


def test_v3_collaborator_domain():
    cfg = ScannerConfig(collaborator_domain="collab.example.com")
    assert cfg.collaborator_domain == "collab.example.com"


def test_v3_verify_ssl_flag():
    cfg = ScannerConfig(verify_ssl=False)
    assert cfg.verify_ssl is False


def test_v3_proxies_list():
    cfg = ScannerConfig(proxies=["http://127.0.0.1:8080"])
    assert cfg.proxies == ["http://127.0.0.1:8080"]
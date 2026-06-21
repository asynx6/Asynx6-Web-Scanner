"""Tests for config V3 additions."""

from __future__ import annotations

from asynx6.core.config import NotifierConfig, ScannerConfig


def test_v3_locale_field():
    cfg = ScannerConfig(locale="id")
    assert cfg.locale == "id"


def test_v3_notifiers_list():
    cfg = ScannerConfig(notifiers=[
        NotifierConfig(kind="slack", webhook_url="https://hooks.slack.com/x"),
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
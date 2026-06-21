"""Tests for collaborator.client (V3)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from asynx6.collaborator.client import CollaboratorClient


def test_issue_token_registers():
    client = CollaboratorClient(domain="collab.example.com")
    token = client.issue_token()
    assert token in client.tokens()
    assert len(client.tokens()) == 1


def test_payload_url_builds_correct_url():
    client = CollaboratorClient(domain="d.com")
    token = client.issue_token()
    url = client.payload_url(token, path="/x")
    assert token in url
    assert "d.com" in url
    assert url.endswith("/x")


def test_poll_returns_false_on_none_response():
    """HttpClient.get returns None on failure; poll returns False."""
    fake_client = MagicMock()
    fake_client.get.return_value = None
    with patch("asynx6.core.http.HttpClient") as MockClient:
        MockClient.return_value.__enter__.return_value = fake_client
        client = CollaboratorClient(domain="d.com")
        assert client.poll("anytoken") is False


def test_poll_returns_true_on_hit():
    fake_resp = MagicMock(status_code=200, content=b"hit")
    fake_client = MagicMock()
    fake_client.get.return_value = fake_resp
    with patch("asynx6.core.http.HttpClient") as MockClient:
        MockClient.return_value.__enter__.return_value = fake_client
        client = CollaboratorClient(domain="d.com")
        assert client.poll("mytoken") is True


def test_wait_for_hit_returns_immediately_when_hit():
    fake_resp = MagicMock(status_code=200, content=b"hit")
    fake_client = MagicMock()
    fake_client.get.return_value = fake_resp
    with patch("asynx6.core.http.HttpClient") as MockClient:
        MockClient.return_value.__enter__.return_value = fake_client
        client = CollaboratorClient(domain="d.com", poll_interval=0.01)
        assert client.wait_for_hit("x", timeout=5.0) is True


def test_wait_for_hit_returns_false_on_timeout():
    fake_client = MagicMock()
    fake_client.get.return_value = None
    with patch("asynx6.core.http.HttpClient") as MockClient:
        MockClient.return_value.__enter__.return_value = fake_client
        client = CollaboratorClient(domain="d.com", poll_interval=0.01)
        assert client.wait_for_hit("x", timeout=0.05) is False
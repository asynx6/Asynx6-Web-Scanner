"""Tests for exfil.db_mysql."""

from __future__ import annotations

from unittest.mock import MagicMock, patch


def _make_fake_conn():
    """Build a MagicMock that quacks like a mysql.connector.Connection."""
    cur = MagicMock()
    # First fetchone call returns 4-tuple user info; subsequent return file_priv.
    cur.fetchone.side_effect = [
        ("u@h", "u@h", "8.0", "Linux"),
        ("",),  # secure_file_priv
    ]
    cur.fetchall.return_value = [("db", "users")]

    conn = MagicMock()
    conn.is_connected.return_value = True
    conn.cursor.return_value = cur
    return conn


def test_returns_breach_finding_when_creds_work():
    fake = _make_fake_conn()
    with patch("mysql.connector.connect", return_value=fake):
        out = run("1.2.3.4", port=3306)
    assert out, "expected at least one finding"
    assert out[0].type == "SQL Direct Access — BREACHED"


def test_returns_open_port_finding_when_no_creds():
    def boom(*_a, **_kw):
        raise Exception("auth failed")
    with patch("mysql.connector.connect", side_effect=boom):
        out = run("1.2.3.4", port=3306)
    assert out
    assert out[0].type == "Exposed MySQL port"


# Import at bottom so the test body above is clean.
from asynx6.exfil.db_mysql import run  # noqa: E402
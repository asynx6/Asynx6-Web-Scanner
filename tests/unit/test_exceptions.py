"""Tests for core.exceptions."""

from __future__ import annotations

from asynx6.core.exceptions import (
    Asynx6Error, ConfigError, ExfilError, FuzzError, HttpError,
    HttpRateLimited, HttpTimeout, ReconError, ReportingError, TemplateError,
    VulnError, safe_call,
)


def test_inheritance():
    assert issubclass(ConfigError, Asynx6Error)
    assert issubclass(HttpRateLimited, HttpError)
    assert issubclass(HttpTimeout, HttpError)
    assert issubclass(ReconError, Asynx6Error)
    assert issubclass(VulnError, Asynx6Error)
    assert issubclass(FuzzError, Asynx6Error)
    assert issubclass(ExfilError, Asynx6Error)
    assert issubclass(TemplateError, Asynx6Error)
    assert issubclass(ReportingError, Asynx6Error)


def test_safe_call_returns_default_on_exception():
    @safe_call(default="x")
    def boom():
        raise ValueError("nope")
    assert boom() == "x"


def test_safe_call_returns_value_on_success():
    @safe_call(default=None)
    def ok():
        return 42
    assert ok() == 42
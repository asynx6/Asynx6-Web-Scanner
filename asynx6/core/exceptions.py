"""Custom exception hierarchy for Asynx6 V2.

All exceptions inherit from `Asynx6Error` so callers can catch the whole family.
Module-specific errors add a prefix so log messages stay greppable.
"""

from __future__ import annotations


class Asynx6Error(Exception):
    """Base exception for all Asynx6 errors."""


class HttpError(Asynx6Error):
    """Raised when an HTTP request fails unrecoverably."""


class HttpRateLimited(HttpError):
    """Raised when the target returns 429 and retries are exhausted."""


class HttpTimeout(HttpError):
    """Raised when an HTTP request exceeds the configured timeout."""


class ConfigError(Asynx6Error):
    """Raised when configuration is invalid."""


class ReconError(Asynx6Error):
    """Base for recon-module errors."""


class VulnError(Asynx6Error):
    """Base for vuln-module errors."""


class FuzzError(Asynx6Error):
    """Base for fuzz-module errors."""


class ExfilError(Asynx6Error):
    """Base for exfil-module errors."""


class TemplateError(Asynx6Error):
    """Raised when a template YAML is malformed or fails validation."""


class ReportingError(Asynx6Error):
    """Raised when report generation fails."""


class EngineError(Asynx6Error):
    """Raised when orchestration fails."""


def safe_call(default: object = None, *, log_errors: bool = True) -> callable:
    """Decorator that converts exceptions to a default return value.

    Intended for use in fire-and-forget callbacks (thread workers, signal handlers)
    where raising would crash the pool. Logs the error at WARNING level.
    """

    def decorator(func: callable) -> callable:
        import functools
        import logging

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as exc:  # noqa: BLE001
                if log_errors:
                    logging.getLogger(func.__module__).warning(
                        "%s in %s: %s", type(exc).__name__, func.__qualname__, exc
                    )
                return default

        return wrapper

    return decorator

"""Vulnerability modules: sqli, xss, lfi, ssrf, open_redirect, jwt, graphql,
cors, headers, idor."""

from asynx6.vuln.sqli import run as sqli_run
from asynx6.vuln.xss import run as xss_run
from asynx6.vuln.lfi import run as lfi_run
from asynx6.vuln.ssrf import run as ssrf_run
from asynx6.vuln.open_redirect import run as open_redirect_run
from asynx6.vuln.jwt import run as jwt_run
from asynx6.vuln.graphql import run as graphql_run
from asynx6.vuln.cors import run as cors_run
from asynx6.vuln.headers import run as headers_run
from asynx6.vuln.idor import run as idor_run

__all__ = [
    "sqli_run", "xss_run", "lfi_run", "ssrf_run", "open_redirect_run",
    "jwt_run", "graphql_run", "cors_run", "headers_run", "idor_run",
]

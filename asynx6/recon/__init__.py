"""Recon modules: subdomain, network, DNS, Wayback, headless, crawler, architect."""

from asynx6.recon.chameleon import detect_stack as chameleon_detect
from asynx6.recon.subdomain import run as subdomain_run
from asynx6.recon.network import run as network_run
from asynx6.recon.dns_enum import run as dns_enum_run
from asynx6.recon.wayback import run as wayback_run
from asynx6.recon.headless import run as headless_run
from asynx6.recon.crawler import run as crawler_run
from asynx6.recon.architect import run as architect_run

__all__ = [
    "chameleon_detect",
    "subdomain_run",
    "network_run",
    "dns_enum_run",
    "wayback_run",
    "headless_run",
    "crawler_run",
    "architect_run",
]
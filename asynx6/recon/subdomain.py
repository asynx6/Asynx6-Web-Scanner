"""Subdomain discovery (passive crt.sh + active wordlist + wildcard filter)."""

from __future__ import annotations

import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

import requests
from rich.console import Console

from asynx6.core.http import HttpClient
from asynx6.core.models import Subdomain

log = logging.getLogger(__name__)
console = Console()

# V1 wordlist preserved for behavioral parity
_WORDLIST: list[str] = [
    "dev", "staging", "api", "api-test", "v1", "v2", "test", "demo",
    "beta", "admin", "administrator", "portal", "dashboard", "manage",
    "webmail", "mail", "vpn", "remote", "git", "gitlab", "jenkins",
    "docker", "k8s", "aws", "s3", "cloud", "billing", "payment", "shop",
]

CRT_SH_URL = "https://crt.sh/?q=%25.{domain}&output=json"


def _query_crt(domain: str) -> set[str]:
    """Query crt.sh for passive subdomain enumeration."""
    found: set[str] = set()
    try:
        res = requests.get(CRT_SH_URL.format(domain=domain), timeout=15)
        if res.status_code != 200:
            return found
        for entry in res.json():
            for sub in entry.get("name_value", "").split("\n"):
                sub = sub.strip().lower()
                if sub.endswith(domain) and "*" not in sub:
                    found.add(sub)
    except (requests.RequestException, ValueError) as exc:
        log.warning("crt.sh query failed for %s: %s", domain, exc)
    return found


def _detect_wildcard(domain: str) -> Optional[str]:
    """Return the IP that a wildcard DNS resolves to, or None if no wildcard."""
    import random as _r
    try:
        rand = _r.randint(10_000, 99_999)
        return socket.gethostbyname(f"asynx6-probe-{rand}.{domain}")
    except socket.gaierror:
        return None


def _resolve(sub: str, domain: str, wildcard_ip: Optional[str]) -> Optional[Subdomain]:
    target = sub if sub.endswith(domain) else f"{sub}.{domain}"
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        return None
    if wildcard_ip and ip == wildcard_ip:
        return None
    return Subdomain(subdomain=target, ip=ip)


def run(url: str, client: HttpClient | None = None,
        threads: int = 30) -> list[Subdomain]:
    """Discover subdomains via crt.sh + wordlist. Returns deduplicated, sorted list.

    Args:
        url: Target URL or domain.
        client: Optional HttpClient (unused, kept for interface parity).
        threads: Concurrent DNS workers.
    """
    from asynx6.core.validators import extract_domain
    domain = extract_domain(url)
    console.print(f"[cyan][*] Subdomain discovery: {domain}[/]")

    wildcard_ip = _detect_wildcard(domain)
    if wildcard_ip:
        console.print(f"[yellow][!] Wildcard DNS detected: {wildcard_ip} (filtering)[/]")

    passive = _query_crt(domain)
    candidates = set(_WORDLIST) | {s.replace(f".{domain}", "") for s in passive}

    discovered: list[Subdomain] = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(_resolve, c, domain, wildcard_ip) for c in candidates]
        for fut in as_completed(futures):
            try:
                result = fut.result()
            except Exception as exc:  # noqa: BLE001
                log.warning("Subdomain resolution error: %s", exc)
                continue
            if result is not None:
                discovered.append(result)
    return sorted(discovered, key=lambda s: s.subdomain)

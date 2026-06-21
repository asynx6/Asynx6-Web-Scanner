"""Network recon: port scan, WAF detection, CDN bypass / origin IP discovery.

V1 fix: replaces V1's heavy use of `try/except: pass` with logged exceptions.
"""

from __future__ import annotations

import logging
import socket
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

import requests
from rich.console import Console

from asynx6.core.http import HttpClient, get_morphing_headers
from asynx6.core.models import OpenPort, OriginIP, Severity

log = logging.getLogger(__name__)
console = Console()

# Suppress InsecureRequestWarning for CDN bypass probes
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Subdomains to probe when hunting origin IPs
_ORIGIN_SUBS = ["direct", "origin", "dev", "staging", "api", "vpn", "mail"]

# Common ports scanned by default
_COMMON_PORTS: list[int] = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433,
                            1521, 3306, 3389, 5432, 8080, 8443, 9000, 27017]

_WAF_SIGNATURES = {
    "cloudflare": "Cloudflare",
    "sucuri": "Sucuri",
    "akamai": "Akamai",
    "incapsula": "Imperva Incapsula",
    "f5": "F5 BIG-IP",
}


def _probe_waf(url: str, client: HttpClient) -> str:
    """Inspect headers + payload-response to fingerprint a WAF."""
    r = client.get(url, rate_limit=False, jitter=False)
    if r is None:
        return "None"
    headers_str = str(r.headers).lower()
    for sig, name in _WAF_SIGNATURES.items():
        if sig in headers_str:
            return name
    # Active probe: send an XSS-looking payload and watch for block
    sep = "&" if "?" in url else "?"
    probe = client.get(f"{url}{sep}id=<script>alert('WAF_TEST')</script>",
                       rate_limit=False, jitter=False)
    if probe and probe.status_code in (403, 406, 429, 501):
        return f"{name} (Confirmed via Payload Blocking)" if name != "None" \
            else "Generic WAF (Blocked Payload)"
    return "None"


def _resolve(domain: str) -> Optional[str]:
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror as exc:
        log.warning("DNS resolution failed for %s: %s", domain, exc)
        return None


def _scan_port(ip: str, port: int) -> Optional[OpenPort]:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.5)
            if s.connect_ex((ip, port)) != 0:
                return None
            banner = "Unknown"
            try:
                if port in (80, 8080):
                    s.sendall(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                    banner = s.recv(1024).decode(errors="ignore").split("\n")[0].strip()
                elif port == 3306:
                    banner = s.recv(1024).decode(errors="ignore")[5:20].strip()
                else:
                    s.sendall(b"\r\n")
                    banner = s.recv(1024).decode(errors="ignore").strip()
            except OSError:
                pass
            try:
                service = socket.getservbyport(port)
            except (OSError, OverflowError):
                service = "Unknown"

            severity = Severity.LOW
            if port == 3306:
                severity = Severity.CRITICAL
            elif port in (22, 21, 445, 3389, 1433, 5432):
                severity = Severity.HIGH
            return OpenPort(port=port, service=service, banner=banner[:100],
                            severity=severity)
    except OSError as exc:
        log.debug("Port %d scan error on %s: %s", port, ip, exc)
        return None


def _port_scan(ip: str, full: bool, workers: int) -> list[OpenPort]:
    if full:
        ports = range(1, 61112)
        workers = min(workers, 500)
    else:
        ports = _COMMON_PORTS
    if ip in ("127.0.0.1", "::1"):
        workers = min(workers, 10)
    open_ports: list[OpenPort] = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for fut in as_completed([ex.submit(_scan_port, ip, p) for p in ports]):
            r = fut.result()
            if r:
                open_ports.append(r)
    return sorted(open_ports, key=lambda p: p.port)


def _find_origin_ips(domain: str, url: str) -> list[OriginIP]:
    """Try direct-connect to common subdomains to expose the origin behind CDN."""
    proto = "https" if "https" in url else "http"
    found: list[OriginIP] = []
    # Get baseline response size
    try:
        baseline = requests.get(f"{proto}://{domain}", timeout=5,
                                headers=get_morphing_headers(), verify=False)
        base_len = len(baseline.content)
    except requests.RequestException as exc:
        log.warning("Baseline origin check failed: %s", exc)
        base_len = 0

    for sub in _ORIGIN_SUBS:
        target_sub = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(target_sub)
        except socket.gaierror:
            continue
        try:
            sub_res = requests.get(f"{proto}://{ip}", timeout=5,
                                   headers={"Host": domain}, verify=False)
            sub_len = len(sub_res.content)
            if base_len and abs(sub_len - base_len) < base_len * 0.2:
                confidence = "HIGH (Content Match)"
            else:
                confidence = "LOW (Different Content)"
        except requests.RequestException:
            confidence = "MEDIUM (No Content Access)"
        found.append(OriginIP(subdomain=sub, ip=ip, confidence=confidence))
    return found


def run(url: str, client: HttpClient, *, full_port_scan: bool = False) -> dict:
    """Top-level network recon. Returns dict with ip, waf, ports, origin_ips."""
    from asynx6.core.validators import extract_domain
    domain = extract_domain(url)
    ip = _resolve(domain)
    if not ip:
        return {"ip": None, "waf": "None", "ports": [], "origin_ips": [],
                "location": "Unknown", "isp": "Unknown"}

    origin_ips = _find_origin_ips(domain, url)
    main_ports = _port_scan(ip, full_port_scan, workers=20)
    waf = _probe_waf(url, client)
    location, isp = _geo_lookup(ip)

    for entry in origin_ips:
        if entry.confidence.startswith("HIGH"):
            entry.ports = [  # type: ignore[assignment]
                {"port": p.port, "service": p.service, "severity": p.severity.value}
                for p in _port_scan(entry.ip, full_port_scan, workers=20)
            ]
    return {
        "ip": ip,
        "waf": waf,
        "ports": main_ports,
        "origin_ips": origin_ips,
        "location": location,
        "isp": isp,
    }


def _geo_lookup(ip: str) -> tuple[str, str]:
    """Try ipapi.co / ip-api.com to enrich with location and ISP."""
    for provider in (f"https://ipapi.co/{ip}/json/", f"http://ip-api.com/json/{ip}"):
        try:
            r = requests.get(provider, timeout=5)
            if r.status_code != 200:
                continue
            data = r.json()
            if "city" in data:
                location = f"{data.get('city')}, {data.get('country_name') or data.get('country')}"
                isp = data.get("org") or data.get("isp") or "Unknown"
                return location, isp
        except (requests.RequestException, ValueError):
            continue
    return "Unknown", "Unknown"

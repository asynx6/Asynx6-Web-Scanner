"""Scan profiles — preset configurations for common workflows.

New in V3. Each profile is a ScannerConfig preset focused on a specific use
case (quick triage, OWASP Top 10, full deep scan, etc.).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from asynx6.core.config import ScannerConfig, RateLimitConfig


@dataclass(frozen=True)
class Profile:
    """A named scan profile."""
    name: str
    description: str
    config: ScannerConfig
    enabled_phases: list[str] = field(default_factory=list)


def quick_triage() -> Profile:
    """Fast scan — subdomain + critical vulns only. ~30 seconds."""
    return Profile(
        name="quick-triage",
        description="Quick triage: subdomain + critical vulns only",
        config=ScannerConfig(
            threads=20, timeout=5, jitter_min=0.1, jitter_max=0.5,
            aggressive=False, report_format="markdown",
        ),
        enabled_phases=["chameleon", "subdomain", "network", "vuln_sqli",
                        "vuln_lfi", "vuln_jwt"],
    )


def owasp_top10() -> Profile:
    """Targeted at OWASP Top 10 categories."""
    return Profile(
        name="owasp-top10",
        description="OWASP Top 10 (2021) coverage",
        config=ScannerConfig(
            threads=15, timeout=10, jitter_min=0.5, jitter_max=2.0,
            aggressive=False, report_format="html",
        ),
        enabled_phases=["chameleon", "subdomain", "network", "headless",
                        "crawler", "vuln_sqli", "vuln_xss", "vuln_lfi",
                        "vuln_ssrf", "vuln_idor", "vuln_headers",
                        "vuln_cors", "fuzz_directory", "fuzz_api"],
    )


def deep() -> Profile:
    """Full deep scan — everything enabled, slow and thorough."""
    return Profile(
        name="deep",
        description="Full deep scan: all modules, slow, aggressive",
        config=ScannerConfig(
            threads=10, timeout=20, jitter_min=1.0, jitter_max=3.0,
            aggressive=True, report_format="all",
            rate_limit=RateLimitConfig(rps=2, burst=5),
        ),
        enabled_phases=["chameleon", "subdomain", "network", "dns_enum",
                        "wayback", "headless", "crawler", "architect",
                        "vuln_sqli", "vuln_xss", "vuln_lfi", "vuln_ssrf",
                        "vuln_open_redirect", "vuln_jwt", "vuln_graphql",
                        "vuln_cors", "vuln_headers", "vuln_idor",
                        "vuln_websocket", "fuzz_directory", "fuzz_api",
                        "fuzz_templates", "exfil_db"],
    )


def stealth() -> Profile:
    """Slow, low-noise scan designed to evade WAF/IDS detection."""
    return Profile(
        name="stealth",
        description="Stealth: slow jitter, no fuzzing, minimal probes",
        config=ScannerConfig(
            threads=2, timeout=30, jitter_min=5.0, jitter_max=15.0,
            aggressive=False, report_format="json",
            rate_limit=RateLimitConfig(rps=0.5, burst=1),
        ),
        enabled_phases=["chameleon", "subdomain", "network", "wayback",
                        "headless", "vuln_headers", "vuln_cors"],
    )


def ci_pipeline() -> Profile:
    """CI-mode: exit-code oriented, SARIF output, baseline diff."""
    return Profile(
        name="ci",
        description="CI pipeline: fast + SARIF + baseline diff",
        config=ScannerConfig(
            threads=20, timeout=5, jitter_min=0.1, jitter_max=0.5,
            aggressive=False, report_format="sarif",
            show_banner=False,
        ),
        enabled_phases=["chameleon", "vuln_sqli", "vuln_xss", "vuln_lfi",
                        "vuln_headers", "vuln_cors", "vuln_idor"],
    )


# Profile registry
_REGISTRY: dict[str, Profile] = {
    "quick-triage": quick_triage(),
    "owasp-top10": owasp_top10(),
    "deep": deep(),
    "stealth": stealth(),
    "ci": ci_pipeline(),
}


def get_profile(name: str) -> Profile:
    """Return profile by name. Raises KeyError if unknown."""
    return _REGISTRY[name]


def list_profiles() -> list[Profile]:
    """Return all registered profiles."""
    return list(_REGISTRY.values())


def apply_profile(cfg: ScannerConfig, profile_name: str) -> ScannerConfig:
    """Merge profile config over a base ScannerConfig (profile wins)."""
    p = get_profile(profile_name)
    return p.config.model_copy(update=cfg.model_dump())
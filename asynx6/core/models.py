"""Domain types (dataclasses) used across the scanner."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """CVSS-aligned severity."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        order = [self.INFO, self.LOW, self.MEDIUM, self.HIGH, self.CRITICAL]
        return order.index(self)


@dataclass(frozen=True)
class Subdomain:
    """A discovered subdomain with its resolved IP."""

    subdomain: str
    ip: str


@dataclass(frozen=True)
class OriginIP:
    """A potential origin IP found via CDN bypass."""

    subdomain: str
    ip: str
    confidence: str  # "HIGH" | "MEDIUM" | "LOW"
    ports: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class OpenPort:
    """A discovered open port."""

    port: int
    service: str
    banner: str
    severity: Severity


@dataclass(frozen=True)
class Finding:
    """A single vulnerability finding produced by any module."""

    type: str
    severity: Severity
    location: str
    description: str
    confidence: int = 50  # 0-100
    payload: str | None = None
    evidence: str | None = None
    remediation: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "severity": self.severity.value,
            "location": self.location,
            "description": self.description,
            "confidence": self.confidence,
            "payload": self.payload,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "extra": self.extra,
        }


@dataclass(frozen=True)
class LootItem:
    """A file/content retrieved from the target."""

    url: str
    filename: str
    md5: str
    content_type: str
    is_binary: bool = False


@dataclass
class ScanContext:
    """Mutable context that flows through the orchestration pipeline."""

    target: str
    base_url: str
    domain: str
    aggressive: bool = False
    output_dir: str = ""
    # Findings accumulated across phases
    findings: list[Finding] = field(default_factory=list)
    subdomains: list[Subdomain] = field(default_factory=list)
    origin_ips: list[OriginIP] = field(default_factory=list)
    open_ports: list[OpenPort] = field(default_factory=list)
    loot: list[LootItem] = field(default_factory=list)
    pages_visited: set[str] = field(default_factory=set)
    js_files: set[str] = field(default_factory=set)
    hidden_endpoints: set[str] = field(default_factory=set)
    forms: list[dict[str, Any]] = field(default_factory=list)
    tech_stack: dict[str, str] = field(default_factory=dict)
    waf: str = "None"
    # Dynamic content captured by headless crawler (used to seed wordlist)
    dynamic_content: str = ""
    # M2: phase allowlist. Empty = run all registered phases.
    active_phases: set[str] = field(default_factory=set)

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def extend_findings(self, findings: list[Finding]) -> None:
        self.findings.extend(findings)

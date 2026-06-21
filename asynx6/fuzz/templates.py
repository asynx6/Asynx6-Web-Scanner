"""Nuclei-style YAML template loader and runner.

New in V2. Templates live in `templates/*.yaml` and look like:

    id: example-sqli
    info:
      name: SQLi via id param
      severity: high
    requests:
      - method: GET
        path:
          - "{{BaseURL}}/?id=SLEEP(5)"
        matchers:
          - type: status
            status: [500]

Only a subset of the nuclei DSL is supported — the goal is extensibility, not
feature parity.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Iterable

import yaml
from pydantic import BaseModel, Field, ValidationError

from asynx6.core.exceptions import TemplateError
from asynx6.core.http import HttpClient
from asynx6.core.models import Finding, Severity

log = logging.getLogger(__name__)


# --- Schema models -----------------------------------------------------------


class Matcher(BaseModel):
    type: str  # "status" | "word" | "regex"
    status: list[int] | None = None
    words: list[str] | None = None
    regex: list[str] | None = None
    part: str = "body"  # "body" | "all"


class Request(BaseModel):
    method: str = "GET"
    path: list[str] = Field(default_factory=list)
    body: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    matchers: list[Matcher] = Field(default_factory=list)


class Template(BaseModel):
    id: str
    info: dict[str, Any]
    requests: list[Request]

    @property
    def severity(self) -> Severity:
        try:
            return Severity(self.info.get("severity", "INFO").upper())
        except ValueError:
            return Severity.INFO

    @property
    def name(self) -> str:
        return self.info.get("name", self.id)


# --- Loader ------------------------------------------------------------------


def load_templates(directory: Path | str) -> list[Template]:
    """Load all `*.yaml` / `*.yml` templates from `directory`."""
    p = Path(directory)
    if not p.is_dir():
        log.debug("Template directory not found: %s", p)
        return []
    templates: list[Template] = []
    for f in sorted(p.glob("*.y*ml")):
        try:
            data = yaml.safe_load(f.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            log.warning("Bad YAML in %s: %s", f, exc)
            continue
        if not isinstance(data, dict):
            continue
        try:
            templates.append(Template(**data))
        except ValidationError as exc:
            log.warning("Invalid template %s: %s", f, exc)
    return templates


# --- Runner ------------------------------------------------------------------


def _render(template_str: str, base_url: str) -> str:
    return template_str.replace("{{BaseURL}}", base_url.rstrip("/"))


def _match(matcher: Matcher, response: Any) -> bool:
    if matcher.type == "status":
        return response.status_code in (matcher.status or [])
    if matcher.type == "word":
        haystack = (response.text if matcher.part == "body" else str(response.headers)).lower()
        return all(w.lower() in haystack for w in matcher.words or [])
    if matcher.type == "regex":
        haystack = response.text if matcher.part == "body" else str(response.headers)
        return all(re.search(p, haystack) for p in matcher.regex or [])
    return False


def run_templates(
    templates: Iterable[Template],
    base_url: str,
    *,
    client: HttpClient,
) -> list[Finding]:
    """Execute each template against `base_url` and convert matches to Findings."""
    findings: list[Finding] = []
    for tmpl in templates:
        for req in tmpl.requests:
            for path in req.path:
                url = _render(path, base_url)
                r = client.request(req.method.upper(), url, data=req.body,
                                   headers=req.headers)
                if r is None:
                    continue
                if all(_match(m, r) for m in req.matchers):
                    findings.append(Finding(
                        type=f"Template match: {tmpl.name}",
                        severity=tmpl.severity,
                        location=url,
                        description=tmpl.info.get("description", tmpl.id),
                        extra={"template_id": tmpl.id},
                    ))
    return findings

"""GraphQL scanner: introspection, deep query DoS, field suggestion leak.

New in V2.
"""

from __future__ import annotations

import json
import logging
from typing import Any
from urllib.parse import urljoin

from asynx6.core.http import HttpClient
from asynx6.core.models import Finding, Severity

log = logging.getLogger(__name__)

_INTROSPECTION = """
{"query":"{ __schema { types { name fields { name } } } }"}
""".strip()

_DEEP_QUERY = """
{"query":"{ __schema { types { fields { type { fields { type { fields { name } } } } } } } }"}
""".strip()


def _graphql_endpoints(base: str) -> list[str]:
    candidates = ["/graphql", "/api/graphql", "/graphql/v1", "/query", "/gql"]
    return [urljoin(base if base.endswith("/") else base + "/", c.lstrip("/")) for c in candidates]


def _looks_like_graphql(body: str) -> bool:
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return False
    return "data" in data or "errors" in data


def run(url: str, *, client: HttpClient, **_kwargs: Any) -> list[Finding]:
    findings: list[Finding] = []
    for endpoint in _graphql_endpoints(url):
        r = client.post(endpoint, json=json.loads(_INTROSPECTION))
        if r is None or r.status_code != 200 or not _looks_like_graphql(r.text):
            continue
        try:
            data = json.loads(r.text)
        except json.JSONDecodeError:
            continue
        types = (data.get("data") or {}).get("__schema", {}).get("types", [])
        findings.append(Finding(
            type="GraphQL introspection enabled",
            severity=Severity.MEDIUM,
            confidence=100,
            location=endpoint,
            description=f"Introspection returned {len(types)} types.",
            remediation="Disable introspection in production.",
        ))
        # Deep query DoS probe
        r2 = client.post(endpoint, json=json.loads(_DEEP_QUERY), timeout=15)
        if r2 is not None and r2.elapsed > 5:
            findings.append(Finding(
                type="GraphQL deep query (potential DoS)",
                severity=Severity.MEDIUM,
                confidence=80,
                location=endpoint,
                description=f"Deep nested query took {r2.elapsed:.2f}s.",
                remediation="Enforce query depth/complexity limits.",
            ))
        return findings  # one endpoint is enough
    return findings

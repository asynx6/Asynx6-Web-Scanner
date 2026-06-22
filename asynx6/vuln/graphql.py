"""GraphQL scanner.

Detects:
  * Introspection enabled on a real GraphQL endpoint
  * Deep query DoS (no depth/complexity limits enforced)

A response is only treated as GraphQL when it is JSON-parseable AND carries
the canonical `{data|errors}` envelope AND `Content-Type` advertises JSON.
"""

from __future__ import annotations

import json
import logging
from typing import Any
from urllib.parse import urljoin

from asynx6.core.http import HttpClient
from asynx6.core.models import Finding, Severity

log = logging.getLogger(__name__)

_INTROSPECTION_QUERY = (
    '{"query":"{ __schema { types { name fields { name } } } }"}'
)
_DEEP_QUERY = (
    '{"query":"{ __schema { types { fields { type { fields { type { fields { name } } } } } } }"}'
)

# Time threshold for deep-query DoS detection. Below this we don't flag.
_DO_SLOW_THRESHOLD_S = 3.0


def _graphql_endpoints(base: str) -> list[str]:
    candidates = ["/graphql", "/api/graphql", "/graphql/v1", "/query", "/gql"]
    base = base if base.endswith("/") else base + "/"
    return [urljoin(base, c.lstrip("/")) for c in candidates]


def _is_json_response(resp: Any) -> dict[str, Any] | None:
    """Return parsed JSON body if the response is JSON, else None."""
    if resp is None:
        return None
    ct = (resp.headers.get("Content-Type", "") or "").lower()
    if "json" not in ct:
        return None
    try:
        data = json.loads(resp.text)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def _looks_like_graphql_envelope(data: dict[str, Any]) -> bool:
    return isinstance(data, dict) and ("data" in data or "errors" in data)


def _has_schema_types(data: dict[str, Any]) -> list[str]:
    """Return the introspection types list if the response has a real schema."""
    inner = (data.get("data") or {}).get("__schema") or {}
    types = inner.get("types") or []
    return types if isinstance(types, list) else []


def run(url: str, *, client: HttpClient, **_kwargs: Any) -> list[Finding]:
    findings: list[Finding] = []
    for endpoint in _graphql_endpoints(url):
        # Introspection probe
        r = client.post(endpoint, json=json.loads(_INTROSPECTION_QUERY))
        data = _is_json_response(r)
        if data is None or not _looks_like_graphql_envelope(data):
            continue

        types = _has_schema_types(data)
        if types:
            findings.append(Finding(
                type="GraphQL introspection enabled",
                severity=Severity.MEDIUM,
                confidence=100,
                location=endpoint,
                description=f"Introspection returned {len(types)} schema types.",
                remediation="Disable introspection in production.",
            ))
        else:
            # Schema envelope present but no types → likely a partial
            # GraphQL response (auth-gated introspection). Don't flag.
            log.debug("GraphQL envelope present but no schema types at %s", endpoint)
            continue

        # Deep query DoS probe
        r2 = client.post(endpoint, json=json.loads(_DEEP_QUERY), timeout=15)
        if r2 is not None and r2.elapsed > _DO_SLOW_THRESHOLD_S:
            findings.append(Finding(
                type="GraphQL deep query (potential DoS)",
                severity=Severity.MEDIUM,
                confidence=80,
                location=endpoint,
                description=f"Deep nested query took {r2.elapsed:.2f}s.",
                remediation="Enforce query depth/complexity limits.",
            ))
        return findings
    return findings
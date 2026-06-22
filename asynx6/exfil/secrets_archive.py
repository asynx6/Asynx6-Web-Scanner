"""Categorize and archive discovered secrets into a JSON file.

Reads `findings.md` (written by recon.crawler / recon.architect) and produces
`secrets.json` with type/severity/cvss for downstream tooling.
"""

from __future__ import annotations

import json
import logging
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_TYPE_SEVERITY = {
    "AWS Access Key": "CRITICAL",
    "Stripe API Key": "CRITICAL",
    "Google API Key": "HIGH",
    "Auth Token": "HIGH",
    "Database Connection": "CRITICAL",
    "Generic Secret": "MEDIUM",
    "Midtrans Server Key": "CRITICAL",
    "Stripe Secret Key": "CRITICAL",
    "JWT Secret?": "CRITICAL",
    "PHP Config Leak": "HIGH",
    "Firebase URL": "MEDIUM",
    "Slack Webhook": "HIGH",
    "Internal IP Leak": "LOW",
    "High Entropy Secret (Potential Key)": "HIGH",
}


def run(vault_path: Path | str, output_dir: Path | str, **_kwargs: Any) -> dict[str, Any]:
    """Parse `vault_path` (Markdown) and write a categorized JSON to `output_dir`.

    Returns a summary dict: {total, by_type, output_path}.
    """
    vault = Path(vault_path)
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "secrets.json"

    if not vault.is_file():
        log.debug("Findings log %s not found", vault)
        return {"total": 0, "by_type": {}, "output_path": str(out_path)}

    # Markdown table parser: lines starting with `|`
    rows: list[dict[str, str]] = []
    for line in vault.read_text(encoding="utf-8").splitlines():
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) != 4 or cells[0] == "Timestamp":
            continue
        # Skip Markdown separator rows (e.g. `|---|---|---|`)
        if all(set(c) <= {"-"} for c in cells if c):
            continue
        rows.append({
            "timestamp": cells[0],
            "url": cells[1],
            "type": cells[2],
            "value": cells[3].strip("`"),
        })

    by_type: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        row["severity"] = _TYPE_SEVERITY.get(row["type"], "MEDIUM")
        by_type[row["type"]].append(row)

    payload = {
        "total": len(rows),
        "by_type": {k: len(v) for k, v in by_type.items()},
        "items": rows,
    }
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    log.info("Secrets archive: %d items, %d categories -> %s",
             len(rows), len(by_type), out_path)
    return {"total": len(rows), "by_type": payload["by_type"],
            "output_path": str(out_path)}

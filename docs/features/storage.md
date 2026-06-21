# Storage & History

SQLite-backed persistent scan history.

## Where the data lives

Default: `~/.asynx6/history.db`

Override via env var:
```bash
export ASYNX6_DB_PATH=/path/to/my.db
```

## Enable persistence

```bash
python index.py https://example.com --persist
```

Or in `config.yaml`:
```yaml
persist: true
```

## Programmatic access

```python
from asynx6.storage.db import Storage
storage = Storage()

# List recent scans
for scan in storage.list_scans(target="https://example.com", limit=10):
    print(scan.id, scan.target, scan.findings_count)

# Diff two scans
diff = storage.diff_scans(scan_id_old=1, scan_id_new=2)
print(f"New findings: {len(diff.new)}")
print(f"Removed: {len(diff.removed)}")
```

## Schema

```sql
CREATE TABLE scans (
    id INTEGER PRIMARY KEY,
    target TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    aggressive INTEGER,
    findings_count INTEGER,
    subdomains_count INTEGER,
    loot_count INTEGER,
    status TEXT
);

CREATE TABLE findings (
    id INTEGER PRIMARY KEY,
    scan_id INTEGER REFERENCES scans(id),
    type TEXT,
    severity TEXT,
    location TEXT,
    description TEXT,
    confidence INTEGER,
    payload TEXT,
    cvss_score REAL,
    extra_json TEXT
);
```
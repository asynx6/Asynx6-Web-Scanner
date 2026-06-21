# Quickstart

## Single target

```bash
python index.py https://example.com
```

## Aggressive mode

```bash
python index.py https://example.com --aggressive
```

## Multiple targets

Create a `targets.txt` file:
```
https://example.com
https://target2.com
```

Then:
```bash
python index.py targets.txt --aggressive
```

## Scan profiles

```bash
# Quick triage (30s scan, critical vulns only)
python index.py https://example.com --profile quick-triage

# OWASP Top 10 coverage
python index.py https://example.com --profile owasp-top10

# Stealth (slow, low-noise)
python index.py https://example.com --profile stealth

# CI pipeline (SARIF + exit codes)
python index.py https://example.com --profile ci
```

## CI mode

```bash
python -m asynx6.ci https://example.com --format sarif --severity-threshold HIGH
```

Exit codes:
- `0` — clean (or no findings above threshold)
- `1` — findings above threshold
- `2` — scanner error

## Web dashboard

```bash
python index.py https://example.com --serve
# Then open http://127.0.0.1:8080
```

## Indonesian output

```bash
python index.py https://example.com --locale id
```
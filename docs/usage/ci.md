# CI/CD Integration

Asynx6 V3 ships with a dedicated CI mode designed for pipelines.

## Quick start (GitHub Actions)

```yaml
name: Asynx6 Security Scan
on: [push, pull_request]

jobs:
  asynx6:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install -e ".[dev]"
      - name: Run Asynx6 scan
        run: |
          python -m asynx6.ci https://staging.example.com \
            --format sarif \
            --output results.sarif \
            --severity-threshold HIGH
      - name: Upload SARIF to GitHub Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Clean (no findings at/above threshold) |
| `1` | Findings present at/above threshold |
| `2` | Scanner error |

## Baseline comparison

Save a baseline after the first clean run, then fail only on NEW findings:

```bash
# First scan — save baseline
python -m asynx6.ci https://target.com \
  --output-baseline baseline.json \
  --severity-threshold MEDIUM

# Subsequent scans — fail only on new findings
python -m asynx6.ci https://target.com \
  --baseline baseline.json \
  --output-baseline baseline.json \
  --fail-on-new-only
```

## GitLab CI

```yaml
asynx6_scan:
  script:
    - pip install -e ".[dev]"
    - python -m asynx6.ci "$CI_ENVIRONMENT_URL" --format sarif --output gl-sast-report.json
  artifacts:
    when: always
    reports:
      sast: gl-sast-report.json
```
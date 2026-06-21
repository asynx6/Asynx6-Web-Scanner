# CLI Reference

```
python index.py [TARGET] [OPTIONS]
```

| Flag | Description |
|---|---|
| `TARGET` | URL or path to .txt list of targets |
| `-a`, `--aggressive` | Enable aggressive fuzzing & discovery |
| `--tui` | Launch interactive Textual dashboard |
| `--threads N` | Worker threads (default 25) |
| `--timeout SECONDS` | HTTP timeout (default 10) |
| `--output-dir PATH` | Results directory (default ./results) |
| `--format FMT` | `markdown` \| `json` \| `sarif` \| `html` \| `all` |
| `--config PATH` | YAML config file |
| `--no-banner` | Suppress ASCII banner |
| `--locale en\|id` | Output language |
| `--profile NAME` | `quick-triage` \| `owasp-top10` \| `deep` \| `stealth` \| `ci` |
| `--serve` | Launch web dashboard after scan |
| `--persist` | Save scan history to SQLite |
| `--ml-filter` | Apply ML false-positive filter |

## Examples

```bash
# Basic scan
python index.py https://example.com

# Aggressive + JSON output
python index.py https://example.com -a --format json

# Batch + persist
python index.py targets.txt --persist

# Quick triage profile
python index.py https://example.com --profile quick-triage

# Indonesian + web dashboard
python index.py https://example.com --locale id --serve
```
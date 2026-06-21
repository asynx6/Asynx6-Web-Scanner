# Reporting Modules

| Format | Output |
|---|---|
| `markdown` | `BUG_BOUNTY_POC.md` with severity icons |
| `json` | Flat JSON dump of all findings |
| `sarif` | SARIF 2.1.0 (GitHub Code Scanning compatible) |
| `html` | Self-contained HTML with Chart.js inline |
| `all` | Generates all four formats at once |

## CVSS v3.1

Each finding is scored per CVSS v3.1 spec. Use `asynx6.reporting.cvss.score()`
directly for custom integrations:

```python
from asynx6.reporting.cvss import CvssVector, score
v = CvssVector(AV="N", AC="L", PR="N", UI="N", C="H", I="H", A="H")
print(score(v))  # 9.8
```
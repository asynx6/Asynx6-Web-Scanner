# Scan Profiles

Profiles are preset configurations for common workflows. Use them with
`--profile <name>`.

## Available profiles

| Profile | Threads | Jitter | Phases |
|---|---|---|---|
| `quick-triage` | 20 | 0.1-0.5 | subdomain, network, sqli, lfi, jwt |
| `owasp-top10` | 15 | 0.5-2.0 | all OWASP-relevant modules |
| `deep` | 10 | 1.0-3.0 | everything, slow + aggressive |
| `stealth` | 2 | 5.0-15.0 | minimal probes, slow rate |
| `ci` | 20 | 0.1-0.5 | critical vulns only, SARIF output |

## Choosing a profile

- **First-look recon?** → `quick-triage`
- **Bug bounty / full audit?** → `deep`
- **Avoiding WAF / IDS?** → `stealth`
- **CI pipeline gating?** → `ci`
- **OWASP compliance audit?** → `owasp-top10`

## Custom profiles

Add custom profiles by importing `asynx6.profiles` and registering:

```python
from asynx6.profiles import _REGISTRY, Profile
from asynx6.core.config import ScannerConfig

_REGISTRY["custom"] = Profile(
    name="custom",
    description="My custom profile",
    config=ScannerConfig(threads=15, aggressive=True),
    enabled_phases=["chameleon", "subdomain", "vuln_sqli"],
)
```

Then use with `python index.py https://x.test --profile custom` after
registering it in your own plugin.
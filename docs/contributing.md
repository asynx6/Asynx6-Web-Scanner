# Contributing

## Setup

```bash
git clone https://github.com/asynx6/Asynx6-Web-Scanner.git
cd Asynx6-Web-Scanner
pip install -e ".[dev]"
playwright install chromium
pytest
```

## Code style

- `ruff check .` — lint
- `ruff format .` — format
- `mypy asynx6` — type check
- `pytest` — test (≥70% coverage required)

## Adding a new vulnerability module

1. Create `asynx6/vuln/my_module.py`:

```python
from asynx6.core.http import HttpClient
from asynx6.core.models import Finding, Severity

def run(url: str, *, client: HttpClient, **_kwargs):
    findings = []
    # ... your logic ...
    return findings
```

2. Add to `asynx6/vuln/__init__.py`
3. Add a phase in `asynx6/engine/orchestrator.py`
4. Write tests in `tests/unit/test_vuln_my_module.py`
5. Document in `docs/modules/vuln.md`

## Adding a new notifier

1. Create `asynx6/notifications/mychat.py`:

```python
from asynx6.notifications.base import Notifier, _post_json

class MyChatNotifier(Notifier):
    def send(self, notification):
        return _post_json(self.config["url"], {"text": notification.message})
```

2. Add to `asynx6/notifications/__init__.py` and the orchestrator's registry
3. Write tests using `responses` mock library

## Commit messages

Use conventional commits:
- `feat: add SSRF collaborator client`
- `fix: handle empty baseline file in CI diff`
- `docs: update CI integration guide`
- `test: add WebSocket CSWSH detection test`

## Pull requests

- Keep changes focused
- Add tests for new features
- Update docs
- Pass all CI checks (ruff + mypy + pytest)
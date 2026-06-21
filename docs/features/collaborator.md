# SSRF Collaborator

The collaborator server enables **out-of-band SSRF detection**: instead of
guessing whether the target made a request based on timing, you give it a
unique URL on a server you control. If the target fetches it, the
collaborator records the interaction.

## Setup

### 1. Deploy the collaborator

```bash
python -c "from asynx6.collaborator import CollaboratorServer; \
  CollaboratorServer(host='0.0.0.0', port=8089).start()"
```

Run behind a public domain (e.g. `collab.yourdomain.com`) with a wildcard
DNS record pointing to your server.

### 2. Configure Asynx6

In `config.yaml`:
```yaml
collaborator_domain: collab.yourdomain.com
```

### 3. Scan

```bash
python index.py https://target.com --profile deep
```

The SSRF scanner will inject `<token>.collab.yourdomain.com` payloads into
suspected SSRF parameters. When the target fetches the URL, the collaborator
records the interaction and the scanner confirms SSRF with high confidence.

## Architecture

```
Target (vulnerable) ── HTTP ──▶ Collaborator (your server)
                              ▲
                              │ token=abc123.collab.yourdomain.com
Asynx6 scanner  ───────────────┘  polls for hits
```
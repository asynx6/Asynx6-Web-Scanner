# Notifications

Send CRITICAL findings to Slack, Discord, Telegram, or any webhook.

## Configuration

In `config.yaml`:
```yaml
notifiers:
  - kind: slack
    webhook_url: https://hooks.slack.com/services/YOUR/WEBHOOK
    channel: "#security"
  - kind: discord
    webhook_url: https://discord.com/api/webhooks/YOUR/WEBHOOK
  - kind: telegram
    bot_token: "123456:ABCDEF"
    chat_id: -1001234567890
  - kind: webhook
    url: https://your-app.example.com/hook
```

## What gets sent

Only CRITICAL findings trigger notifications. Each notification includes:
- Title with target URL and finding count
- Top finding type + location
- Severity indicator (colored)
- Optional link to full report

## Custom notifier

Add your own by implementing the `Notifier` base class:

```python
from asynx6.notifications.base import Notifier, Notification

class PagerDutyNotifier(Notifier):
    def send(self, n: Notification) -> bool:
        # POST to PagerDuty Events API
        ...
```

Register it in your config or submit a PR upstream.
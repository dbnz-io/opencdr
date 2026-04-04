# Notifications

Configure channels and routing in the settings table via the CLI or the API.

## Settings Example

```json
{
  "setting_id": "global",
  "notifications_enabled": true,
  "channels": {
    "discord": {
      "enabled": true,
      "webhook_url": "https://discord.com/api/webhooks/YOUR_WEBHOOK"
    },
    "slack": {
      "enabled": false,
      "webhook_url": ""
    },
    "email": {
      "enabled": false,
      "topic_arn": "arn:aws:sns:us-east-1:123456789012:opencdr-dev-alerts"
    }
  },
  "routing": {
    "severity_overrides": {
      "CRITICAL": ["discord", "slack", "email"],
      "HIGH": ["discord"],
      "MEDIUM": []
    }
  }
}
```

Routing is per-severity. If no routing entry matches, all enabled channels receive the alert.

## Configure via CLI

```bash
# Slack
python3 scripts/opencdr.py settings set --slack-webhook https://hooks.slack.com/...

# Discord
python3 scripts/opencdr.py settings set --discord-webhook https://discord.com/api/webhooks/...

# Email (SNS topic ARN)
python3 scripts/opencdr.py settings set --email-topic-arn arn:aws:sns:<region>:<account>:opencdr-dev-alerts

# Full settings payload
python3 scripts/opencdr.py settings set --file support_files/settings/settings.json
```

## Email via SNS

Email notifications go through the `opencdr-<stage>-alerts` SNS topic created by the stack.

**Get the topic ARN:**

```bash
aws sns list-topics \
  --query "Topics[?contains(TopicArn, 'opencdr') && contains(TopicArn, 'alerts')]" \
  --output text
```

**Subscribe an email address:**

```bash
aws sns subscribe \
  --topic-arn arn:aws:sns:<region>:<account-id>:opencdr-<stage>-alerts \
  --protocol email \
  --notification-endpoint you@example.com
```

AWS will send a confirmation email — click the link to activate before alerts are delivered.

Alternatively, pass `--param="alertEmail=you@example.com"` at deploy time to create the subscription automatically.

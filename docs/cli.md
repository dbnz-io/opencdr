# CLI Reference

`scripts/opencdr.py` is a management CLI for interacting with a deployed OpenCDR stack.

## Setup

```bash
# Interactive setup wizard — configures API connection, loads rules, and sets up notifications
python3 scripts/opencdr.py setup

# Or configure manually
python3 scripts/opencdr.py config set \
  --url https://<api-id>.execute-api.<region>.amazonaws.com/dev \
  --key <api-key>
```

Your API URL and key are printed by `serverless deploy` in the endpoints and API Keys sections.

## Commands

### Status

```bash
python3 scripts/opencdr.py status
```

### Rules

```bash
# Load all rules from support_files/
python3 scripts/opencdr.py rules load

# List rules
python3 scripts/opencdr.py rules list --kind signal
python3 scripts/opencdr.py rules list --kind correlation

# Get a rule
python3 scripts/opencdr.py rules get <rule_id> --kind signal

# Delete a rule
python3 scripts/opencdr.py rules delete <rule_id> --kind signal
```

### Settings

```bash
# View current settings
python3 scripts/opencdr.py settings get

# Set notification channels
python3 scripts/opencdr.py settings set --slack-webhook https://hooks.slack.com/...
python3 scripts/opencdr.py settings set --discord-webhook https://discord.com/api/webhooks/...
python3 scripts/opencdr.py settings set --email-topic-arn arn:aws:sns:<region>:<account>:opencdr-dev-alerts

# Load full settings payload from file
python3 scripts/opencdr.py settings set --file support_files/settings/settings.json
```

### Signals & Logs

```bash
python3 scripts/opencdr.py signals list --severity HIGH
python3 scripts/opencdr.py logs list --service OCDR-PROCESSOR
```

### Testing

```bash
# Test rules locally (no AWS needed)
python3 scripts/opencdr.py test local

# Test against a deployed stack
python3 scripts/opencdr.py test deployed --stage dev
```

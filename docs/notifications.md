# Notifications

*How alerts reach you: channels, per-severity routing, and how channel secrets are stored.*

## Channels

Six channels exist (`_VALID_CHANNELS` in `src/handlers/notifier.py`): `slack`, `discord`, `email`, `securityhub`, `jira`, `webhook`. Configure them in the settings document — via the CLI, the interactive setup wizard, or directly through the API.

```bash
# Interactive setup wizard
python3 scripts/opencdr.py setup

# Or one channel at a time
python3 scripts/opencdr.py settings set --slack-webhook https://hooks.slack.com/services/EXAMPLE/EXAMPLE/EXAMPLE
```

### Slack and Discord

Generate an incoming webhook URL in the Slack app or Discord server settings; the webhook URL is the sole authentication mechanism for both, so treat it as a secret (it's stored accordingly — see below).

```bash
python3 scripts/opencdr.py settings set --slack-webhook <url>
python3 scripts/opencdr.py settings set --discord-webhook <url>
```

### Email (via SNS)

Delivered through the `opencdr-<stage>-alerts` SNS topic — the same topic the API's `/settings` `email.topic_arn` field points at. Subscribe an address either at deploy time (`--param="alertEmail=you@example.com"`) or after the fact:

```bash
aws sns subscribe \
  --topic-arn arn:aws:sns:<region>:<account-id>:opencdr-<stage>-alerts \
  --protocol email \
  --notification-endpoint you@example.com
```

AWS sends a confirmation email — the subscription isn't active until that link is clicked. Then enable the channel:

```bash
python3 scripts/opencdr.py settings set \
  --email-topic-arn arn:aws:sns:<region>:<account-id>:opencdr-<stage>-alerts
```

This is the same `AlertsSnsTopic` used for security detections specifically — distinct from `AlarmsSnsTopic`, which is infra/ops health alarms, not security alerts. See [Observability](observability.md) for that topic.

### AWS Security Hub

Pushes findings in [ASFF format](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html). Requires Security Hub to already be enabled in the account/region (`aws securityhub describe-hub` to check). No further configuration — `notifier` derives the product ARN from its own execution context at runtime.

```bash
python3 scripts/opencdr.py settings set --enable-securityhub
```

### Jira

Creates issues via the [Jira REST API v3](https://developer.atlassian.com/cloud/jira/platform/rest/v3/), ADF-formatted, with severity mapped to Jira priority (`CRITICAL`→Highest, `HIGH`→High, `MEDIUM`→Medium, `LOW`→Low, `INFORMATIONAL`→Lowest) and an `opencdr` label.

```bash
python3 scripts/opencdr.py settings set \
  --jira-url https://yourco.atlassian.net \
  --jira-project SEC \
  --jira-email soc@yourco.com \
  --jira-token <api-token>
```

All four flags are required together. Generate the token at [id.atlassian.com/manage-profile/security/api-tokens](https://id.atlassian.com/manage-profile/security/api-tokens).

### Custom webhook

POSTs the raw OpenCDR alert JSON to one or more named HTTPS targets, each with its own optional headers — covers anything that accepts a generic webhook (PagerDuty, OpsGenie, Teams, a SIEM's HTTP ingest, ...) without a dedicated first-party integration. Each target is attempted independently: one target failing doesn't stop the others, and sent/failed counts reflect individual results.

```bash
python3 scripts/opencdr.py settings set \
  --webhook-url https://api.example.com/alerts \
  --webhook-name my-siem \
  --webhook-header "Authorization=Bearer <token>"
```

The payload is the raw OpenCDR alert object — most platforms expect their own shape (PagerDuty wants `routing_key`/`event_action`, Splunk HEC wants a `{"event": ...}` wrapper, etc.). If you need payload transformation, either front the target with a small reshaping Lambda, or use the SNS fan-out pattern below.

### SNS fan-out (for anything the built-in channels don't cover)

OpenCDR publishes every alert to the `opencdr-<stage>-alerts` SNS topic regardless of which channels are enabled. Subscribing your own Lambda to it gets you the full alert payload with no changes to OpenCDR itself — the mechanism the built-in Datadog/Splunk/Sentinel/Elastic/QRadar/Sumo Logic integration patterns in [SIEM Integrations](siem-integrations.md) are all built on. Use this for conditional routing, multi-step workflows, or a destination with an auth flow the webhook channel can't express (OAuth, signed requests, etc.).

## Remediation success notifications

A distinct notification type from everything above: when [an automated response action succeeds](incident-response.md#remediation-notifications), `responder` queues a second, notifications-only item (`type: remediation_success`) separate from the alert that triggered it, so a successful remediation is as visible as the detection was — not just a CloudWatch log line.

`notifier` routes it to green-styled builders on Slack and Discord, and a plain-text email via SNS — distinct from the severity-colored alert builders every other notification above uses. **Not supported yet on Security Hub, Jira, or the custom webhook channel**: those builders expect the full alert shape (severity, primary signal, playbook), which a remediation-success item doesn't have, so they're explicitly skipped for this type rather than fed something they'd mishandle.

Routing still applies (the item carries the triggering detection's severity, defaulting to `UNKNOWN` if none), but there's no separate settings toggle for this notification type today — if a channel is enabled and selected by routing, it receives both alerts and remediation-success notifications.

## Per-severity routing

```json
"routing": {
  "CRITICAL": ["slack", "email", "jira"],
  "HIGH": ["slack", "securityhub"],
  "MEDIUM": ["discord"],
  "LOW": ["webhook"]
}
```

If no routing entry matches a given severity, every enabled channel with sufficient configuration receives the alert. A full example settings document is in `support_files/settings/settings.json`.

## Channel isolation

One channel failing doesn't affect the others in the same alert delivery — a Slack outage doesn't block Discord, email, Jira, or webhook delivery for that same event. `notifier` is also the most thoroughly tested file in the codebase (20–35 tests per channel, including partial-failure and malformed-response paths), if you're looking for the reference example of how a channel is expected to behave under failure.

## How channel secrets are stored

Every secret-shaped field — Slack/Discord webhook URLs, the Jira API token, and every custom webhook target's header values — is transparently externalized to SSM Parameter Store (as a `SecureString`) the moment you write it through the API or CLI. DynamoDB only ever holds an `ssm:`-prefixed reference, never the real value; `notifier` resolves the reference back to the real value at send time. `GET /settings` masks these fields to `***REDACTED***` regardless — there's no way to read a secret back out through the API once set. Full detail in [Security](security.md#secrets-management).

## Related pages

- [API Reference](api-reference.md#settings) — the `/settings` endpoints
- [Security](security.md) — secrets handling in full
- [Architecture](architecture.md) — where `notifier` sits in the pipeline
- [Incident Response](incident-response.md#remediation-notifications) — what triggers a remediation-success notification
- [SIEM Integrations](siem-integrations.md) — Datadog, Splunk, Sentinel, and other SIEM walkthroughs

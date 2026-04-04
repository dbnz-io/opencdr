# Deployment

## Deploy

```bash
# Deploy to dev (default)
serverless deploy

# Deploy to a specific stage / region
serverless deploy --stage prod --region us-west-2

# Deploy with email subscriptions
serverless deploy \
  --param="alarmEmail=ops@example.com" \
  --param="alertEmail=security@example.com"
```

`alarmEmail` subscribes to infrastructure alerts (Lambda errors, DLQ depth). `alertEmail` subscribes to security detection alerts. Both are optional — you can subscribe later via the SNS topic ARNs.

## What Gets Provisioned

- 6 Lambda functions (each with its own least-privilege IAM role)
- 6 DynamoDB tables (signals, alerts, outbox, logs, detection-rules, settings)
- 2 SQS queues with dead-letter queues (notifications, responses)
- 1 stream failure queue (catches poison-pill records from DynamoDB streams)
- API Gateway with API key auth (10k requests/month, 100 RPS)
- 2 SNS topics: infrastructure alarms (`opencdr-<stage>-alarms`) and security alerts (`opencdr-<stage>-alerts`)
- 12 CloudWatch alarms

## CloudWatch Alarms

| Alarm | Metric | Threshold |
|---|---|---|
| `processor/alerter/publisher/notifier/responder/api` errors | `AWS/Lambda Errors` | > 0 |
| Notifications DLQ depth | `AWS/SQS ApproximateNumberOfMessagesVisible` | > 0 |
| Responses DLQ depth | `AWS/SQS ApproximateNumberOfMessagesVisible` | > 0 |
| Stream failure queue depth | `AWS/SQS ApproximateNumberOfMessagesVisible` | > 0 |
| Alerter stream iterator age | `AWS/Lambda IteratorAge` | > 5 min |
| Publisher stream iterator age | `AWS/Lambda IteratorAge` | > 5 min |

Pass `--param="alarmEmail=you@example.com"` at deploy time to subscribe automatically.

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `OPENCDR_IR_ROLE_ARN` | *(empty)* | IAM role ARN to assume for cross-account IR actions |
| `DREDGE_DRY_RUN` | `false` | Set to `true` to simulate IR actions without executing them |
| `CORRELATION_QUERY_LIMIT` | `300` | Max signals queried per correlation evaluation |

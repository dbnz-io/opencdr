# Observability

*What you get automatically when you deploy OpenCDR, and the two optional one-time steps for getting alarm notifications delivered somewhere.*

This is about the health of OpenCDR's own pipeline — is `processor` erroring, is a queue backing up, is detection actually happening — not about security detections themselves. For that, see [Notifications](notifications.md).

## Automatic, zero configuration

Every `serverless deploy` provisions all of the following. There is nothing to turn on.

### CloudWatch Dashboard

One dashboard per stage, named `opencdr-<stage>-ops`. Fastest way to find it: the stack's `DashboardUrl` CloudFormation output, printed at the end of every deploy (or `aws cloudformation describe-stacks --stack-name opencdr-<stage> --query "Stacks[0].Outputs"`). It has five widgets: Lambda errors across all 9 functions, Lambda p99 duration, Lambda invocations, depth across all four queues (`notifications-dlq`, `responses-dlq`, `stream-failures` — the last one now also catches `archiver`'s own stream-processing failures, see [`data-archival.md`](data-archival.md) — and `signals-write-dlq`), and the five custom metrics below via CloudWatch `SEARCH` expressions (needed because their dimensions — `rule_id`, `destination`, etc. — aren't knowable at template-write time).

### Custom metrics

Emitted via CloudWatch Embedded Metric Format (EMF, `src/infra/metrics.py`) under the `OpenCDR` namespace — chosen over an OTel-based pipeline specifically because it needs zero additional infrastructure or IAM beyond the log-write permission every Lambda already has.

| Metric | Dimensions | Emitted by | Tells you |
|---|---|---|---|
| `SignalsCreated` | `rule_id`, `severity` | `processor`, after a signal is newly inserted (not on every match — a duplicate detection doesn't inflate this) | Whether detection is actually producing output, broken down by rule |
| `CorrelationMatches` | `rule_id` | `alerter` | Whether correlation rules are firing |
| `PublishSuccess` | `destination` | `publisher` | Outbox → SQS delivery is working, per destination queue |
| `PublishFailure` | `destination` | `publisher` | Outbox → SQS delivery is failing, per destination queue |
| `ResponderActionsExecuted` | `response_module`, `result` | `responder` | Whether automated IR actions are succeeding or failing, per module |

This is the layer that answers the question Lambda's own built-in metrics can't: a Lambda reporting 0 errors tells you nothing about whether a rule silently stopped matching. `SignalsCreated` dropping to zero while error counts stay flat is exactly that failure mode.

### X-Ray tracing

`provider.tracing: {lambda: true, apiGateway: true}` in `serverless.yml` — every invocation across all 9 Lambdas and every API Gateway request is traced, viewable in the X-Ray console for the deployed account.

That setting alone only traces the *invocation boundary* — it doesn't instrument what a handler's code does internally, so without more, the service map would show Lambda nodes but never DynamoDB or SQS. Closed with a small amount of application code after all: `src/infra/xray_setup.py` calls `aws_xray_sdk`'s `patch(["boto3"])` (AWS's own SDK, deliberately narrower than `patch_all()` — this codebase doesn't use `requests`/sqlite3/mysql for anything that needs tracing) once per handler at cold start, so every DynamoDB/SQS/SNS call shows up as its own node too. Worth being explicit that this walks back the "zero application code" framing this page used to have — but it's a different risk than the OTel instrumentor bug described below: that library wrapped Lambda invocation and API Gateway event parsing and crashed before the handler ever ran, where this only wraps outgoing `boto3` calls and never touches event handling.

## Alarms exist automatically — delivery is the one-time step

16 CloudWatch Alarms are created on every deploy: one per-function `AWS/Lambda` Errors alarm for 8 of the 9 functions (`processor`, `signalWriter`, `alerter`, `publisher`, `notifier`, `responder`, `api`, `archiver` — `alarmNotifier` itself doesn't have one), four SQS DLQ/queue-depth alarms (`notifications-dlq`, `responses-dlq`, `stream-failures`, `signals-write-dlq`), three DynamoDB-stream `IteratorAge` alarms (`alerter`, `publisher`, `archiver` — the last one covers all three of `archiver`'s own streams, not individually attributed, since `AWS/Lambda IteratorAge` is dimensioned by function name only), and one DynamoDB `ThrottledRequests` alarm on `logs-table-v2` (the tripwire for whether that table's day-bucketed partition key alone is holding up under load, without the SQS write-buffer `signals-table-v2` has — see [Architecture](architecture.md#dynamodb-tables)). All of them fire into `AlarmsSnsTopic` (`opencdr-<stage>-alarms`) — but a topic with no subscription doesn't notify anyone. Two ways to fix that, both zero application code:

### Option 1 — email (fastest, no Lambda involved)

```bash
serverless deploy --stage dev --param="alarmEmail=ops@example.com"
```

This subscribes that address directly to `AlarmsSnsTopic` via a CloudFormation-conditional resource (`AlarmsEmailSubscription`, gated on `HasAlarmEmail`) — no code runs in the delivery path at all. AWS sends a confirmation email; click it once to activate. You can also subscribe after the fact without redeploying:

```bash
aws sns subscribe --topic-arn <AlarmsTopicArn output> --protocol email --notification-endpoint ops@example.com
```

### Option 2 — Slack (nicer formatting, via the alarmNotifier Lambda)

A generic `alarmNotifier` Lambda is already deployed, subscribed to `AlarmsSnsTopic`, and does nothing until you give it a webhook. Set one SSM parameter, post-deploy, per stage:

```bash
aws ssm put-parameter \
  --name /opencdr-dev/ops-alerts/slack-webhook \
  --type SecureString \
  --value "https://hooks.slack.com/services/EXAMPLE/EXAMPLE/EXAMPLE"
```

`alarmNotifier` reads this parameter (with a short TTL cache, same pattern the notifier settings cache uses) and formats each alarm state-change (🔴 `ALARM` / ✅ `OK`, name, description, reason) as a Slack message. If the parameter isn't set, the Lambda has nothing to read and simply has no effect — it doesn't need to be disabled or removed, it's inert by default.

Nothing here is client-specific in code — every stage gets its own SSM parameter at that same path, so a second deployment (a different client, a different AWS account) sets their own value at their own path without touching anything else.

### The monthly cost budget reuses this same path

`CostBudget` (an `AWS::Budgets::Budget`, scoped to this stack's own tagged spend, not the whole account) alerts at 80%/100% actual and 100% forecasted spend into the same `AlarmsSnsTopic` above — so once alarm delivery is set up (email or Slack), cost alerts arrive the same way with no separate configuration. Pass `--param="monthlyBudgetUsd=<amount>"` at deploy time to set the threshold (default `50`).

## Cost tracking

Every resource this stack creates is tagged `Project=opencdr` / `Stage=<stage>` — that tagging is what scopes `CostBudget` above to just this stack's spend instead of the whole account.

Two one-time steps in the AWS account are required before any of this reports real numbers — neither is something CloudFormation can do for you:

1. Enable Cost Explorer once (Billing console → Cost Explorer).
2. Activate the `Project`/`Stage` tags as cost allocation tags (Billing console → Cost allocation tags) — takes up to 24h to start appearing, and only covers spend from activation forward, not retroactively.

Once both are done, get a spend breakdown for a stage with:

```bash
./scripts/cost_report.sh --stage dev
./scripts/cost_report.sh --stage prod --granularity MONTHLY --start 2026-07-01 --end 2026-08-01
```

## Portability — the honest tradeoff

This entire layer — X-Ray, EMF metrics, CloudWatch Alarms and Dashboard — is AWS-native, not portable to a non-AWS observability backend. That was a deliberate choice, not an oversight: an earlier attempt at a vendor-agnostic OTLP pipeline (configurable exporter destination, no vendor SDK) worked for its intended scope but hit a real bug in a third-party Lambda instrumentation library that broke the `api` Lambda in production. Given the choice between debugging that library and shipping something AWS-native that works reliably today, AWS-native won. If you're deploying into a client's account who already runs their own observability stack, everything on this page still surfaces in *their* CloudWatch/X-Ray — it's not locked to a separate dbnz-owned backend — but it won't forward into Datadog/Grafana/Splunk/etc. without you building that forwarding yourself (see [Notifications](notifications.md#sns-fan-out-for-anything-the-built-in-channels-dont-cover) for the same SNS fan-out pattern applied to security alerts, which generalizes to this too).

## Related pages

- [Architecture](architecture.md) — the pipeline these metrics/alarms describe
- [Notifications](notifications.md) — the separate, security-alert delivery pipeline (`AlertsSnsTopic`, not `AlarmsSnsTopic`)
- [Deployment](deployment.md) — where `alarmEmail` and `monthlyBudgetUsd` fit into the deploy flow

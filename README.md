# OpenCDR.

[![CI](https://github.com/dbnz-io/opencdr/actions/workflows/ci.yml/badge.svg)](https://github.com/dbnz-io/opencdr/actions/workflows/ci.yml)
![Coverage](coverage-badge.svg)
[![License: MPL 2.0](https://img.shields.io/badge/License-MPL_2.0-brightgreen.svg)](https://opensource.org/licenses/MPL-2.0)

Open-source Cloud Detection & Response for AWS. OpenCDR ingests CloudTrail and GuardDuty events, runs them through a configurable detection and correlation engine, and delivers alerts to Slack, Discord, Email, AWS Security Hub, Jira, or any custom HTTPS webhook — with optional automated incident response.

📚 This README is the fast-start overview and copy-paste command reference. For the deep-reference documentation — architecture, security model, and a "find what you need" index — see **[`docs/`](docs/README.md)**.

---

## Table of Contents

- [How It Works](#how-it-works)
- [Architecture](#architecture)
- [Complete Setup](#complete-setup)
- [Prerequisites](#prerequisites)
  - [CloudTrail must be enabled](#cloudtrail-must-be-enabled)
  - [Organization-level deployment](#organization-level-deployment)
  - [Install dependencies](#install-dependencies)
- [Deployment](#deployment)
  - [CloudWatch Alarms](#cloudwatch-alarms)
  - [Observability](#observability)
  - [Cost tracking](#cost-tracking)
  - [Multi-region coverage](#multi-region-coverage)
  - [Environment variables](#environment-variables)
  - [CI/CD deployment (OIDC, no long-lived keys)](#cicd-deployment-oidc-no-long-lived-keys)
- [OpenCDR CLI](#opencdr-cli)
  - [Quick start](#quick-start)
  - [Commands](#commands)
- [Batteries Included — Detection Rules](#batteries-included--detection-rules)
  - [Signal rules](#signal-rules)
  - [Correlation rules](#correlation-rules)
- [Testing Rules Locally](#testing-rules-locally)
  - [Integration testing (deployed stack)](#integration-testing-deployed-stack)
- [Writing Detection Rules](#writing-detection-rules)
  - [Signal rule](#signal-rule)
  - [Correlation rule](#correlation-rule)
- [Automated Incident Response](#automated-incident-response)
  - [How the responder authorizes itself](#how-the-responder-authorizes-itself)
- [Notifications](#notifications)
  - [Slack and Discord](#slack-and-discord)
  - [Email notifications via SNS](#email-notifications-via-sns)
  - [AWS Security Hub](#aws-security-hub)
  - [Jira](#jira)
  - [Custom webhook](#custom-webhook)
  - [Custom integrations via SNS](#custom-integrations-via-sns)
- [SIEM Integrations](#siem-integrations)
- [API](#api)
- [Project Structure](#project-structure)
- [Running Tests](#running-tests)
- [License](#license)

---

## How It Works

```
EventBridge (CloudTrail / GuardDuty)
  └─► processor      — normalizes events, runs detection rules → writes signals
        └─► alerter  — runs correlation rules → writes alerts + outbox
              └─► publisher  — drains outbox → SQS
                    ├─► notifier   — sends alerts to Slack / Discord / Email / Security Hub / Jira / custom webhook
                    └─► responder  — executes automated IR actions (disable user, isolate EC2, block S3…)
```

A REST API lets you query signals, logs, and rules, and manage configuration at runtime.

---

## Architecture

| Component | Trigger | Responsibility |
|---|---|---|
| **processor** | EventBridge rule | Parse event → normalize → run signal detection → store signals |
| **alerter** | DynamoDB stream (signals) | Run correlation rules → store alerts → write outbox |
| **publisher** | DynamoDB stream (outbox) | Claim outbox records → publish to SQS queues |
| **notifier** | SQS (notifications) | Format and deliver alerts to Slack / Discord / Email (SNS) / Security Hub / Jira / custom webhook |
| **responder** | SQS (responses) | Execute incident response actions via IAM / EC2 / S3 |
| **api** | API Gateway (HTTP) | Query signals, logs, rules; manage settings |

All state lives in DynamoDB (pay-per-request). The outbox pattern guarantees at-least-once delivery from alerter to SQS without direct coupling.

---

## Complete Setup

The sections below cover each step in depth. In order, going from a clean AWS account to a fully working deployment:

1. **Prerequisites** — Node.js, Serverless Framework, Python 3.12, AWS credentials, CloudTrail enabled.
2. **Deploy the stack** — `serverless deploy --stage dev`.
3. **Load the bundled detection rules** — `./scripts/load_rules.sh --stage dev`.
4. **Configure a notification channel** — `python3 scripts/opencdr.py setup` (interactive; also does step 3).
5. **Set up alarm delivery** — operational health, not security alerts; `alarmEmail` param or a Slack SSM parameter.
6. **Enable cost tracking** — two manual AWS-console steps, then `./scripts/cost_report.sh`.
7. **Onboard additional regions** — only if your account operates in more than one; otherwise it's silently blind outside the deployment region. `./scripts/setup_region_forwarding.sh`.
8. **Onboard additional accounts** — only if you need cross-account incident response; single-account needs nothing here. Create the same-named IR role in the other account, then register it: `curl -X POST "$OPENCDR_API_URL/ir-roles" -H "x-api-key: $OPENCDR_API_KEY" -d '{"aws_account_id": "<id>", "role_arn": "<arn>"}'` — full walkthrough (trust policy, kill-switch) in [`docs/ir-role.md`](docs/ir-role.md#multi-account-onboard-each-additional-account).
9. **Set up CI/CD** — optional, recommended beyond a one-off evaluation. One-time bootstrap in [`ci-bootstrap/`](ci-bootstrap/README.md), then every push to `main` deploys automatically.
10. **Verify end to end** — `./scripts/test_deployed.sh`.

Steps 7–9 are opt-in and skippable for a single-account, single-region evaluation. Full detail, exact commands, and what each step is actually doing: **[`docs/setup.md`](docs/setup.md)**.

---

## Prerequisites

- [Node.js](https://nodejs.org/) >= 18 (CI itself runs Node 20)
- [Serverless Framework](https://www.serverless.com/) v3
- Python 3.12 (matches `provider.runtime` in `serverless.yml`)
- AWS credentials configured (`aws configure` or environment variables)
- `jq` (for the load/test scripts)

### CloudTrail must be enabled

OpenCDR receives events via EventBridge. CloudTrail management events are only delivered to EventBridge when CloudTrail is active in your account and region.

Enable it before deploying:

```bash
# Create a trail (one-time setup)
aws cloudtrail create-trail \
  --name opencdr-trail \
  --s3-bucket-name <your-log-bucket> \
  --is-multi-region-trail

# Start logging
aws cloudtrail start-logging --name opencdr-trail
```

Or enable it in the AWS Console under **CloudTrail → Trails → Create trail**. Management events (read + write) must be enabled — data events are optional.

> Without CloudTrail enabled, the processor Lambda will never receive events and no signals will be generated.

### Organization-level deployment

For multi-account AWS Organizations setups, you can route all CloudTrail and GuardDuty events from every member account into a single central EventBridge bus and deploy OpenCDR once in a dedicated security account.

```
Member Account A  ─┐
Member Account B  ─┼─► EventBridge cross-account rules ─► Central Security Account
Member Account C  ─┘                                         EventBridge default bus
                                                                      │
                                                             OpenCDR processor Lambda
```

**Setup steps:**

1. **Enable an organization trail** in the management account — this creates a CloudTrail that covers all member accounts automatically:

   ```bash
   aws cloudtrail create-trail \
     --name org-trail \
     --s3-bucket-name <your-log-bucket> \
     --is-organization-trail \
     --is-multi-region-trail
   aws cloudtrail start-logging --name org-trail
   ```

2. **Allow member accounts to send events to the central bus.** In the central security account, add a resource policy to the default EventBridge bus:

   ```bash
   aws events put-permission \
     --action events:PutEvents \
     --principal "*" \
     --statement-id AllowOrgAccounts \
     --condition '{"Type":"StringEquals","Key":"aws:PrincipalOrgID","Value":"o-XXXXXXXXXX"}'
   ```

3. **Create a forwarding rule in each member account** (or deploy via CloudFormation StackSets across the org) that matches CloudTrail and GuardDuty events and forwards them to the central bus:

   ```bash
   aws events put-rule \
     --name forward-to-central-opencdr \
     --event-pattern '{"source":["aws.cloudtrail","aws.guardduty"]}' \
     --state ENABLED

   aws events put-targets \
     --rule forward-to-central-opencdr \
     --targets '[{
       "Id": "CentralBus",
       "Arn": "arn:aws:events:<region>:<security-account-id>:event-bus/default",
       "RoleArn": "arn:aws:iam::<member-account-id>:role/EventBridgeForwardRole"
     }]'
   ```

4. **Deploy OpenCDR in the central security account** as normal. The processor Lambda will receive events from all member accounts through the central bus, and signals will include the originating `aws_account_id` for triage.

---

### Install dependencies

```bash
npm install -g serverless
npm install          # installs serverless-python-requirements and serverless-iam-roles-per-function
```

---

## Deployment

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

This provisions:
- 7 Lambda functions (each with its own least-privilege IAM role): processor, alerter, publisher, notifier, responder, api, alarmNotifier
- 7 DynamoDB tables (signals, alerts, outbox, logs, detection-rules, settings, ir-account-roles)
- 2 SQS queues with dead-letter queues (notifications, responses)
- 1 stream failure queue (catches poison-pill records from DynamoDB streams)
- API Gateway with API key auth (10k requests/month, 100 RPS)
- 2 SNS topics: infrastructure alarms (`opencdr-<stage>-alarms`) and security alerts (`opencdr-<stage>-alerts`)
- 11 CloudWatch alarms + 1 dashboard (Lambda errors, DLQ depth, stream iterator age — see [CloudWatch Alarms](#cloudwatch-alarms))
- 1 monthly cost budget alerting through the same Slack pipeline as the alarms above (see [Cost tracking](#cost-tracking))
- X-Ray tracing and custom CloudWatch metrics for detection health (see [Observability](#observability))
- The receiving side of cross-region event forwarding (an IAM role + bus policy) — the sending side needs a separate, opt-in step per additional region (see [Multi-region coverage](#multi-region-coverage))

### CloudWatch Alarms

OpenCDR ships 11 alarms out of the box:

| Alarm | Metric | Threshold |
|---|---|---|
| `processor`/`alerter`/`publisher`/`notifier`/`responder`/`api` errors (one alarm each — `alarmNotifier` itself is deliberately excluded, to avoid an alarm-notification loop) | `AWS/Lambda Errors` | > 0 |
| Notifications DLQ depth | `AWS/SQS ApproximateNumberOfMessagesVisible` | > 0 |
| Responses DLQ depth | `AWS/SQS ApproximateNumberOfMessagesVisible` | > 0 |
| Stream failure queue depth | `AWS/SQS ApproximateNumberOfMessagesVisible` | > 0 |
| Alerter stream iterator age | `AWS/Lambda IteratorAge` | > 5 min |
| Publisher stream iterator age | `AWS/Lambda IteratorAge` | > 5 min |

All alarms deliver to the `opencdr-<stage>-alarms` SNS topic, which `alarmNotifier` forwards to Slack (🔴 ALARM / ✅ OK, name, description, reason) — the same delivery path the [cost budget](#cost-tracking) below reuses. Pass `--param="alarmEmail=you@example.com"` at deploy time to also subscribe an email address directly to that topic. AWS will send a confirmation email — click the link once to activate.

A single CloudWatch Dashboard (`OpsDashboard`, linked in the stack's outputs after deploy) ties these together with Lambda health/duration/invocations across all 7 functions, all three queue depths, and the custom detection-health metrics below.

### Observability

X-Ray tracing, four custom detection-health metrics, and the `OpsDashboard` CloudWatch dashboard are all provisioned automatically, zero configuration. Full detail — including how the X-Ray service map's node coverage works — is in [`docs/observability.md`](docs/observability.md).

### Cost tracking

Every resource this stack creates is tagged `Project=opencdr` / `Stage=<stage>`, and a monthly `AWS::Budgets::Budget` (`CostBudget` in `serverless.yml`) alerts through the same Slack pipeline as the CloudWatch alarms above at 80% actual, 100% actual, and 100% forecasted spend. Pass `--param="monthlyBudgetUsd=<amount>"` at deploy time to set the threshold (default `50`).

Two one-time steps in the AWS account are required before any of this reports real numbers — neither is something CloudFormation can do for you:
1. Enable Cost Explorer once (Billing console → Cost Explorer).
2. Activate the `Project`/`Stage` tags as cost allocation tags (Billing console → Cost allocation tags) — takes up to 24h to start appearing, and only covers spend from activation forward, not retroactively.

Once both are done, get a spend breakdown for a stage with:

```bash
./scripts/cost_report.sh --stage dev
./scripts/cost_report.sh --stage prod --granularity MONTHLY --start 2026-07-01 --end 2026-08-01
```

### Multi-region coverage

**A fresh deploy only covers its own region.** CloudTrail delivers events to the default EventBridge bus in whichever region the API call happened in — true even for a multi-region trail — and GuardDuty detectors are per-region. If your account operates in more than one region, activity outside the deployment region is silently missed until you explicitly onboard each additional region:

```bash
./scripts/setup_region_forwarding.sh --stage dev --region eu-west-1        # one region
./scripts/setup_region_forwarding.sh --stage dev --regions eu-west-1,ap-southeast-1  # several
./scripts/setup_region_forwarding.sh --stage dev --region eu-west-1 --remove         # tear one down
```

This acts on each region independently and continues past a failure rather than aborting the run — an account restricted to an approved region list (AWS Control Tower, an SCP) will legitimately deny this in blocked regions, which is expected, not a bug. Full detail, including exactly which signal rules are affected, in [`docs/region-forwarding.md`](docs/region-forwarding.md).

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `OPENCDR_IR_ROLE_ARN` | auto-created home-account role | Fallback IAM role the responder assumes when a detection's AWS account has no row in `irAccountRolesTable` — see [docs/ir-role.md](docs/ir-role.md). Auto-wired by `serverless.yml`; only set this to override it. |
| `DREDGE_DRY_RUN` | `false` | Set to `true` to simulate IR actions without executing them |
| `RESPONDER_RATE_LIMIT_WINDOW_MINUTES` | `5` | Rolling window for the responder's action-rate circuit breaker |
| `RESPONDER_RATE_LIMIT_MAX_ACTIONS` | `20` | Max destructive actions per window before the circuit breaker trips |
| `RESPONDER_ROLE_CACHE_TTL_SECONDS` | `60` | How long a resolved account→role lookup is cached before re-checking `irAccountRolesTable` |
| `CORRELATION_QUERY_LIMIT` | `300` | Max signals queried per correlation evaluation |

### CI/CD deployment (OIDC, no long-lived keys)

`.github/workflows/ci.yml` deploys to a `dev` stage automatically on every
push to `main`, using short-lived credentials federated via GitHub's OIDC
provider rather than long-lived AWS access keys. One-time setup for your
own account (or a client's) is in [`ci-bootstrap/`](ci-bootstrap/README.md)
— the same template also serves as the reference workflow for adopters who
want this instead of the manual `serverless deploy` flow above. See
[`docs/stack-protection.md`](docs/stack-protection.md) for the termination
protection and drift detection that come with it. Every CI deploy also
writes the stage's real API key to SSM Parameter Store as a SecureString
(`/opencdr-<stage>/api-key`) — retrieve it with:

```bash
aws ssm get-parameter --name /opencdr-dev/api-key --with-decryption \
  --query Parameter.Value --output text
```

rather than pulling it into a local file by hand — that's exactly how a
real key ended up committed to this repo once already (see `.opencdr.json`
in git history, since removed).


---

## OpenCDR CLI

`scripts/opencdr.py` is a management CLI for interacting with a deployed OpenCDR stack. It wraps the REST API and provides an interactive setup wizard.

### Quick start

```bash
# Interactive setup wizard — configures API connection, loads rules, and sets up notifications
python3 scripts/opencdr.py setup

# Or configure manually
python3 scripts/opencdr.py config set --url https://<api-id>.execute-api.<region>.amazonaws.com/dev --key <api-key>
```

Your API URL and key are printed by `serverless deploy` in the endpoints and API Keys sections.

### Commands

```bash
# Check API health
python3 scripts/opencdr.py status

# Rules
python3 scripts/opencdr.py rules load                            # load all rules from support_files/
python3 scripts/opencdr.py rules list --kind signal
python3 scripts/opencdr.py rules get <rule_id> --kind signal
python3 scripts/opencdr.py rules delete <rule_id> --kind signal

# Notification settings
python3 scripts/opencdr.py settings get
python3 scripts/opencdr.py settings set --slack-webhook https://hooks.slack.com/...
python3 scripts/opencdr.py settings set --discord-webhook https://discord.com/api/webhooks/...
python3 scripts/opencdr.py settings set --email-topic-arn arn:aws:sns:<region>:<account>:opencdr-dev-alerts
python3 scripts/opencdr.py settings set --enable-securityhub
python3 scripts/opencdr.py settings set \
  --jira-url https://yourco.atlassian.net \
  --jira-project SEC \
  --jira-email soc@yourco.com \
  --jira-token <api-token>
python3 scripts/opencdr.py settings set \
  --webhook-url https://events.pagerduty.com/v2/enqueue \
  --webhook-name pagerduty
python3 scripts/opencdr.py settings set \
  --webhook-url https://api.opsgenie.com/v2/alerts \
  --webhook-name opsgenie \
  --webhook-header "Authorization=GenieKey <api-key>"
python3 scripts/opencdr.py settings set --file support_files/settings/settings.json  # full payload

# Query signals and logs
python3 scripts/opencdr.py signals list --severity HIGH
python3 scripts/opencdr.py logs list --service OCDR-PROCESSOR

# Run tests
python3 scripts/opencdr.py test local
python3 scripts/opencdr.py test deployed --stage dev
```

---

## Batteries Included — Detection Rules

OpenCDR ships 19 signal rules and 4 correlation rules covering the most common AWS attack patterns. Load them with:

```bash
# Load all rules into DynamoDB (dev stage)
./scripts/load_rules.sh

# Load into a specific stage / region
./scripts/load_rules.sh --stage prod --region us-west-2

# Preview without writing
./scripts/load_rules.sh --dry-run
```

### Signal rules

| Rule | Severity | Tactic |
|---|---|---|
| `001` Console login without MFA | HIGH | Initial Access |
| `002` Root account used for any action | CRITICAL | Privilege Escalation |
| `003` Root account console login | CRITICAL | Initial Access |
| `004` Root access key created | CRITICAL | Persistence |
| `005` IAM user created | MEDIUM | Persistence |
| `006` Access key created | MEDIUM | Persistence |
| `007` IAM role created | MEDIUM | Persistence |
| `008` Lambda function created or updated | MEDIUM | Persistence |
| `009` AdministratorAccess policy attached | CRITICAL | Privilege Escalation |
| `010` Wildcard inline policy created | HIGH | Privilege Escalation |
| `011` Security group ingress rule added | MEDIUM | Defense Evasion |
| `012` CloudTrail stopped, deleted, or updated | CRITICAL | Defense Evasion |
| `013` GuardDuty detector deleted or disabled | CRITICAL | Defense Evasion |
| `014` AWS Config recorder stopped or deleted | HIGH | Defense Evasion |
| `015` Security Hub disabled | HIGH | Defense Evasion |
| `016` Secrets Manager secret accessed | HIGH | Credential Access |
| `017` SSM parameter accessed | MEDIUM | Credential Access |
| `018` S3 bucket made public | HIGH | Exfiltration |
| `019` RDS snapshot made public | HIGH | Exfiltration |

### Correlation rules

| Rule | Severity | Description |
|---|---|---|
| `020` Console login brute force | CRITICAL | 5+ MFA-less logins from same user in 15 min |
| `021` IAM activity burst | CRITICAL | 5+ IAM signals from same actor in 5 min |
| `022` Defense evasion burst | CRITICAL | 2+ logging/detection services disabled in 10 min |
| `023` Credential harvesting | CRITICAL | 3+ secrets/SSM accesses from same actor in 5 min |

---

## Testing Rules Locally

Test all rules against sample events without deploying to AWS:

```bash
python3 scripts/test_rules_local.py

# Filter by event
python3 scripts/test_rules_local.py --event 012

# Filter by rule
python3 scripts/test_rules_local.py --rule cloudtrail
```

Sample events for all 19 signal rules live in `support_files/test_events/`.

### Integration testing (deployed stack)

```bash
# Test all events against the deployed processor Lambda
./scripts/test_deployed.sh

# Test a single event
./scripts/test_deployed.sh --event 009

# Test against prod
./scripts/test_deployed.sh --stage prod --region us-west-2
```

---

## Writing Detection Rules

Rules are stored in DynamoDB. You can write them as JSON and load them with `load_rules.sh`, or manage them at runtime via the API.

### Signal rule

Matches a single normalized event. When all conditions pass, a signal is written to the signals table.

```json
{
  "rule_id": "001_console_login_no_mfa",
  "rule_kind": "signal",
  "description": "Console login without MFA.",
  "enabled": true,
  "severity": "HIGH",
  "notify": true,
  "response_module": "",
  "playbook": "Verify user and source IP. If suspicious, revoke sessions and enforce MFA.",
  "conditions": [
    { "field": "activity_name", "op": "equals", "value": "ConsoleLogin" },
    { "field": "raw_event.detail.additionalEventData.MFAUsed", "op": "equals", "value": "No" }
  ]
}
```

**Supported operators:** `exists`, `not_exists`, `equals`, `not_equals`, `in`, `not_in`, `contains`, `not_contains`, `prefix`, `suffix`, `matches` (regex), `wildcard` (matches any event)

**Normalized fields available in conditions:**

| Field | Description |
|---|---|
| `activity_name` | CloudTrail event name (e.g. `ConsoleLogin`, `CreateUser`) |
| `category` | Event category derived from service (e.g. `iam`, `s3`, `ec2`, `authn`) |
| `class_name` | Event class (`api_activity`, `authentication`, `security_finding`) |
| `source` | Event source (`cloudtrail`, `guardduty`) |
| `severity` | Normalized severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN`) |
| `actor.type` | Identity type (`Root`, `IAMUser`, `AssumedRole`, `FederatedUser`) |
| `actor.user_name` | IAM principal name |
| `actor.account_id` | AWS account ID of the actor |
| `actor.arn` | Full ARN of the actor |
| `network.source_ip` | Source IP address |
| `network.user_agent` | User agent string |
| `api.service` | AWS service endpoint (e.g. `iam.amazonaws.com`) |
| `api.operation` | API operation name |
| `api.error_code` | CloudTrail error code if the call failed |
| `raw_event.detail.*` | Any field from the raw EventBridge event payload |

### Correlation rule

Groups signals by a field, counts them within a time window, and fires an alert when the threshold is reached. `signal_conditions` optionally filters which signals count toward the threshold.

```json
{
  "rule_id": "020_correlation_console_login_bruteforce",
  "rule_kind": "correlation",
  "description": "Multiple MFA-less logins from the same user.",
  "enabled": true,
  "severity": "CRITICAL",
  "group_by": "actor.user_name",
  "time_window_seconds": 900,
  "threshold": 5,
  "signal_conditions": [
    { "field": "rule_id", "op": "equals", "value": "001_console_login_no_mfa" }
  ],
  "notify": true,
  "response_module": "disable_user",
  "playbook": "Disable the user and investigate source IPs."
}
```

---

## Automated Incident Response

Set `response_module` on any rule to trigger an automated action when it fires.

| Module | Action |
|---|---|
| `disable_user` | Disable all IAM access keys for the actor |
| `delete_user` | Delete the IAM user |
| `disable_access_key` | Disable a specific access key |
| `disable_role` | Attach a deny-all inline policy to the role |
| `block_s3_public_access` | Enable account-level S3 public access block |
| `block_s3_bucket_public_access` | Block public access on a specific bucket |
| `block_s3_object_public_access` | Make a single S3 object private (`ACL=private`) |
| `isolate_ec2_instances` | Replace instance security groups with an isolation group |

Set `DREDGE_DRY_RUN=true` to simulate all IR actions without making changes.

Destructive actions are also capped by a rolling-window circuit breaker
(`RESPONDER_RATE_LIMIT_MAX_ACTIONS` per `RESPONDER_RATE_LIMIT_WINDOW_MINUTES`,
default 20 per 5 minutes) — once tripped, further matching detections are
logged and skipped rather than executed until the window rolls forward.

A successful action doesn't just log — it also notifies. `responder`
queues a second, green-styled Slack/Discord/email notification distinct
from the alert that triggered it (Security Hub/Jira/webhook aren't
supported for this notification type yet), so "this was remediated" is
as visible as "this was detected." See [Notifications](#notifications).

### How the responder authorizes itself

The responder's own Lambda execution role has no destructive AWS
permissions — the only thing it can do on its own credentials is
`sts:AssumeRole` on roles named `${self:service}-${self:provider.stage}-ir-role`
(e.g. `opencdr-dev-ir-role`) in *any* AWS account, not a blanket grant.
Everything a response module actually does (disabling a user, blocking S3
public access, isolating an EC2 instance, ...) runs through the temporary
credentials returned by assuming one of those roles instead.

Which role gets assumed is resolved **per detection**, from the AWS account
that detection came from (`_resolve_role_arn` in
`src/handlers/responder.py`):

1. That account has an enabled row in the `irAccountRolesTable` DynamoDB
   table → assume that row's `role_arn`.
2. That account has a row but it's disabled → skip the action entirely
   (logged as `IR_ACCOUNT_DISABLED`) — does **not** fall back to (3).
3. No row for that account, or the account couldn't be determined at all →
   `OPENCDR_IR_ROLE_ARN`.

**Single-account deployments need zero setup for this.**
`serverless.yml` auto-creates the home account's IR role as a CloudFormation
resource and wires `OPENCDR_IR_ROLE_ARN` to it automatically — `serverless
deploy` alone is enough; there's no manual `aws iam create-role` step and no
env var to set.

**Additional accounts** (multi-account / cross-account IR) get onboarded by
creating the same-named role there by hand and adding one row via
`POST /ir-roles`:

```bash
aws iam create-role --role-name opencdr-dev-ir-role \
  --assume-role-policy-document file:///tmp/trust-policy.json   # see docs/ir-role.md
aws iam put-role-policy --role-name opencdr-dev-ir-role \
  --policy-name opencdr-ir-permissions \
  --policy-document file://docs/ir-role-permissions.json

curl -X POST "$OPENCDR_API_URL/ir-roles" -H "x-api-key: $OPENCDR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"aws_account_id": "<TARGET_ACCOUNT_ID>", "role_arn": "arn:aws:iam::<TARGET_ACCOUNT_ID>:role/opencdr-dev-ir-role"}'
```

Full walkthrough (trust policy example, kill-switch/disable, cache TTLs,
keeping the permissions policy in sync) is in
[docs/ir-role.md](docs/ir-role.md).

---

## Notifications

Configure channels and routing in the settings table via the CLI or the API. A full example is in `support_files/settings/settings.json`.

```json
{
  "setting_id": "global",
  "notifications_enabled": true,
  "channels": {
    "slack": {
      "enabled": true,
      "webhook_url": "https://hooks.slack.com/services/..."
    },
    "discord": {
      "enabled": false,
      "webhook_url": "https://discord.com/api/webhooks/..."
    },
    "email": {
      "enabled": false,
      "topic_arn": "arn:aws:sns:us-east-1:123456789012:opencdr-dev-alerts"
    },
    "securityhub": {
      "enabled": false
    },
    "jira": {
      "enabled": false,
      "base_url": "https://yourco.atlassian.net",
      "project_key": "SEC",
      "user_email": "soc@yourco.com",
      "api_token": "<api-token>",
      "issue_type": "Bug"
    },
    "webhook": {
      "enabled": false,
      "targets": [
        {
          "name": "pagerduty",
          "url": "https://events.pagerduty.com/v2/enqueue",
          "headers": {}
        },
        {
          "name": "opsgenie",
          "url": "https://api.opsgenie.com/v2/alerts",
          "headers": { "Authorization": "GenieKey <api-key>" }
        }
      ]
    }
  },
  "routing": {
    "CRITICAL": ["slack", "email", "jira"],
    "HIGH": ["slack", "securityhub"],
    "MEDIUM": ["discord"],
    "LOW": ["webhook"]
  }
}
```

Routing is per-severity. If no routing entry matches, all enabled channels with sufficient configuration receive the alert.

### Slack and Discord

Generate an incoming webhook URL in the Slack app or Discord server settings and pass it to the CLI:

```bash
python3 scripts/opencdr.py settings set --slack-webhook https://hooks.slack.com/services/...
python3 scripts/opencdr.py settings set --discord-webhook https://discord.com/api/webhooks/...
```

The webhook URL is the sole authentication mechanism for both platforms — treat it as a secret.

### Email notifications via SNS

Email notifications are delivered through the `opencdr-<stage>-alerts` SNS topic created by the stack.

**Get the topic ARN:**

```bash
aws sns list-topics \
  --query "Topics[?contains(TopicArn, 'opencdr') && contains(TopicArn, 'alerts')]" \
  --output text
```

**Subscribe your email address:**

```bash
aws sns subscribe \
  --topic-arn arn:aws:sns:<region>:<account-id>:opencdr-<stage>-alerts \
  --protocol email \
  --notification-endpoint you@example.com
```

AWS will send a confirmation email — click the link to activate the subscription before alerts will be delivered.

Alternatively, pass `--param="alertEmail=you@example.com"` at deploy time and the subscription is created automatically.

**Enable email in settings:**

```bash
python3 scripts/opencdr.py settings set \
  --email-topic-arn arn:aws:sns:<region>:<account-id>:opencdr-<stage>-alerts
```

### AWS Security Hub

OpenCDR can push findings to Security Hub in [ASFF format](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html). Findings appear in the Security Hub console under the custom product for your account.

**Prerequisites:** Security Hub must be enabled in your account and region.

```bash
# Verify Security Hub is active
aws securityhub describe-hub

# Enable the channel
python3 scripts/opencdr.py settings set --enable-securityhub
```

No additional configuration is required — the notifier Lambda derives the product ARN from its own execution context at runtime.

### Jira

OpenCDR creates Jira issues via the [Jira REST API v3](https://developer.atlassian.com/cloud/jira/platform/rest/v3/). Issues are created with ADF-formatted descriptions, severity-mapped priorities, and an `opencdr` label.

**Severity → Jira priority mapping:**

| OpenCDR severity | Jira priority |
|---|---|
| CRITICAL | Highest |
| HIGH | High |
| MEDIUM | Medium |
| LOW | Low |
| INFORMATIONAL | Lowest |

**Setup:**

1. Generate a Jira API token at [id.atlassian.com/manage-profile/security/api-tokens](https://id.atlassian.com/manage-profile/security/api-tokens)
2. Configure the channel:

```bash
python3 scripts/opencdr.py settings set \
  --jira-url https://yourco.atlassian.net \
  --jira-project SEC \
  --jira-email soc@yourco.com \
  --jira-token <api-token>

# Optional: use a different issue type (default: Bug)
python3 scripts/opencdr.py settings set \
  --jira-url https://yourco.atlassian.net \
  --jira-project SEC \
  --jira-email soc@yourco.com \
  --jira-token <api-token> \
  --jira-issue-type Task
```

All four Jira flags (`--jira-url`, `--jira-project`, `--jira-email`, `--jira-token`) are required together.

### Custom webhook

The custom webhook channel POSTs the raw OpenCDR alert JSON to one or more HTTPS endpoints. Configure any number of named targets, each with its own URL and optional headers. This covers platforms that accept generic webhooks — PagerDuty, OpsGenie, Microsoft Teams, and others — without needing a dedicated first-party integration.

**Single target (no auth):**

```bash
python3 scripts/opencdr.py settings set \
  --webhook-url https://events.pagerduty.com/v2/enqueue \
  --webhook-name pagerduty
```

**With an authorization header:**

```bash
python3 scripts/opencdr.py settings set \
  --webhook-url https://api.opsgenie.com/v2/alerts \
  --webhook-name opsgenie \
  --webhook-header "Authorization=GenieKey <api-key>"
```

**Multiple headers:**

```bash
python3 scripts/opencdr.py settings set \
  --webhook-url https://example.com/hook \
  --webhook-name my-hook \
  --webhook-header "Authorization=Bearer <token>" \
  --webhook-header "X-Source=opencdr"
```

To configure multiple targets, use `--file` with a full settings JSON.

Each target is attempted independently — if one target fails the others still run, and sent/failed counts reflect individual target results.

> **Note on payload shape:** the webhook receives the raw OpenCDR alert object. Most platforms expect a platform-specific format (e.g. PagerDuty expects `routing_key` and `event_action` fields). If you need payload transformation, point the webhook at a small Lambda or API Gateway that reshapes the payload before forwarding it. See [Custom integrations via SNS](#custom-integrations-via-sns) below for the recommended AWS-native approach.

### Custom integrations via SNS

For anything beyond the built-in channels — custom payload formats, conditional routing, multi-step workflows — subscribe a Lambda to the `opencdr-<stage>-alerts` SNS topic. OpenCDR publishes every alert there; your Lambda does whatever you need.

**Architecture:**

```
OpenCDR notifier
  └─► SNS topic (opencdr-<stage>-alerts)
        └─► Your Lambda
              ├─► PagerDuty (with custom payload)
              ├─► ServiceNow
              ├─► Datadog
              └─► Anything else
```

**Setup:**

1. Deploy your integration Lambda (any runtime)
2. Subscribe it to the SNS topic:

```bash
aws sns subscribe \
  --topic-arn arn:aws:sns:<region>:<account-id>:opencdr-<stage>-alerts \
  --protocol lambda \
  --notification-endpoint arn:aws:lambda:<region>:<account-id>:function:<your-function>
```

3. Grant SNS permission to invoke your Lambda:

```bash
aws lambda add-permission \
  --function-name <your-function> \
  --statement-id opencdr-sns-invoke \
  --action lambda:InvokeFunction \
  --principal sns.amazonaws.com \
  --source-arn arn:aws:sns:<region>:<account-id>:opencdr-<stage>-alerts
```

Your Lambda receives the full OpenCDR alert payload in `event["Records"][0]["Sns"]["Message"]` as a JSON string. No changes to OpenCDR are needed.

---

## SIEM Integrations

OpenCDR alerts can be shipped to a SIEM using either the built-in custom webhook channel or the SNS fan-out pattern — raw JSON over HTTP, or a Lambda subscribed to the alerts topic for payload transformation. Full walkthroughs for Datadog, Splunk, Microsoft Sentinel, Elastic/OpenSearch, Chronicle, IBM QRadar, and Sumo Logic are in [`docs/siem-integrations.md`](docs/siem-integrations.md).

---

## API

All endpoints require an `x-api-key` header. The key is created automatically by Serverless and available in API Gateway after deployment.

| Method | Path | Description |
|---|---|---|
| `GET` | `/status` | Health check |
| `GET` | `/help` | Endpoint reference |
| `GET` | `/signals` | Query signals by `severity`, `event_id`, or `category` |
| `GET` | `/logs` | Query logs by `service`, `event_id`, or `event_name` |
| `GET` | `/rules` | List rules (filter by `rule_kind=signal\|correlation`) |
| `GET` | `/settings` | Get global notification settings |
| `GET` | `/ir-roles` | List AWS account → IR role mappings (see [docs/ir-role.md](docs/ir-role.md)) |

All list endpoints support `page_size`, `order` (`asc`/`desc`), and cursor-based pagination via `next_token`.

---

## Project Structure

```
src/
  domain/               # Cloud-agnostic detection & correlation logic
  handlers/             # Lambda entry points (processor, alerter, publisher, notifier, responder, api, alarm_notifier)
  infra/                # AWS adapters (DynamoDB, SQS, logging, metrics, X-Ray)
  config/               # Env/config loading shared across handlers
  notifier/             # Shared HTTP transport used by notification delivery
docs/                   # Deep-reference documentation — see docs/README.md
support_files/
  detection_rules/      # Production rules (load with scripts/load_rules.sh)
  test_events/          # Sample EventBridge events for local rule testing
  settings/             # Example notification settings
scripts/
  opencdr.py            # Management CLI (setup wizard, rules, settings, signals, logs)
  test_rules_local.py   # Test rules locally without AWS
  load_rules.sh         # Seed rules into DynamoDB
  test_deployed.sh      # Integration test against deployed stack
  cost_report.sh        # Query Cost Explorer spend for a stage
  setup_region_forwarding.sh  # Onboard additional AWS regions (see docs/region-forwarding.md)
tests/
  domain/               # Unit tests for detection, correlation, and parser
  handlers/             # Unit tests for Lambda handlers (notifier channels, etc.)
  infra/                # Unit tests for AWS adapter layer
  scripts/              # Unit tests for the CLI
ci-bootstrap/           # Standalone CFN template for the OIDC deploy role (see docs/deployment.md)
region-forwarding/      # Standalone CFN template for cross-region event forwarding (see docs/region-forwarding.md)
serverless.yml          # Infrastructure definition
openapi.yml             # API spec (see docs/api-reference.md for known drift)
```

Note: `dredge` (the incident response action library `responder` runs actions through) is a separate, pinned dependency (`requirements.txt`), not vendored into this repo — see [Incident Response](docs/incident-response.md).

---

## Running Tests

```bash
pip install pytest pytest-cov
pytest tests/ -v

# With coverage
pytest tests/ --cov=src --cov=scripts --cov-report=term-missing
```

---

## License

[MPL 2.0](LICENSE)

# OpenCDR

[![CI](https://github.com/dbnz-io/opencdr-internal/actions/workflows/ci.yml/badge.svg)](https://github.com/dbnz-io/opencdr-internal/actions/workflows/ci.yml)
[![License: MPL 2.0](https://img.shields.io/badge/License-MPL_2.0-brightgreen.svg)](https://opensource.org/licenses/MPL-2.0)

Open-source Cloud Detection & Response for AWS. OpenCDR ingests CloudTrail and GuardDuty events, runs them through a configurable detection and correlation engine, and delivers alerts to Slack, Discord, or Email — with optional automated incident response.

## How It Works

```
EventBridge (CloudTrail / GuardDuty)
  └─► processor      — normalizes events, runs detection rules → writes signals
        └─► alerter  — runs correlation rules → writes alerts + outbox
              └─► publisher  — drains outbox → SQS
                    ├─► notifier   — sends alerts to Slack / Discord / Email (SNS)
                    └─► responder  — executes automated IR actions (disable user, isolate EC2, block S3…)
```

A REST API lets you query signals, logs, and rules, and manage configuration at runtime.

## Architecture

| Component | Trigger | Responsibility |
|---|---|---|
| **processor** | EventBridge rule | Parse event → normalize → run signal detection → store signals |
| **alerter** | DynamoDB stream (signals) | Run correlation rules → store alerts → write outbox |
| **publisher** | DynamoDB stream (outbox) | Claim outbox records → publish to SQS queues |
| **notifier** | SQS (notifications) | Format and deliver alerts to Slack / Discord / Email (SNS) |
| **responder** | SQS (responses) | Execute incident response actions via IAM / EC2 / S3 |
| **api** | API Gateway (HTTP) | Query signals, logs, rules; manage settings |

All state lives in DynamoDB (pay-per-request). The outbox pattern guarantees at-least-once delivery from alerter to SQS without direct coupling.

## Project Structure

```
src/
  domain/               # Cloud-agnostic detection & correlation logic
  handlers/             # Lambda entry points
  infra/                # AWS adapters (DynamoDB, SQS, logging)
  dredge/               # Incident response action library
support_files/
  detection_rules/      # Production rules (load with scripts/load_rules.sh)
  test_events/          # Sample EventBridge events for local rule testing
  settings/             # Example notification settings
scripts/
  opencdr.py            # Management CLI (setup wizard, rules, settings, signals, logs)
  test_rules_local.py   # Test rules locally without AWS
  load_rules.sh         # Seed rules into DynamoDB
  test_deployed.sh      # Integration test against deployed stack
tests/
  domain/               # Unit tests for detection, correlation, and parser
  handlers/             # Unit tests for Lambda handlers
serverless.yml          # Infrastructure definition
openapi.yml             # API spec
```

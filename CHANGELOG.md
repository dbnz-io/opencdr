# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [0.1.0] — 2026-04-02

### Added
- 6 Lambda functions: processor, alerter, publisher, notifier, responder, api
- 19 signal detection rules covering initial access, persistence, privilege escalation, defense evasion, credential access, and exfiltration
- 4 correlation rules: console login brute force, IAM activity burst, defense evasion burst, credential harvesting
- 7 automated incident response modules: disable_user, delete_user, disable_access_key, disable_role, block_s3_public_access, block_s3_bucket_public_access, isolate_ec2_instances
- Outbox pattern for at-least-once SQS delivery
- Slack and Discord notification support with severity routing
- REST API with API key auth, cursor pagination
- `scripts/load_rules.sh` — seed rules into DynamoDB
- `scripts/test_rules_local.py` — test rules without AWS
- `scripts/test_deployed.sh` — integration test against deployed stack
- Per-function least-privilege IAM roles
- DLQs for both SQS queues and DynamoDB stream failures
- OCSF-aligned event normalization for CloudTrail and GuardDuty

### Infrastructure
- DynamoDB pay-per-request on all 6 tables
- EventBridge rules covering CloudTrail (IAM, S3, EC2, RDS, Secrets Manager, SSM, Lambda, CloudTrail, GuardDuty, Config, Security Hub) and GuardDuty findings
- API Gateway with API key auth, 10k/month quota, 100 RPS throttle

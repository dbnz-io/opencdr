# OpenCDR Documentation

*Open-source Cloud Detection & Response for AWS — ingests CloudTrail and GuardDuty events, runs them through a configurable detection and correlation engine, and delivers alerts (with optional automated incident response) to Slack, Discord, Email, Security Hub, Jira, or any custom webhook.*

This is the deep-reference documentation set. For a fast-start overview and copy-paste command reference, the root [README](../README.md) is often quicker; these pages go deeper on *why* things are built the way they are, and are meant to work as a standalone reference on their own.

## Pages

- [Complete Setup Guide](setup.md) — every step, in order, from a clean AWS account to a fully working deployment
- [Architecture](architecture.md) — the nine Lambdas, the data stores, and how an event flows from raw CloudTrail record to delivered alert
- [Detection Rules](detection-rules.md) — the rule schema, how to author/test/load rules
- [API Reference](api-reference.md) — every REST endpoint, auth model, and where the OpenAPI spec is out of date
- [Incident Response](incident-response.md) — automated response modules, how `responder` authorizes itself, rate limiting, remediation notifications
- [Notifications](notifications.md) — channels, per-severity routing, remediation-success notifications
- [SIEM Integrations](siem-integrations.md) — Datadog, Splunk, Microsoft Sentinel, Elastic/OpenSearch, Chronicle, IBM QRadar, Sumo Logic
- [Observability](observability.md) — dashboard, custom metrics, tracing, alarm delivery, and the cost budget
- [Data Archival](data-archival.md) — why signals/alerts/logs TTL out of DynamoDB, where they go first (S3, Parquet), and how to query the archive
- [Deployment](deployment.md) — standing up a new deployment, CI/CD, what's automatic vs. manual
- [Security](security.md) — IAM model, secrets handling, known limitations stated plainly
- [Glossary](glossary.md) — terms used throughout these pages, defined the way this codebase actually uses them
- [`ir-role.md`](ir-role.md) — full IAM walkthrough for onboarding additional AWS accounts for cross-account incident response
- [`stack-protection.md`](stack-protection.md) — CloudFormation termination protection and drift detection
- [`region-forwarding.md`](region-forwarding.md) — why OpenCDR is blind outside its deployment region by default, and how to fix it
- [`org-forwarding.md`](org-forwarding.md) — routing every member account's events into a central security account, without an org-wide `PutEvents` grant

## Find what you need

| Question | Page |
|---|---|
| What does OpenCDR actually do, end to end? | [Architecture](architecture.md) |
| I'm setting this up for the first time — what's the full checklist? | [Complete Setup Guide](setup.md) |
| How do I deploy this into a new AWS account? | [Deployment](deployment.md) |
| What do I get automatically vs. what needs manual setup? | [Deployment](deployment.md#whats-automatic-vs-what-needs-a-one-time-step) |
| How do I write / test / load a detection rule? | [Detection Rules](detection-rules.md) |
| What's the difference between a signal, a correlation, and an alert? | [Glossary](glossary.md#signal-vs-alert-vs-correlation) |
| What fields can a rule's `conditions` check? | [dbnz-io/opencdr-detection-rules](https://github.com/dbnz-io/opencdr-detection-rules#signal-rules) |
| How does OpenCDR notify me of an alert? | [Notifications](notifications.md) |
| How do I route different severities to different channels? | [Notifications](notifications.md#per-severity-routing) |
| How do I forward alerts to my SIEM (Datadog, Splunk, Sentinel, ...)? | [Notifications](notifications.md#sns-fan-out-for-anything-the-built-in-channels-dont-cover) |
| Are my Slack/Jira/webhook secrets stored in plaintext? | [Security](security.md#secrets-management) |
| What AWS permissions does the responder Lambda need? | [Incident Response](incident-response.md#how-the-responder-authorizes-itself) |
| What automated response actions exist? | [Incident Response](incident-response.md#response-modules) |
| Is there rate limiting on automated response actions? | [Incident Response](incident-response.md#rate-limiting) |
| How do I know a remediation actually worked, not just that it was attempted? | [Incident Response](incident-response.md#remediation-notifications) |
| How do I set up incident response across multiple AWS accounts? | [`ir-role.md`](ir-role.md) |
| My account operates in more than one region — will OpenCDR catch everything? | [`region-forwarding.md`](region-forwarding.md) |
| Why does GuardDuty/EC2/S3 activity in another region never generate a signal? | [`region-forwarding.md`](region-forwarding.md#the-problem) |
| I run an AWS Organization — how do I get every member account's events into one place? | [`org-forwarding.md`](org-forwarding.md) |
| How do I disable automated response for one account without deleting its config? | [`ir-role.md`](ir-role.md#multi-account-onboard-each-additional-account) |
| Are API keys scoped, or does one key control everything? | [API Reference](api-reference.md#api-key-scopes) |
| Can I manage rules/settings/etc. from an MCP client instead of the CLI? | [API Reference](api-reference.md#mcp-server-default-management-plane) |
| What REST endpoints exist, and what do they need in the request? | [API Reference](api-reference.md) |
| Can I trust `openapi.yml` as complete? | [API Reference](api-reference.md#a-note-on-openapiyml) |
| What do I get for observability with zero configuration? | [Observability](observability.md#automatic-zero-configuration) |
| How do I get Slack/email notifications when OpenCDR itself breaks (not a detection)? | [Observability](observability.md#alarms-exist-automatically-delivery-is-the-one-time-step) |
| What custom metrics exist, and what do they tell me? | [Observability](observability.md#custom-metrics) |
| Is the observability stack portable to a non-AWS backend? | [Observability](observability.md#portability-the-honest-tradeoff) |
| Why does the X-Ray service map show DynamoDB/SQS nodes now when it didn't before? | [Observability](observability.md#x-ray-tracing) |
| How do I know what OpenCDR itself costs to run? | [Cost tracking](observability.md#cost-tracking) |
| Why do signals/alerts/logs disappear from DynamoDB after 90 days — is that data actually gone? | [Data Archival](data-archival.md) |
| How do I query old signals/alerts/logs after they've expired from DynamoDB? | [Data Archival](data-archival.md#querying-the-archive-athena) |
| How is CI/CD wired, and what happens on a push to `main`? | [Deployment](deployment.md#cicd-github-actions-oidc) |
| How do I protect the stack from accidental deletion? | [`stack-protection.md`](stack-protection.md#termination-protection) |
| How do I forward alerts to Datadog, Splunk, or another SIEM? | [SIEM Integrations](siem-integrations.md) |
| What DynamoDB tables and SQS queues exist, and who reads/writes them? | [Architecture](architecture.md#dynamodb-tables) |
| What does "outbox pattern" mean here specifically? | [Glossary](glossary.md#outbox-pattern) |
| What does OCSF-aligned mean in this codebase? | [Glossary](glossary.md#ocsf) |
| How do I report a security vulnerability in OpenCDR itself? | [`SECURITY.md`](../SECURITY.md) |
| How do I contribute a rule, bug fix, or feature? | [`CONTRIBUTING.md`](../CONTRIBUTING.md) |

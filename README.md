# OpenCDR

[![CI](https://github.com/dbnz-io/opencdr/actions/workflows/ci.yml/badge.svg)](https://github.com/dbnz-io/opencdr/actions/workflows/ci.yml)
![Coverage](coverage-badge.svg)
[![License: MPL 2.0](https://img.shields.io/badge/License-MPL_2.0-brightgreen.svg)](https://opensource.org/licenses/MPL-2.0)
[![Release](https://img.shields.io/github/v/release/dbnz-io/opencdr)](https://github.com/dbnz-io/opencdr/releases)
![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)
[![CodeQL](https://github.com/dbnz-io/opencdr/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/dbnz-io/opencdr/security/code-scanning)

Open-source event-driven Cloud Detection & Response for AWS. OpenCDR ingests CloudTrail and GuardDuty events, evaluates them against configurable detection rules, correlates related activity, and delivers alerts to Slack, Discord, Email, AWS Security Hub, Jira, or any HTTPS webhook — with optional automated incident response.

This README is a quickstart: enough to get a working deployment. Everything else — full architecture, every notification channel's setup, writing detection rules, the automated-response module reference, multi-account/multi-region setup, CI/CD, observability, cost tracking, SIEM integrations, the security model — lives in **[`docs/`](docs/README.md)**, which has a ["find what you need"](docs/README.md#find-what-you-need) index.

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

A REST API lets you query signals, logs, and rules, and manage configuration at runtime. Full architecture — all 9 Lambdas, every data store, the event-flow diagram: [`docs/architecture.md`](docs/architecture.md).

---

## Prerequisites

- [Node.js](https://nodejs.org/) >= 18 (CI itself runs Node 20)
- [Serverless Framework](https://www.serverless.com/) v4 — requires a free Serverless.com account/license key for CLI auth, see [Deployment](docs/deployment.md)
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

Deploying into an AWS Organization instead of a single account? See [`docs/org-forwarding.md`](docs/org-forwarding.md) — routes every member account's events into one central deployment.

---

## Quickstart

```bash
# 1. Install dependencies
npm install -g serverless
npm install

# 2. Deploy
serverless deploy --stage dev
```

Rule content lives in its own repo, [dbnz-io/opencdr-detection-rules](https://github.com/dbnz-io/opencdr-detection-rules) (MIT-licensed), pulled in here as a git submodule at `support_files/detection_rules`. If you cloned this repo without `--recurse-submodules`, run `git submodule update --init` first — otherwise step 3 below silently loads zero rules.

```bash
# 3. Load the bundled detection rules
./scripts/load_rules.sh --stage dev
```

> **⚠️ Automated response can take real, destructive action.** Rules load with every `response_module` stripped by default, regardless of `DREDGE_DRY_RUN` — a majority of the bundled rules ship with a `response_module` set. `DREDGE_DRY_RUN` itself now defaults to **live** in CI. Pass `--with-response-modules` only once you've reviewed [Response modules](docs/incident-response.md#response-modules) and actually want them armed.

```bash
# 4. Configure a notification channel (interactive wizard — also re-runs step 3)
python3 scripts/opencdr.py setup

# 5. Verify end to end
./scripts/test_deployed.sh --stage dev
```

Your API URL and key are printed by `serverless deploy`. That's a working deployment — detecting, correlating, and notifying.

**Beyond this:** multi-region coverage, multi-account incident response, CI/CD, alarm delivery, cost tracking, every notification channel in depth, writing your own detection rules, and the full automated-response module reference are all in [`docs/`](docs/README.md) — start with the **[Complete Setup Guide](docs/setup.md)** for the full, ordered checklist (this quickstart is roughly its first 4 steps of 11).

---

## OpenCDR CLI & MCP Server

`scripts/opencdr.py` is a management CLI for a deployed OpenCDR stack — rules, settings, signals, logs, and the interactive setup wizard used above.

```bash
python3 scripts/opencdr.py status   # health check
python3 scripts/opencdr.py setup    # interactive wizard
```

`mcp_server/server.py` exposes that same management surface as MCP tools, for driving OpenCDR from an MCP-aware client (Claude Code, etc.) instead of the command line. Full CLI command reference and MCP setup: [`docs/api-reference.md`](docs/api-reference.md#mcp-server-default-management-plane).

---

## Running Tests

```bash
pip install pytest pytest-cov
pytest tests/ -v

# With coverage
pytest tests/ --cov=src --cov=scripts --cov-report=term-missing
```

Contributing a rule or code change? See [`CONTRIBUTING.md`](CONTRIBUTING.md).

---

## License

[MPL 2.0](LICENSE)

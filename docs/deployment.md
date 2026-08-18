# Deployment

*How to stand up OpenCDR in an AWS account, and what you get automatically vs. what needs a one-time manual step.*

## Prerequisites

- [Node.js](https://nodejs.org/) >= 18 and [Serverless Framework](https://www.serverless.com/) v4 (`npm install -g serverless`)
- Python 3.12 (matches `provider.runtime` in `serverless.yml`)
- AWS credentials for the target account (`aws configure`, or environment variables, or — for CI — the OIDC role below)
- `jq` (used by the rule-loading and integration-test scripts)
- **CloudTrail enabled** in the target account/region. OpenCDR receives events via EventBridge, and CloudTrail management events are only delivered to EventBridge once a trail is active — without one, `processor` never receives anything and no signals are ever generated. See the root [README](../README.md#cloudtrail-must-be-enabled) for the exact `aws cloudtrail create-trail` commands, including the multi-account/AWS-Organizations variant.
- **A Serverless Framework license key.** v4 requires CLI authentication for every invocation, including a local `serverless deploy` — free under $2M annual revenue, but still needs a one-time account/license key from [serverless.com](https://www.serverless.com/). For CI, set it as the `SERVERLESS_LICENSE_KEY` repo secret (see [CI/CD](#cicd-github-actions-oidc) below); locally, `export SERVERLESS_LICENSE_KEY=<key>` or `serverless login`.
- **Rule content**, if you'll be running `load_rules.sh`: `support_files/detection_rules` is a git submodule ([dbnz-io/opencdr-detection-rules](https://github.com/dbnz-io/opencdr-detection-rules)) — clone with `--recurse-submodules`, or run `git submodule update --init` after the fact.

## Manual deploy

```bash
npm install    # installs serverless-python-requirements
serverless deploy --stage dev
```

This single command provisions everything in [Architecture](architecture.md): all 9 Lambdas with their own IAM roles, all 7 DynamoDB tables, the S3/Glue/Firehose archival pipeline (see [Data Archival](data-archival.md)), all 7 SQS queues, both SNS topics, API Gateway with API-key auth, 16 CloudWatch alarms, a monthly cost budget, and the [CloudWatch Dashboard](observability.md). Nothing else needs to run first.

Two deploy-time parameters are worth knowing about, both optional:

```bash
serverless deploy --stage dev \
  --param="alarmEmail=ops@example.com" \
  --param="alertEmail=security@example.com"
```

`alarmEmail` subscribes that address to infrastructure alarms (Lambda errors, DLQ depth) via the `AlarmsSnsTopic`. `alertEmail` subscribes to security detection alerts via the separate `AlertsSnsTopic`. Both default to unset — you can always subscribe an address (or anything else SNS supports) to either topic later without redeploying. See [Observability](observability.md) for the full picture on alarm delivery, including the zero-app-code Slack option.

## What's automatic vs. what needs a one-time step

This is the general pattern worth internalizing, not just an observability-specific one:

| Automatic on every deploy | One-time manual step |
|---|---|
| All 9 Lambdas, all tables/queues/topics, the S3 archive pipeline | Enabling CloudTrail (prerequisite, not part of the stack) |
| The home account's IR role (`OpencdrIrRole`), wired to `responder` | Onboarding *additional* AWS accounts for cross-account IR — see [Incident Response](incident-response.md) |
| CloudWatch Dashboard, custom metrics, X-Ray tracing | Alarm delivery destination (`alarmEmail` param, or the Slack SSM parameter) — see [Observability](observability.md) |
| Cost-allocation tags (`Project`/`Stage`) on every resource, monthly `CostBudget` alert | Enabling Cost Explorer and activating those tags as cost allocation tags in Billing preferences — see [Cost tracking](observability.md#cost-tracking) |
| The receiving side of cross-region event forwarding (`RegionForwarderRole`, bus policy) | Onboarding *additional regions* your account operates in — otherwise CloudTrail/GuardDuty activity outside the deployment region is silently missed. See [Cross-Region Event Forwarding](region-forwarding.md) |
| Stack termination protection (CI only — see below) | Subscribing to the alerts SNS topic if you want email delivery for security alerts too |
| Detection rule *table* and schema | Loading the 24 signal + 4 correlation rules into it (`scripts/load_rules.sh`) |

## CI/CD (GitHub Actions, OIDC)

`.github/workflows/ci.yml` deploys to `dev` automatically on every push to `main`, authenticating via short-lived credentials federated through GitHub's OIDC provider — no long-lived AWS access keys stored in GitHub at all.

Pipeline stages, in order: `validate-rules` → `secrets-scan` / `python-sast` (parallel, non-blocking — findings are visible but don't fail the run) → `test` → `deploy` → post-deploy checks (parallel) → `release`.

The post-deploy stage used to be one long serial job; it's now independent jobs, all `needs: [deploy]` and nothing else, running in parallel — each has one concern, each is individually re-runnable from the GitHub UI if only it fails, and total wall-clock time is bounded by the slowest single job rather than the sum of all of them (the two pipeline checks each have up to ~90s of built-in retry/sleep for a warm-container rule-cache race, which used to be additive against everything else):

- **`post-deploy-auth-check`** — asserts API-key auth actually enforces (valid/invalid key against `/rules` and `/signals`).
- **`post-deploy-cloudtrail-check`** — fires a synthetic CloudTrail-shaped event straight at a dedicated, isolated canary rule to confirm a detection rule can genuinely fire end-to-end via a direct Lambda invoke, confirms TTL is actually enabled (not just declared in `serverless.yml`) on all four archived/expiring tables, and confirms the canary signal actually reached `archiver` (grepping its own CloudWatch logs for the canary's `detection_id`, not waiting on the slower eventually-consistent S3/Parquet write — see [Data Archival](data-archival.md#verified-by-ci-not-just-declared)).
- **`post-deploy-guardduty-check`** — the same direct-invoke canary pattern, but GuardDuty-shaped, proving `GuardDutyEventBridgeParser`'s finding-type parsing, severity bucketing, and `gd_resource_type` extraction all work against the real deployed code. **This check caught a real production bug on its first genuine run**: a GuardDuty-sourced detection's `raw_event` carries AWS's own float `severity` (e.g. `8.0`) — every real GuardDuty finding, not just this synthetic one — and `signal_writer.py`'s `json.loads()` reconstituted it as a native Python `float`, which DynamoDB's high-level `Table.put_item` rejects outright (`"Float types are not supported. Use Decimal types instead."`). Invisible for CloudTrail items (no floats anywhere in their `raw_event`), invisible to 1000+ unit tests (none of them round-trip a detection through JSON→SQS→JSON→DynamoDB), and would have silently dropped every real GuardDuty finding into the dead-letter queue in a live deployment. Fixed with `json.loads(..., parse_float=Decimal)` at the SQS-message-parsing boundary — see `tests/handlers/test_signal_writer.py`'s `TestFloatToDecimalConversion`.
- **`post-deploy-notifier-check`** — confirms the test webhook endpoint is reachable; `continue-on-error` at the step level, so it never blocks `release` even though `release` still waits for the job to complete.

`release` only cuts a version tag once `deploy` and all post-deploy jobs have completed — a release means "confirmed working," not just "the deploy command exited zero." It also generates an SBOM from GitHub's dependency graph and attaches it as a permanent asset on that release — for the current state of `main` at any other time, use GitHub's own Insights → Dependency graph → Export SBOM button instead (free on private repos, unlike CodeQL/native secret scanning).

**Cutting a release without a fresh deploy**: `.github/workflows/release.yml` (`workflow_dispatch`, `dry_run` input defaulting to `true`) runs the same tag/SBOM/GitHub-Release logic on demand — the real case is "I already deployed and verified this via [manual testing](manual-testing.md) or a prior green push-to-main, and just want to add a CHANGELOG.md entry and cut the release without pushing a no-op commit to re-trigger the whole pipeline." It deliberately does **not** re-check that the current commit passed post-deploy checks — that's the automatic path's job — so only run it against a commit you've actually confirmed working. Both paths call the same `.github/actions/cut-release` composite action, so the tag-cutting logic itself lives in one place.

**One-time setup, per AWS account** — before the `deploy` job can authenticate at all, deploy the OIDC provider + deploy role from [`ci-bootstrap/`](../ci-bootstrap/README.md). That template is deliberately kept separate from `serverless.yml` (it's account-bootstrap infrastructure, applied once, not application infrastructure redeployed on every push), and it's generic enough to be the reference for standing up your own CI pipeline against your own — or a client's — AWS account.

**One-time setup, per repo** — the `deploy` job also needs a `SERVERLESS_LICENSE_KEY` repository secret (Settings → Secrets and variables → Actions), generated once from a [serverless.com](https://www.serverless.com/) account — see the Prerequisites note above. Without it, `deploy` fails at the `serverless deploy` step with "You must sign in or use a license key," not at the AWS-credentials step, since v4's own auth check runs before anything AWS-related does.

Every CI deploy also writes the stage's connection details to SSM Parameter Store — both API keys as SecureStrings (`/opencdr-<stage>/api-key`, the original all-scopes key; `/opencdr-<stage>/api-key-mcp`, a separate all-scopes key for the MCP server — see [API key scopes](api-reference.md#api-key-scopes) for why they're two independently-revocable keys rather than one shared) and the API base URL as a plain String (`/opencdr-<stage>/api-url` — not sensitive; it's the same value as the CloudFormation stack's `ServiceEndpoint` output, just persisted so you don't need `describe-stacks` access to find it). Retrieve any of them with:

```bash
aws ssm get-parameter --name /opencdr-dev/api-key --with-decryption \
  --query Parameter.Value --output text

aws ssm get-parameter --name /opencdr-dev/api-key-mcp --with-decryption \
  --query Parameter.Value --output text

aws ssm get-parameter --name /opencdr-dev/api-url \
  --query Parameter.Value --output text
```

Handy for pointing Postman (or any other manual API client) at a deployed stage without hunting through deploy logs — set `x-api-key` to one of the key values and use the URL as the request base. Use `api-key-mcp` when configuring the MCP server (see [API Reference](api-reference.md#mcp-server-default-management-plane)).

And enables CloudFormation stack termination protection automatically as the last step of a successful deploy — see [`docs/stack-protection.md`](stack-protection.md) for that and the weekly drift-detection check that runs alongside it.

## After deploying

1. **Load the bundled detection rules**: `./scripts/load_rules.sh --stage dev` (or `--dry-run` to preview first). See [Detection Rules](detection-rules.md).
2. **Configure at least one notification channel** so alerts actually go somewhere: `python3 scripts/opencdr.py settings set --slack-webhook <url>` or the interactive `python3 scripts/opencdr.py setup` wizard. See [Notifications](notifications.md).
3. **Decide on alarm delivery** (email param, or the Slack SSM parameter) if you want to know when the pipeline itself breaks, not just when it detects something. See [Observability](observability.md).
4. **If you need cross-account IR**, onboard each additional account — see [Incident Response](incident-response.md). Single-account deployments need nothing here.
5. **If your account operates in more than one region**, onboard each additional region: `./scripts/setup_region_forwarding.sh --stage dev --regions <region1>,<region2>`. Without this, activity outside the deployment region never generates a signal. See [Cross-Region Event Forwarding](region-forwarding.md).


## Related pages

- [Architecture](architecture.md) — what actually gets provisioned
- [Security](security.md) — the IAM model behind the per-function roles and the OIDC deploy role
- [Observability](observability.md) — the dashboard/metrics/traces/alarms every deploy includes
- [`ci-bootstrap/README.md`](../ci-bootstrap/README.md) — OIDC role setup in full
- [`docs/stack-protection.md`](stack-protection.md) — termination protection and drift detection
- [Cross-Region Event Forwarding](region-forwarding.md) — onboarding additional regions

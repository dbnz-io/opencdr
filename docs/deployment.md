# Deployment

*How to stand up OpenCDR in an AWS account, and what you get automatically vs. what needs a one-time manual step.*

## Prerequisites

- [Node.js](https://nodejs.org/) >= 18 and [Serverless Framework](https://www.serverless.com/) v3 (`npm install -g serverless`)
- Python 3.12 (matches `provider.runtime` in `serverless.yml`)
- AWS credentials for the target account (`aws configure`, or environment variables, or — for CI — the OIDC role below)
- `jq` (used by the rule-loading and integration-test scripts)
- **CloudTrail enabled** in the target account/region. OpenCDR receives events via EventBridge, and CloudTrail management events are only delivered to EventBridge once a trail is active — without one, `processor` never receives anything and no signals are ever generated. See the root [README](../README.md#cloudtrail-must-be-enabled) for the exact `aws cloudtrail create-trail` commands, including the multi-account/AWS-Organizations variant.

## Manual deploy

```bash
npm install    # installs serverless-python-requirements, serverless-iam-roles-per-function
serverless deploy --stage dev
```

This single command provisions everything in [Architecture](architecture.md): all 7 Lambdas with their own IAM roles, all 7 DynamoDB tables, all 5 SQS queues, both SNS topics, API Gateway with API-key auth, 11 CloudWatch alarms, a monthly cost budget, and the [CloudWatch Dashboard](observability.md). Nothing else needs to run first.

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
| All 7 Lambdas, all tables/queues/topics | Enabling CloudTrail (prerequisite, not part of the stack) |
| The home account's IR role (`OpencdrIrRole`), wired to `responder` | Onboarding *additional* AWS accounts for cross-account IR — see [Incident Response](incident-response.md) |
| CloudWatch Dashboard, custom metrics, X-Ray tracing | Alarm delivery destination (`alarmEmail` param, or the Slack SSM parameter) — see [Observability](observability.md) |
| Cost-allocation tags (`Project`/`Stage`) on every resource, monthly `CostBudget` alert | Enabling Cost Explorer and activating those tags as cost allocation tags in Billing preferences — see [Cost tracking](../README.md#cost-tracking) |
| The receiving side of cross-region event forwarding (`RegionForwarderRole`, bus policy) | Onboarding *additional regions* your account operates in — otherwise CloudTrail/GuardDuty activity outside the deployment region is silently missed. See [Cross-Region Event Forwarding](region-forwarding.md) |
| Stack termination protection (CI only — see below) | Subscribing to the alerts SNS topic if you want email delivery for security alerts too |
| Detection rule *table* and schema | Loading the 19 signal + 4 correlation rules into it (`scripts/load_rules.sh`) |

## CI/CD (GitHub Actions, OIDC)

`.github/workflows/ci.yml` deploys to `dev` automatically on every push to `main`, authenticating via short-lived credentials federated through GitHub's OIDC provider — no long-lived AWS access keys stored in GitHub at all.

Pipeline stages, in order: `validate-rules` → `secrets-scan` / `python-sast` / `sbom` (parallel, non-blocking — findings are visible but don't fail the run) → `test` → `deploy` → `post-deploy-check` → `release`.

`post-deploy-check` is a real integration test against the just-deployed stack, not a smoke test against mocks: it asserts API-key auth actually enforces (valid/invalid key against `/rules` and `/signals`), and fires a synthetic event straight at a dedicated, isolated canary rule to confirm a detection rule can genuinely fire end-to-end. `release` only cuts a version tag once both `deploy` and `post-deploy-check` have succeeded — a release means "confirmed working," not just "the deploy command exited zero."

**One-time setup, per AWS account** — before the `deploy` job can authenticate at all, deploy the OIDC provider + deploy role from [`ci-bootstrap/`](../ci-bootstrap/README.md). That template is deliberately kept separate from `serverless.yml` (it's account-bootstrap infrastructure, applied once, not application infrastructure redeployed on every push), and it's generic enough to be the reference for standing up your own CI pipeline against your own — or a client's — AWS account.

Every CI deploy also writes the stage's real API key to SSM Parameter Store as a SecureString (`/opencdr-<stage>/api-key`) rather than anyone pulling it into a local file — retrieve it with:

```bash
aws ssm get-parameter --name /opencdr-dev/api-key --with-decryption \
  --query Parameter.Value --output text
```

And enables CloudFormation stack termination protection automatically as the last step of a successful deploy — see [`docs/stack-protection.md`](stack-protection.md) for that and the weekly drift-detection check that runs alongside it.

## After deploying

1. **Load the bundled detection rules**: `./scripts/load_rules.sh --stage dev` (or `--dry-run` to preview first). See [Detection Rules](detection-rules.md).
2. **Configure at least one notification channel** so alerts actually go somewhere: `python3 scripts/opencdr.py settings set --slack-webhook <url>` or the interactive `python3 scripts/opencdr.py setup` wizard. See [Notifications](notifications.md).
3. **Decide on alarm delivery** (email param, or the Slack SSM parameter) if you want to know when the pipeline itself breaks, not just when it detects something. See [Observability](observability.md).
4. **If you need cross-account IR**, onboard each additional account — see [Incident Response](incident-response.md). Single-account deployments need nothing here.
5. **If your account operates in more than one region**, onboard each additional region: `./scripts/setup_region_forwarding.sh --stage dev --regions <region1>,<region2>`. Without this, activity outside the deployment region never generates a signal. See [Cross-Region Event Forwarding](region-forwarding.md).

## Promoting to the public repo

This repo (`opencdr-internal`) is where development happens. Released versions are published to the public `dbnz-io/opencdr` repo via a separate, manual, on-demand workflow — clean-slate (no private git history crosses over) and independently versioned from this repo's own. See [`docs/promoting-to-public.md`](promoting-to-public.md).

## Related pages

- [Architecture](architecture.md) — what actually gets provisioned
- [Security](security.md) — the IAM model behind the per-function roles and the OIDC deploy role
- [Observability](observability.md) — the dashboard/metrics/traces/alarms every deploy includes
- [`ci-bootstrap/README.md`](../ci-bootstrap/README.md) — OIDC role setup in full
- [`docs/stack-protection.md`](stack-protection.md) — termination protection and drift detection
- [`docs/promoting-to-public.md`](promoting-to-public.md) — publishing a release to the public repo
- [Cross-Region Event Forwarding](region-forwarding.md) — onboarding additional regions

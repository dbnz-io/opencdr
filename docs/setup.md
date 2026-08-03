# Complete Setup Guide

*Everything involved in going from a clean AWS account to a fully working OpenCDR deployment, in order. Each step links to the page with the full detail — this page is the checklist and the sequence, not a duplicate of the deep reference.*

Not every step applies to every deployment — single-account, single-region setups skip several of these entirely, and that's called out at each step rather than left implicit.

## 1. Prerequisites

- [Node.js](https://nodejs.org/) >= 18, [Serverless Framework](https://www.serverless.com/) v3, Python 3.12 (matches `provider.runtime` in `serverless.yml`)
- AWS credentials for the target account (`aws configure`, environment variables, or CI's OIDC role — see step 9)
- `jq` (used by the rule-loading and integration-test scripts)
- **CloudTrail enabled** in the target account/region — without it, `processor` never receives anything. See the root [README](../README.md#cloudtrail-must-be-enabled) for the exact commands, including the multi-account/AWS-Organizations variant.

```bash
npm install -g serverless
npm install    # installs serverless-python-requirements, serverless-iam-roles-per-function
```

## 2. Deploy the stack

```bash
serverless deploy --stage dev
```

Optional deploy-time parameters, all can be set later without redeploying:

```bash
serverless deploy --stage dev \
  --param="alarmEmail=ops@example.com" \
  --param="alertEmail=security@example.com" \
  --param="monthlyBudgetUsd=50"
```

This provisions everything — all 7 Lambdas, all 7 tables, both SQS queues, both SNS topics, API Gateway, 11 CloudWatch alarms, the dashboard, X-Ray tracing, and the cost budget. Full detail: [Architecture](architecture.md), [Deployment](deployment.md).

## 3. Load the bundled detection rules

```bash
./scripts/load_rules.sh --stage dev
```

19 signal rules + 4 correlation rules. See [Detection Rules](detection-rules.md) for the schema if you want to add your own before or after this step.

## 4. Configure at least one notification channel

Without this, detections happen but nothing tells you. Fastest path — the interactive wizard does steps 3 and 4 together:

```bash
python3 scripts/opencdr.py setup
```

Or configure channels individually:

```bash
python3 scripts/opencdr.py settings set --slack-webhook https://hooks.slack.com/services/...
```

Full channel-by-channel detail (Discord, email, Security Hub, Jira, custom webhook): [Notifications](notifications.md).

## 5. Set up alarm delivery (operational health, separate from security alerts)

`alarmEmail` in step 2 already covers this if you set it. Otherwise, a Slack option that needs no redeploy:

```bash
aws ssm put-parameter --name /opencdr-dev/ops-alerts/slack-webhook --type SecureString --value "<webhook-url>"
```

This is *ops* health (Lambda errors, queue depth) — distinct from the security detections step 4 configures. Full detail: [Observability](observability.md#alarms-exist-automatically--delivery-is-the-one-time-step).

## 6. Enable cost tracking

Two manual AWS-console steps, neither automatable via CloudFormation:

1. Enable Cost Explorer (Billing console → Cost Explorer).
2. Activate the `Project`/`Stage` tags as cost allocation tags (Billing console → Cost allocation tags) — takes up to 24h to start appearing.

```bash
./scripts/cost_report.sh --stage dev
```

Full detail: [Cost tracking](../README.md#cost-tracking).

## 7. Onboard additional regions — only if your account operates in more than one

Skip this for a genuinely single-region account. Otherwise, a fresh deploy is silently blind outside its deployment region:

```bash
./scripts/setup_region_forwarding.sh --stage dev --region eu-west-1
```

Repeat per region, or pass a comma-separated list. Full detail, including exactly which signal rules are affected and why: [Cross-Region Event Forwarding](region-forwarding.md).

## 8. Onboard additional AWS accounts — only if you need cross-account incident response

Skip this for a single-account deployment (it needs zero setup — the home account's IR role is created automatically in step 2). Otherwise, per additional account:

```bash
aws iam create-role --role-name opencdr-dev-ir-role --assume-role-policy-document file:///tmp/trust-policy.json
aws iam put-role-policy --role-name opencdr-dev-ir-role --policy-name opencdr-ir-permissions --policy-document file://docs/ir-role-permissions.json

curl -X POST "$OPENCDR_API_URL/ir-roles" -H "x-api-key: $OPENCDR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"aws_account_id": "<TARGET_ACCOUNT_ID>", "role_arn": "arn:aws:iam::<TARGET_ACCOUNT_ID>:role/opencdr-dev-ir-role"}'
```

Full walkthrough (trust policy, kill-switch, keeping the permissions policy in sync): [`ir-role.md`](ir-role.md).

## 9. Set up CI/CD — optional, recommended for anything beyond a one-off evaluation

```bash
aws cloudformation deploy \
  --template-file ci-bootstrap/oidc-deploy-role.yaml \
  --stack-name opencdr-ci-bootstrap \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    GitHubOrg=<your-github-org> \
    GitHubRepo=<your-repo-name> \
    GitHubBranch=main
```

Then set the resulting role ARN as the `OPENCDR_CI_DEPLOY_ROLE_ARN` repo variable and every push to `main` deploys, verifies, and (once a version is ready) tags a release automatically. Full detail, including the `CreateOidcProvider` flag and what to do if your account already has a GitHub OIDC provider: [`ci-bootstrap/README.md`](../ci-bootstrap/README.md), [Deployment](deployment.md#cicd-github-actions-oidc).

## 10. Verify it actually works end to end

```bash
./scripts/test_deployed.sh --stage dev
```

Fires sample events at the deployed stack and confirms signals are produced. Also worth a manual look: the `DashboardUrl` output from step 2's deploy (Lambda health, queue depth, custom metrics), and confirming a real notification arrives in whichever channel you configured in step 4.

## What this guide doesn't cover

- **Publishing a release of OpenCDR itself** (as opposed to setting up *your own deployment* of it) is a separate, maintainer-facing process — see [`promoting-to-public.md`](promoting-to-public.md). Not something a new deployment needs to think about.
- **Writing your own detection rules** beyond the bundled 23 — see [Detection Rules](detection-rules.md) and [Writing Detection Rules](../README.md#writing-detection-rules).

## Related pages

- [Architecture](architecture.md) — what actually gets provisioned and why
- [Deployment](deployment.md) — the automatic-vs-manual breakdown this guide's steps are drawn from
- [Security](security.md) — the IAM model and known, deliberate limitations

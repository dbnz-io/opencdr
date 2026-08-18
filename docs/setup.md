# Complete Setup Guide

*Everything involved in going from a clean AWS account to a fully working OpenCDR deployment, in order. Each step links to the page with the full detail — this page is the checklist and the sequence, not a duplicate of the deep reference.*

Not every step applies to every deployment — single-account, single-region setups skip several of these entirely, and that's called out at each step rather than left implicit.

## 1. Prerequisites

- [Node.js](https://nodejs.org/) >= 18, [Serverless Framework](https://www.serverless.com/) v4, Python 3.12 (matches `provider.runtime` in `serverless.yml`)
- A Serverless Framework license key (free under $2M annual revenue) — v4 requires CLI authentication for every invocation, see [Deployment](deployment.md#prerequisites)
- AWS credentials for the target account (`aws configure`, environment variables, or CI's OIDC role — see step 9)
- `jq` (used by the rule-loading and integration-test scripts)
- **CloudTrail enabled** in the target account/region — without it, `processor` never receives anything. See the root [README](../README.md#cloudtrail-must-be-enabled) for the exact commands, including the multi-account/AWS-Organizations variant.

```bash
npm install -g serverless
npm install    # installs serverless-python-requirements
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

This provisions everything — all 9 Lambdas, all 7 tables, the S3/Glue/Firehose archival pipeline, all 7 SQS queues, both SNS topics, API Gateway, 16 CloudWatch alarms, the dashboard, X-Ray tracing, and the cost budget. Full detail: [Architecture](architecture.md), [Deployment](deployment.md), [Data Archival](data-archival.md).

## 3. Load the bundled detection rules

```bash
./scripts/load_rules.sh --stage dev
```

24 signal rules + 6 correlation rules (see [dbnz-io/opencdr-detection-rules](https://github.com/dbnz-io/opencdr-detection-rules) for the full list and schema — rule content lives in its own repo, consumed here as a git submodule; `git submodule update --init` first if you cloned without `--recurse-submodules`). See [Detection Rules](detection-rules.md) for how rules are stored and loaded here if you want to add your own before or after this step.

**⚠️ Automated response can take real, destructive action.** Rules load with every `response_module` stripped by default, regardless of `DREDGE_DRY_RUN` — a majority of the 30 bundled rules ship with a `response_module` set (exact, current count in [Response modules](incident-response.md#response-modules), deliberately not repeated here where it can drift). `DREDGE_DRY_RUN` itself now **defaults to live (`false`) in CI** (see [How the responder authorizes itself](incident-response.md#how-the-responder-authorizes-itself)) — so the rule-level strip above is the layer actually protecting a fresh deploy from taking real action, not the dry-run flag. Pass `--with-response-modules` once you've reviewed [Response modules](incident-response.md#response-modules) and actually want them armed.

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

Full detail: [Cost tracking](observability.md#cost-tracking).

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

## 9. Onboard an AWS Organization — only for a multi-account org routing events to one central deployment

Skip this unless you're deploying once in a central security account and want every member account's CloudTrail/GuardDuty events routed there. Different concern from step 8 above — this is about event *ingestion*, not incident-response permissions. Two parts: redeploy the central account with your org ID, then onboard each member account:

```bash
serverless deploy --stage dev --param="orgId=o-XXXXXXXXXX"
./scripts/setup_org_forwarding.sh --stage dev --profiles member-a,member-b
```

Full detail, including exactly why this isn't a single `aws events put-permission --principal "*"` call: [Org-Wide Account Forwarding](org-forwarding.md).

## 10. Set up CI/CD — optional, recommended for anything beyond a one-off evaluation

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

## 11. Verify it actually works end to end

```bash
./scripts/test_deployed.sh --stage dev
```

Fires sample events at the deployed stack and confirms signals are produced. Also worth a manual look: the `DashboardUrl` output from step 2's deploy (Lambda health, queue depth, custom metrics), and confirming a real notification arrives in whichever channel you configured in step 4.

## What this guide doesn't cover

- **Writing your own detection rules** beyond the bundled 24 — see [dbnz-io/opencdr-detection-rules](https://github.com/dbnz-io/opencdr-detection-rules) for the schema.

## Related pages

- [Architecture](architecture.md) — what actually gets provisioned and why
- [Deployment](deployment.md) — the automatic-vs-manual breakdown this guide's steps are drawn from
- [Security](security.md) — the IAM model and known, deliberate limitations

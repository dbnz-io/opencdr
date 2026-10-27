# Complete Setup Guide

*Everything involved in going from a clean AWS account to a fully working OpenCDR deployment, in order. Each step links to the page with the full detail — this page is the checklist and the sequence, not a duplicate of the deep reference.*

Not every step applies to every deployment — single-account, single-region setups skip several of these entirely, and that's called out at each step rather than left implicit.

## 1. Prerequisites

- [Node.js](https://nodejs.org/) >= 18, [Serverless Framework](https://www.serverless.com/) v4, Python 3.12 (matches `provider.runtime` in `serverless.yml`), and Docker for packaging Lambda-compatible Linux native dependencies
- A Serverless Framework license key (free under $2M annual revenue) — v4 requires CLI authentication for every invocation, see [Deployment](deployment.md#prerequisites)
- AWS credentials for the target account (`aws configure`, environment variables, or CI's OIDC role — see step 9)
- `jq` (used by the rule-loading and integration-test scripts)
- **CloudTrail enabled** in the target account/region — without it, `processor` never receives anything. See the root [README](../README.md#cloudtrail-must-be-enabled) for the exact commands, including the multi-account/AWS-Organizations variant.

```bash
npm install -g serverless
npm install    # installs the locked Serverless build toolchain
```

## 2. Deploy the stack

```bash
serverless deploy --stage dev
```

Optional deploy-time parameters, all can be changed on a later redeploy:

```bash
serverless deploy --stage dev \
  --param="alarmEmail=ops@example.com" \
  --param="alertEmail=security@example.com" \
  --param="monthlyBudgetUsd=50" \
  --param="archiveEnabled=false" \
  --param="securityProfile=hardened"
```

This provisions everything — all 11 Lambdas, all 11 tables, the managed S3/Glue/Firehose archival resources, all 11 SQS queues, both SNS topics, API Gateway, 21 CloudWatch alarms, the dashboard, and the cost budget. Archival and X-Ray are opt-in; `archiveEnabled=true` activates the three DynamoDB event mappings while the pipeline resources remain managed but idle by default. DynamoDB TTL remains active, so records written while archival is off expire without an OpenCDR archive and are not backfilled. `securityProfile=hardened` adds reversible protection only to resources OpenCDR owns; see [Resource security profiles](security-profiles.md). Full detail: [Architecture](architecture.md), [Deployment](deployment.md), [Data Archival](data-archival.md).

## 3. Load the bundled detection rules

```bash
./scripts/load_rules.sh --stage dev
```

24 signal rules + 6 correlation rules (see [dbnz-io/opencdr-detection-rules](https://github.com/dbnz-io/opencdr-detection-rules) for the full list and schema — rule content lives in its own repo, consumed here as a git submodule; `git submodule update --init` first if you cloned without `--recurse-submodules`). See [Detection Rules](detection-rules.md) for how rules are stored and loaded here if you want to add your own before or after this step.

Reusable lists are intentionally not loaded with rule releases. Create only the lists your rules
reference, replacing example values with your own:

```bash
python3 scripts/opencdr.py lists create admin-users \
  --matcher exact --value-type iam_user \
  --description "Approved administrative users" \
  --values alice-admin break-glass-admin

python3 scripts/opencdr.py lists create corporate-networks \
  --matcher cidr --value-type cidr \
  --values 192.0.2.0/24 2001:db8:100::/48
```

The rules repository's [`lists/`](https://github.com/dbnz-io/opencdr-detection-rules/tree/main/lists)
folder contains examples for both matchers and every supported value type.

**⚠️ Automated response can take real, destructive action.** Rules load with `response_module` and `response_actions` stripped by default, and CI deploys `DREDGE_DRY_RUN=true` unless a manual workflow explicitly disables it. Pass `--with-response-modules` and choose live execution only once you've reviewed [Response modules](incident-response.md#response-modules) and actually want them armed.

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

## 9. Repeat Core deployment for additional accounts

OpenCDR Core's deployment unit is one AWS account. For an AWS Organization, repeat steps 1–8 in each protected account: deploy one home-region Core and add account-local collectors for that account's enabled regions. Organization discovery, coordinated rollout, drift, and fleet health are deliberately a separate control-plane concern; see [OpenCDR Core](core.md) and the [management contract](management-contract.md).

The previous central-ingestion workflow remains documented in [Org-Wide Account Forwarding](org-forwarding.md) for compatibility with existing installations, but is not recommended for new Core deployments.

## 10. Set up CI/CD — optional, recommended for managed production change

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

## 12. Record customer production security decisions

Steps 1–11 produce and validate a working OpenCDR deployment. OpenCDR Core is
production-ready within its documented boundary; it does not choose the customer's
identity boundary, network restriction, retention policy, recovery objectives, or
approval process.

For a production stage, review the [security shared-responsibility
model](shared-responsibility.md) and record whether the customer will implement,
accept, or mark as not applicable each environment-specific control. Examples
include:

- whether the supplied API-key boundary is sufficient or IAM/SigV4/OIDC/JWT is needed;
- whether API Gateway needs principal, resource-policy, WAF, or private-network restrictions;
- whether each state class needs PITR, retention, or an accepted-loss decision;
- whether archive-bucket versioning or additional retention is appropriate;
- whether formal RPO/RTO and isolated restore exercises are required; and
- whether the customer's production process requires protected promotion of the exact staging artifact.

These controls belong to the AWS account owner/deployer because their correct
settings and costs depend on the customer's identities, network, legal retention,
recovery targets, and production account boundary. They are recommendations and
risk decisions, not unresolved OpenCDR defects.

## What this guide doesn't cover

- **Writing your own detection rules** beyond the bundled 24 — see [dbnz-io/opencdr-detection-rules](https://github.com/dbnz-io/opencdr-detection-rules) for the schema.

## Related pages

- [Architecture](architecture.md) — what actually gets provisioned and why
- [Deployment](deployment.md) — the automatic-vs-manual breakdown this guide's steps are drawn from
- [Security](security.md) — the IAM model and known, deliberate limitations
- [Security shared-responsibility model](shared-responsibility.md) — authoritative OpenCDR/customer security boundary
- [Customer production deployment decisions](production-deployment.md) — optional controls, tradeoffs, and installation evidence

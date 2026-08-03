# ci-bootstrap

A GitHub Actions OIDC identity provider + IAM deploy role for OpenCDR,
kept as a standalone CloudFormation template deliberately **separate**
from the main `serverless.yml` one directory up.

## Why this is separate

`serverless.yml` describes the OpenCDR application stack — the thing that
gets deployed *into* an AWS account. This folder describes how CI gets
*permission* to run that deploy in the first place: an OIDC trust
relationship and an IAM role scoped to one specific GitHub repo/branch.
That's account-bootstrap infrastructure, not application infrastructure —
it's applied once per account (yours, or a client's), not redeployed
alongside the app on every change, and it's self-contained enough to move
into its own repo later without dragging the rest of OpenCDR with it.

No dependency on the Serverless Framework, its plugins, or the Python app
— just the AWS CLI and a CloudFormation template.

## One-time setup

1. Check whether this AWS account already has a GitHub Actions OIDC
   provider:

   ```bash
   aws iam list-open-id-connect-providers --profile opencdr-dev
   ```

   If `token.actions.githubusercontent.com` is **not** listed, leave
   `CreateOidcProvider` at its default (`true`). If it **is** already
   there, pass `CreateOidcProvider=false` below — CloudFormation fails if
   you try to create a second provider for the same URL.

2. Deploy the template:

   ```bash
   aws cloudformation deploy \
     --template-file oidc-deploy-role.yaml \
     --stack-name opencdr-ci-bootstrap \
     --capabilities CAPABILITY_NAMED_IAM \
     --profile opencdr-dev \
     --parameter-overrides \
       GitHubOrg=dbnz-io \
       GitHubRepo=opencdr-internal \
       GitHubBranch=main \
       CreateOidcProvider=true
   ```

3. Grab the role ARN from the stack output:

   ```bash
   aws cloudformation describe-stacks \
     --stack-name opencdr-ci-bootstrap \
     --profile opencdr-dev \
     --query "Stacks[0].Outputs[?OutputKey=='RoleArn'].OutputValue" \
     --output text
   ```

4. In the GitHub repo, add it as a **repository variable** (Settings →
   Secrets and variables → Actions → Variables), not a secret — a role
   ARN isn't sensitive, only the short-lived credentials minted from it
   are, and those never leave the workflow run:

   - Name: `OPENCDR_CI_DEPLOY_ROLE_ARN`
   - Value: the ARN from step 3

Once that variable is set, the `deploy` job in
`.github/workflows/ci.yml` starts working on the next push to `main` —
nothing else to wire up.

## Reusing this for a client's own account

This template is generic (parameterized on org/repo/branch/service name),
so it's also the reference adopters can copy to set up their own
OIDC-based deploy pipeline instead of hand-rolling long-lived AWS keys.
Same three steps above, run against the client's account and their fork's
repo/branch.

## Permissions granted

Scoped to the `${ServiceName}-*` resource-naming convention already used
throughout `serverless.yml` everywhere the relevant AWS service supports
resource-level ARN scoping (Lambda, DynamoDB, SQS, SNS, IAM roles,
CloudWatch Logs/Alarms). A few services don't support that level of
scoping and get a narrower-than-full-access-but-still-broad grant instead
— the deployment S3 bucket (name includes a random suffix, scoped by
prefix instead of exact name) and API Gateway (its resource ARN format
doesn't expose the REST API's own name until after creation).

**This is a first pass, not a battle-tested policy** — assembled by
cross-checking every AWS resource type `serverless.yml` actually creates,
but never run against real AWS (no credentials available in the
environment that built it). Expect the first real `serverless deploy`
through this role to surface one or two missing permissions; add them to
`oidc-deploy-role.yaml`'s policy statements and redeploy this stack
(`aws cloudformation deploy ...` again, same command as step 2 — it's an
update, not a fresh create).

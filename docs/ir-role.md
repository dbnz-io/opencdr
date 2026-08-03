# Incident-response (IR) roles for the responder Lambda

The `responder` Lambda (`src/handlers/responder.py`) executes destructive
containment actions — disabling IAM users/roles/keys, blocking public S3
access, isolating EC2 instances — via the `dredge` library (a pinned
dependency, `dredge.aws_ir.response` — see `requirements.txt`, no longer
vendored as of Phase 2).

The responder's own Lambda execution role is deliberately given **no**
IAM/EC2/S3/S3control permissions (see the `responder` block in
`serverless.yml`). Instead it assumes a separate IAM role for every action,
and every response module runs against that assumed role's session. This
keeps destructive AWS permissions off the Lambda's own credentials: a
compromised responder invocation can't act beyond `sts:AssumeRole` on its
own — and that `sts:AssumeRole` grant only covers roles named
`${self:service}-${self:provider.stage}-ir-role` (e.g.
`opencdr-dev-ir-role`) in *any* account, not a blanket grant.

## Single-account: works out of the box

`serverless.yml` auto-creates this role for the account you deploy
OpenCDR into (the CFN resource `OpencdrIrRole`), with the trust policy and
permissions already wired up — the same policy documented in
[`ir-role-permissions.json`](ir-role-permissions.json). The responder's
`OPENCDR_IR_ROLE_ARN` environment variable is auto-wired to it. There is
**no manual role-creation step** for this case:

```bash
serverless deploy --stage dev
```

That's it — the home account is ready to receive automated responses.

Override `OPENCDR_IR_ROLE_ARN` at deploy time if you'd rather point the
default at a role you manage yourself instead of the auto-created one:

```bash
export OPENCDR_IR_ROLE_ARN=arn:aws:iam::<ACCOUNT_ID>:role/some-other-role
serverless deploy --stage dev
```

## Multi-account: onboard each additional account

OpenCDR can act across multiple AWS accounts — a detection carries its
originating account (`cloud_account_id`), and the responder looks up which
role to assume for that account in the `irAccountRolesTable` DynamoDB table
(`src/handlers/responder.py` `_resolve_role_arn`) before falling back to
`OPENCDR_IR_ROLE_ARN`. A `serverless deploy` in one account/region can't
provision an IAM role in a *different* AWS account, so additional accounts
need two manual steps:

**1. Create the role in the target account.** Trust policy — allow the
responder Lambda's own execution role to assume it (find the exact
principal ARN with `aws lambda get-function-configuration --function-name
opencdr-<stage>-responder --query Role` against the OpenCDR account, or use
the pattern
`${self:service}-${self:provider.stage}-responder-${self:provider.region}-lambdaRole`):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::<OPENCDR_ACCOUNT_ID>:role/opencdr-<stage>-responder-<region>-lambdaRole"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

```bash
aws iam create-role \
  --role-name opencdr-<stage>-ir-role \
  --assume-role-policy-document file:///tmp/trust-policy.json

aws iam put-role-policy \
  --role-name opencdr-<stage>-ir-role \
  --policy-name opencdr-ir-permissions \
  --policy-document file://docs/ir-role-permissions.json
```

The role name **must** be `${self:service}-${self:provider.stage}-ir-role`
(e.g. `opencdr-dev-ir-role`) — that's the naming convention the responder's
own `sts:AssumeRole` grant is scoped to. A role under any other name will
never be assumable by responder, regardless of what's in the table below.

**2. Add a row to `irAccountRolesTable`**, via the API (`POST /ir-roles`):

```bash
curl -X POST "$OPENCDR_API_URL/ir-roles" \
  -H "x-api-key: $OPENCDR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
        "aws_account_id": "<TARGET_ACCOUNT_ID>",
        "role_arn": "arn:aws:iam::<TARGET_ACCOUNT_ID>:role/opencdr-dev-ir-role"
      }'
```

That account's detections now resolve to that role. To temporarily stop
responder from acting in an account without deleting the mapping, flip it
off instead of deleting the row — this is a real kill switch, it does
*not* fall back to `OPENCDR_IR_ROLE_ARN`:

```bash
curl -X PUT "$OPENCDR_API_URL/ir-roles/<TARGET_ACCOUNT_ID>" \
  -H "x-api-key: $OPENCDR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"role_arn": "arn:aws:iam::<TARGET_ACCOUNT_ID>:role/opencdr-dev-ir-role", "enabled": false}'
```

Full CRUD: `GET /ir-roles` (list), `GET|PUT|DELETE /ir-roles/{aws_account_id}`.

**Resolution order, per detection** (`_resolve_role_arn`):
1. Account has an enabled row in `irAccountRolesTable` → that role.
2. Account has a row but it's `"enabled": false` → no role at all (skip the
   action, logged as `IR_ACCOUNT_DISABLED`) — does not fall back to (3).
3. No row for the account, or the account couldn't be determined at all →
   `OPENCDR_IR_ROLE_ARN`.

Resolved role ARNs are cached per account for
`RESPONDER_ROLE_CACHE_TTL_SECONDS` (default 60s), and assumed-role
credentials are cached per role for close to their session lifetime — so
onboarding/disabling an account takes effect within about a minute, not
instantly, and normal operation isn't calling `sts:AssumeRole` on every
single detection.

**Note:** a write to `irAccountRolesTable` directly controls which AWS
role responder may assume in which account — treat access to `POST/PUT
/ir-roles` as at least as sensitive as the settings endpoint's integration
secrets.

## Keeping the permissions policy in sync

`docs/ir-role-permissions.json` and the `OpencdrIrRole` CFN resource in
`serverless.yml` (the home-account role) both hardcode the same 6 IAM
statements — CloudFormation has no clean way to include an external JSON
policy file, so this is duplicated by necessity. If you change what the 8
response modules in `dredge.aws_ir.response` can do, update both.

## Rate limiting

The responder also enforces a circuit breaker on destructive actions
(`RESPONDER_RATE_LIMIT_WINDOW_MINUTES` / `RESPONDER_RATE_LIMIT_MAX_ACTIONS`,
default 20 actions per 5 minutes, account-agnostic) — see `serverless.yml`'s
`responder` `environment:` block to override the defaults.

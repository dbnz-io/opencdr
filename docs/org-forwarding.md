# Org-Wide Account Forwarding

*How to route every member account's CloudTrail/GuardDuty events into a central security account running OpenCDR — without granting `events:PutEvents` to anyone who happens to have a credential in the org.*

## The problem this replaces

The original org-wide deployment recipe was a single command run once, in the central security account:

```bash
aws events put-permission \
  --action events:PutEvents \
  --principal "*" \
  --statement-id AllowOrgAccounts \
  --condition '{"Type":"StringEquals","Key":"aws:PrincipalOrgID","Value":"o-XXXXXXXXXX"}'
```

That grants `events:PutEvents` on the central bus to **any principal anywhere in the organization** — not just the intended per-account forwarding mechanism. A compromised Lambda, an over-permissioned application role, or an insider in *any* member account could call `PutEvents` directly with a hand-crafted, CloudTrail-shaped event, and `processor` would treat it exactly like a real one — no forwarding rule, no local EventBridge match required first.

This isn't hypothetical once you consider what a forged event can do: it can carry whatever `requestParameters` the forger wants (a `userName`, an `instanceId`, a `bucketName`) and, if it matches a rule with a `response_module`, direct real automated response at a target of their choosing.

## The fix: a scoped role per member account, not a blanket org-wide grant

Same shape as [cross-region forwarding](region-forwarding.md)'s `RegionForwarderRole` — a role only `events.amazonaws.com` can assume, so no human or application credential can call it directly — extended to work across account boundaries. The one real difference: IAM roles are account-scoped, so unlike region-forwarding's single role reused across every region in the same account, **org-forwarding needs its own role provisioned in every member account**.

```
Member Account A                    Central Security Account
  CloudTrail / GuardDuty              CloudTrail / GuardDuty (own)
        │                                    │
        ▼                                    ▼
  default event bus                   default event bus ◄── processor Lambda
        │                                    ▲
        │  AccountForwarderRole              │  OrgForwarderBusPolicy only
        │  (only events.amazonaws.com        │  trusts principals matching
        │   can assume it)                   │  arn:...role/opencdr-<stage>-
        └────────── forward ─────────────────┘  account-forwarder-role
```

## One-time setup

### 1. Enable an organization trail

In the management account — this creates a CloudTrail that covers all member accounts automatically:

```bash
aws cloudtrail create-trail \
  --name org-trail \
  --s3-bucket-name <your-log-bucket> \
  --is-organization-trail \
  --is-multi-region-trail
aws cloudtrail start-logging --name org-trail
```

### 2. Central security account: deploy with `orgId` set

```bash
serverless deploy --stage dev --param="orgId=o-XXXXXXXXXX"
```

This creates `OrgForwarderBusPolicy` — an `AWS::Events::EventBusPolicy` that only exists when `orgId` is non-empty, trusting `events:PutEvents` only from principals that are **both** in your org (`aws:PrincipalOrgID`) **and** whose ARN matches `arn:aws:iam::*:role/opencdr-<stage>-account-forwarder-role` (`aws:PrincipalArn`, `StringLike`). Deploying without `orgId` is exactly today's single-account behavior — this is fully opt-in.

### 3. Each member account: onboard via the script

```bash
# One account:
./scripts/setup_org_forwarding.sh --stage dev --profile member-a

# Several at once:
./scripts/setup_org_forwarding.sh --stage dev --profiles member-a,member-b,member-c

# Central account not your default AWS CLI profile:
./scripts/setup_org_forwarding.sh --stage dev --central-profile security-account --profiles member-a,member-b

# Preview without deploying anything:
./scripts/setup_org_forwarding.sh --stage dev --profiles member-a --dry-run
```

Each named profile must already be configured (`aws configure --profile <name>`, or however your org's SSO issues per-account credentials) — this script doesn't create profiles, only uses them. `--profile` (singular) and `--profiles` (comma-separated) are interchangeable, same convenience as [`setup_region_forwarding.sh`](region-forwarding.md).

The script reads `DefaultEventBusArn` from the central account's stack outputs (using the central account's own credentials — default profile, or `--central-profile`), then deploys [`org-forwarding/account-event-forwarder.yaml`](../org-forwarding/account-event-forwarder.yaml) independently into each target member account. That template creates:

- **`AccountForwarderRole`** — trusted only by `events.amazonaws.com`, scoped to `events:PutEvents` on the central bus. Named exactly `opencdr-<stage>-account-forwarder-role` — this isn't just a convention, it's the literal string `OrgForwarderBusPolicy` checks for.
- **`ForwardingRule`** — an `AWS::Events::Rule` on the member account's own default bus, matching the identical event pattern `processor`'s own rule uses, targeting the central bus via that role.

## Removing a member account

```bash
./scripts/setup_org_forwarding.sh --stage dev --profile member-a --remove
```

Deletes that account's forwarder stack (waited on to confirm it actually completes). Safe against an account never onboarded — `DeleteStack` is idempotent. Doesn't touch or require the central stack at all, same as region-forwarding's `--remove`.

## Failures are per-account, not all-or-nothing

A missing/misconfigured profile, an SCP blocking IAM role creation or CloudFormation in a given member account, or an account you simply don't have access to yet — all look like a normal per-account failure here, not a reason to abort onboarding the rest. `setup_org_forwarding.sh` acts on each profile independently and prints a full succeeded/failed/skipped summary at the end, same guarantee `setup_region_forwarding.sh` already gives for regions.

## Keeping this in sync

The event pattern is duplicated in three places now — `processor`'s rule in `serverless.yml`, `region-forwarding/cross-region-forwarder.yaml`, and `org-forwarding/account-event-forwarder.yaml` — because each is deployed by a different mechanism to a different trust boundary. **Adding a new event source to one and not the others silently reintroduces a blind spot** for every onboarded region or member account. All three files carry a comment pointing at this reminder.

## Related pages

- [`region-forwarding.md`](region-forwarding.md) — the same "can't provision infrastructure somewhere else from here" problem, one region instead of one account; `AccountForwarderRole` mirrors `RegionForwarderRole`'s design directly
- [`ir-role.md`](ir-role.md) — onboarding additional accounts for cross-account *incident response* (a different concern from event *ingestion*, covered here)
- [Security](security.md) — least-privilege IAM model this fits into
- [Architecture](architecture.md) — where `processor`'s own rule fits in the pipeline

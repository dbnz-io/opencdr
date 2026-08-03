# Cross-Region Event Forwarding

*Why OpenCDR is blind outside its deployment region by default, and how to fix that.*

## The problem

`processor`'s EventBridge rule (`serverless.yml`) only exists on the default event bus in the region OpenCDR is deployed to. CloudTrail delivers an event to the default bus in **whichever region the API call actually happened in** — this is true even for a multi-region trail; a multi-region trail changes where log *files* are aggregated (S3), not which region's bus receives the real-time EventBridge notification. GuardDuty is the same story: detectors are inherently per-region, and each region's findings publish to that region's own bus.

The one exception is global services — IAM, STS, Route53, CloudFront, Organizations — whose API calls are always recorded as `us-east-1` events regardless of where the call was made. That's why signal rules `001`–`010` (console login, root account, IAM/access-key activity) keep working across regions **if** you deployed to `us-east-1` — but stop working there too if you deployed anywhere else.

Everything else — `011` (security groups), every GuardDuty finding, `013`–`019` (Config, Security Hub, Secrets Manager, SSM, S3, RDS) — is silently blind in every region except the deployment region, for any account operating in more than one. This isn't an edge case; multi-region AWS usage is the norm.

## The fix: cross-region forwarding, opt-in per region

Same shape as [multi-account IR role onboarding](ir-role.md): a `serverless deploy` in the home region can't provision an EventBridge rule in a different region, so each additional region you want covered needs a small, separate one-time setup, applied via `scripts/setup_region_forwarding.sh`, not automatically.

```
Region A (e.g. eu-west-1)          Home region (deployment region)
  CloudTrail / GuardDuty              CloudTrail / GuardDuty
        │                                    │
        ▼                                    ▼
  default event bus ──forward──────────► default event bus
  (region-forwarding/                        │
   cross-region-forwarder.yaml)         processor Lambda
```

### One-time setup, per additional region

```bash
# Deploy the home region's stack first if you haven't (it now exposes the
# outputs the per-region forwarder needs):
serverless deploy --stage dev

# Onboard a single region:
./scripts/setup_region_forwarding.sh --stage dev --region eu-west-1

# Onboard several at once:
./scripts/setup_region_forwarding.sh --stage dev --regions eu-west-1,ap-southeast-1

# Preview without deploying anything:
./scripts/setup_region_forwarding.sh --stage dev --regions eu-west-1 --dry-run
```

`--region` (singular, one value) and `--regions` (comma-separated) are interchangeable — `--region` exists purely as a convenience for the common case of onboarding just one region at a time, without needing to think about list syntax.

The script reads `DefaultEventBusArn` and `RegionForwarderRoleArn` from the home region's stack outputs, then deploys `region-forwarding/cross-region-forwarder.yaml` — a small standalone CloudFormation template (no Serverless Framework dependency, same reasoning as [`ci-bootstrap/`](../ci-bootstrap/README.md)) — independently in each target region. That template creates one `AWS::Events::Rule` on the target region's own default bus, mirroring `processor`'s event pattern, targeting the home region's bus.

### Removing a region

```bash
./scripts/setup_region_forwarding.sh --stage dev --region eu-west-1 --remove
./scripts/setup_region_forwarding.sh --stage dev --regions eu-west-1,ap-southeast-1 --remove
```

Deletes that region's forwarding stack (`aws cloudformation delete-stack`, waited on to confirm it actually completes, not just that the delete call was accepted). Safe to run against a region that was never onboarded — CloudFormation's `DeleteStack` is idempotent, so this is a no-op rather than an error. `--remove` doesn't touch or require the home region's stack at all, unlike onboarding — there's nothing to read outputs from for a deletion.

### Failures are per-region, not all-or-nothing

An AWS Control Tower or Service Control Policy setup that restricts the account to an approved region list will legitimately deny CloudFormation/EventBridge calls in blocked regions — this is expected, not a bug. `setup_region_forwarding.sh` deploys each region independently and continues past a failure rather than aborting the whole run, printing a full succeeded/failed/skipped summary at the end. Verified directly (not just claimed): a mock run with one region simulating an `AccessDeniedException` confirmed the other regions still deploy and the script exits `0` on partial success.

### What's created

**Home region** (part of `serverless.yml`, deployed with everything else):
- `RegionForwarderRole` — an IAM role only `events.amazonaws.com` can assume, scoped to `events:PutEvents` on this region's own default bus. Nothing else.
- `RegionForwarderBusPolicy` — an `AWS::Events::EventBusPolicy` on the default bus granting that specific role (and only that role) permission to call `PutEvents` here. Required even for same-account cross-region delivery — same-account access to another region's bus isn't implicit the way, say, same-account S3 access often is.

**Each additional region** (`region-forwarding/cross-region-forwarder.yaml`, applied independently):
- One `AWS::Events::Rule` on that region's own default bus, matching the identical event pattern `processor`'s rule uses, targeting the home region's bus via the role above.

## Keeping this in sync

The event pattern is duplicated in two places — `processor`'s rule in `serverless.yml` and `region-forwarding/cross-region-forwarder.yaml` — because they're deployed by two different mechanisms to two different regions. **Adding a new event source to one and not the other silently reintroduces a blind spot** for every onboarded additional region. Both files have a comment pointing at this page as the reminder.

## Related pages

- [Architecture](architecture.md) — where `processor`'s own rule fits in the pipeline
- [`ir-role.md`](ir-role.md) — the multi-account version of the same "can't provision infrastructure somewhere else from here" problem
- [`ci-bootstrap/README.md`](../ci-bootstrap/README.md) — the CI deploy role's own `events:*` permissions, added alongside this
- [Security](security.md) — least-privilege IAM model this fits into

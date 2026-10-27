# OpenCDR resource security profiles

OpenCDR has two resource-protection profiles: `standard` (the default) and
`hardened`. The profile only changes resources deployed and owned by this stack.
It does not change API authentication or exposure, activate product features, or
configure account-level services.

Both profiles are supported for production. `standard` is the secure baseline;
`hardened` is an opt-in cost/operability tradeoff for customers that want stronger
deletion resistance. Controls outside the profile are customer-owned choices under
the [security shared-responsibility model](shared-responsibility.md), not missing
hardening bugs.

## What is always enabled

Both profiles keep the secure baseline: least-privilege per-function IAM roles,
encrypted DynamoDB/S3/SQS storage, S3 public-access blocking and bucket-owner
enforcement, TLS-only S3 access, bounded retries and DLQs, package credential
exclusions, and CloudWatch log retention. These are not feature flags because an
insecure alternative is not supported.

## What hardened changes

`hardened` adds reversible deletion resistance to the existing resource graph:

- `DeletionProtectionEnabled: true` on every OpenCDR DynamoDB table;
- `DeletionPolicy: Retain` and `UpdateReplacePolicy: Retain` on all OpenCDR
  DynamoDB tables and S3 buckets;
- `RedriveAllowPolicy: byQueue` on the four named application DLQs, restricted
  to their intended source queues. The older ingestion queue has a generated
  physical name; adding the reverse reference would create a CloudFormation
  dependency cycle, while naming it now would replace a live queue.

The profile creates no new service or resource type. DynamoDB deletion protection
does not add an AWS charge. Retained resources continue to incur their normal
storage charges after removal from a stack, which is the principal cost and
operational tradeoff.

## Customer-owned controls outside the profile

The customer/deployer remains responsible for API authentication and network
exposure, CloudTrail and GuardDuty, backups and recovery objectives, Object Lock,
customer-managed KMS keys, WAF/VPC endpoints, AWS Config/Security Hub, SCPs,
permission boundaries, and production promotion policy. The profile does not
claim to harden the surrounding AWS account.

These controls can add AWS charges, client migration, retained-resource cleanup,
key-management dependencies, or irreversible retention constraints. OpenCDR
therefore documents them without enabling them unconditionally.

## Deploying

Standard is the default:

```bash
serverless deploy --stage dev
```

Select hardened explicitly:

```bash
./scripts/check_security_profile_transition.sh \
  --stage prod --target hardened --region us-east-1

serverless deploy --stage prod \
  --param="securityProfile=hardened"
```

The transition check reads the current stack's `CoreSecurityProfile` output. A
stack deployed before profiles existed is treated as `standard`. The internal CI
workflow performs this check automatically and verifies the live DynamoDB
deletion-protection state after deployment.

`GET /status` and the `CoreSecurityProfile` stack output report the active profile.
They expose only `standard` or `hardened`, never customer-sensitive policy input.

Feature flags are independent. For example:

```bash
serverless deploy --stage prod \
  --param="securityProfile=hardened" \
  --param="archiveEnabled=false" \
  --param="xrayEnabled=false"
```

## Changing an existing deployment

`standard` to `hardened` is an in-place stack update. It does not replace tables
or buckets.

Reducing a deployed stack from `hardened` to `standard` disables DynamoDB deletion
protection and changes CloudFormation's policy for future deletion/replacement.
Because that is a protection downgrade, the transition guard rejects it unless
the operator explicitly acknowledges it after reviewing the change set:

```bash
./scripts/check_security_profile_transition.sh \
  --stage prod --target standard --region us-east-1 --allow-downgrade

serverless deploy --stage prod \
  --param="securityProfile=standard"
```

Resources already retained and removed from CloudFormation are not automatically
reattached or deleted by changing the profile. They require an intentional import
or cleanup procedure.

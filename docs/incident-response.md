# Incident Response

*What the `responder` Lambda can do automatically, how it authorizes itself, and the safety controls around it.*

## Response modules

Set `response_module` on any detection rule to trigger an automated action when it fires. Eight modules exist, registered in `RESPONSE_MODULE_HANDLERS` in `src/handlers/responder.py`:

| Module | Action |
|---|---|
| `disable_access_key` | Disable a specific IAM access key |
| `disable_user` | Disable all IAM access keys for the actor |
| `delete_user` | Delete the IAM user |
| `disable_role` | Attach a deny-all inline policy to the role |
| `block_s3_public_access` | Enable account-level S3 public access block |
| `block_s3_bucket_public_access` | Block public access on a specific bucket |
| `block_s3_object_public_access` | Block public access on a specific object |
| `isolate_ec2_instances` | Replace instance security groups with an isolation group |

Each module runs through [`dredge`](https://github.com/dbnz-io/dredge) (a pinned dependency, `dredge.aws_ir.response`), not against `responder`'s own credentials — see below.

Set `DREDGE_DRY_RUN=true` to simulate every IR action without making changes — useful for validating a new correlation rule's `response_module` before trusting it live.

## Remediation notifications

A successful action doesn't just log and emit a metric — `responder` also queues a second, notifications-only outbox item (`type: remediation_success`) distinct from the alert that triggered it, so "this was remediated" is as visible as "this was detected" was. Best-effort: a failure to queue this notification is logged but never makes an already-succeeded action look failed.

`notifier` routes this type to green-styled Slack/Discord/email builders rather than the alert ones. Security Hub, Jira, and the custom webhook channel don't support this notification type yet — those builders assume the full alert shape (severity, primary signal, playbook) this item doesn't have, so they're explicitly skipped for it rather than fed a shape they don't expect. See [Notifications](notifications.md#remediation-success-notifications) for the channel-level detail.

Only successful actions notify this way today — a failed action is still visible only in CloudWatch logs and the `ResponderActionsExecuted` metric (see [Observability](observability.md)), not as its own notification.

## How the responder authorizes itself

`responder`'s own Lambda execution role has **no** destructive AWS permissions — no IAM, no EC2, no S3/S3control grants. The only thing it can do on its own credentials is `sts:AssumeRole`, and only on roles named `${service}-${stage}-ir-role` (e.g. `opencdr-dev-ir-role`) in *any* AWS account — not a blanket grant on every role in every account. Every actual response module runs against the temporary credentials returned by that assumed role, not `responder`'s own.

Which role gets assumed is resolved **per detection**, from the AWS account the detection came from (`_resolve_role_arn` in `responder.py`):

1. That account has an **enabled** row in the `ir-account-roles-table` DynamoDB table → assume that row's `role_arn`.
2. That account has a row but it's **disabled** → skip the action entirely (logged as `IR_ACCOUNT_DISABLED`) — does **not** fall back to (3). This is a real kill switch.
3. No row for the account, or the account couldn't be determined at all → `OPENCDR_IR_ROLE_ARN`.

Resolved role ARNs are cached per account for `RESPONDER_ROLE_CACHE_TTL_SECONDS` (default 60s); assumed-role credentials are cached per role for close to their session lifetime. Onboarding or disabling an account takes effect within about a minute, not instantly — `responder` isn't calling `sts:AssumeRole` on every single detection.

## Single-account: zero setup

`serverless.yml` auto-creates the home account's IR role (`OpencdrIrRole`) with the trust policy and permissions already wired, and auto-wires `OPENCDR_IR_ROLE_ARN` to it. `serverless deploy` alone is enough — there's no manual `aws iam create-role` step for the account you deploy into.

## Multi-account: onboard each additional account

A `serverless deploy` in one account can't provision an IAM role in a *different* AWS account, so cross-account IR needs two manual steps per additional account — creating the role there by hand (must be named exactly `opencdr-<stage>-ir-role`) and adding a row via `POST /ir-roles`. The full walkthrough — trust policy example, the exact `iam create-role`/`put-role-policy` commands, the kill-switch API call, and keeping the IAM permissions policy in sync with what the 8 response modules actually need — is in [`docs/ir-role.md`](ir-role.md). This page covers the *behavior*; that one covers the *setup*.

## Rate limiting

Destructive actions are capped by a rolling-window circuit breaker: `RESPONDER_RATE_LIMIT_MAX_ACTIONS` per `RESPONDER_RATE_LIMIT_WINDOW_MINUTES` (default 20 actions per 5 minutes, account-agnostic — the cap is shared across all accounts, not per-account). The check is a `Query` against the existing logs table, not a scan, and **fails closed**: if the logs table is unreachable, the action is skipped rather than executed. Once tripped, further matching detections are logged (`IR_CIRCUIT_BREAKER_TRIPPED`) and skipped until the window rolls forward — this is a brake against runaway automation (e.g. a misconfigured rule matching far more than intended), not per-alert human approval, which doesn't exist today.

## Failure isolation

A single malformed record in a response batch doesn't take the rest of the batch down — `responder` logs it (`IR_RECORD_PROCESSING_ERROR`) and continues processing the remaining records in the same invocation.

## Related pages

- [`docs/ir-role.md`](ir-role.md) — full IAM setup walkthrough for onboarding additional accounts
- [Detection Rules](detection-rules.md) — where `response_module` is set
- [API Reference](api-reference.md#ir-roles) — the `/ir-roles` endpoints
- [Security](security.md) — the IAM model this all sits on top of
- [Notifications](notifications.md#remediation-success-notifications) — how a successful remediation actually gets delivered

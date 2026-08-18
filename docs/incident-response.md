# Incident Response

*What the `responder` Lambda can do automatically, how it authorizes itself, and the safety controls around it.*

## Response modules

Set `response_module` on any detection rule to trigger an automated action when it fires. Nineteen modules exist, registered in `RESPONSE_MODULE_HANDLERS` in `src/handlers/responder.py`. **`api.py` validates `response_module` against this exact list** (`ALLOWED_RESPONSE_MODULES`, kept in sync with the registry by a dedicated test) — a typo or an unregistered name is rejected with a `400` at write time, not silently accepted and only discovered later as `IR_UNKNOWN_RESPONSE_MODULE` in `responder`'s logs the first time the rule actually fires:

| Module | Action | Needs on the detection event |
|---|---|---|
| `disable_access_key` | Disable a specific IAM access key | `user_name` + `access_key_id` |
| `disable_user` | Disable all IAM access keys for the actor | `user_name` |
| `delete_user` | Delete the IAM user | `user_name` |
| `disable_role` | Detach managed policies, delete inline policies, and clear the role's trust policy | `role_name` |
| `revoke_active_sessions` | Attach a deny-all inline policy conditioned on `aws:TokenIssueTime` — invalidates active STS sessions without touching permanent access keys | `user_name` |
| `delete_inline_policy` | Remove a single offending inline policy — surgical, doesn't touch the principal's other permissions or (unlike `revoke_active_sessions`) their active sessions | `user_name` **or** `role_name` (not `group_name` — see below) + `policy_name` |
| `block_s3_public_access` | Enable account-level S3 public access block | `aws_account_id` |
| `block_s3_bucket_public_access` | Block public access on a specific bucket | `bucket_name` |
| `block_s3_object_public_access` | Block public access on a specific object | `bucket_name` + `key` |
| `quarantine_s3_bucket` | Block public access + a deny-all bucket policy for any principal outside the account — broader containment than `block_s3_bucket_public_access` | `bucket_name` (`aws_account_id` optional, narrows the deny policy) |
| `isolate_ec2_instances` | Replace instance security groups with an isolation group | `instance_ids` (one or more) |
| `deauthorize_security_group_rules` | Revoke the specific ingress/egress rule that was added — narrower than `isolate_ec2_instances`, doesn't touch instances | `group_id` + a CIDR-based ingress/egress rule |
| `disable_lambda_function` | Throttle a function to zero reserved concurrency (reversible — new invocations fail, in-flight ones aren't interrupted) | `function_name` |
| `disable_secrets_manager_secret` | **Schedule** a secret for deletion (7-day default recovery window, still restorable via `RestoreSecret` until it elapses — not an instant delete) | `secret_id` |
| `revoke_rds_snapshot_public_access` | Remove `"all"` from a DB/cluster snapshot's `restore` attribute, without touching any other explicit account IDs already granted restore access | `dBSnapshotIdentifier` **or** `dBClusterSnapshotIdentifier` |
| `enable_cloudtrail_logging` | Re-enable a stopped CloudTrail trail | trail `name` |
| `enable_guardduty_detector` | Re-enable a disabled GuardDuty detector | `detectorId` |
| `start_config_recorder` | Re-start a stopped AWS Config recorder | `configurationRecorderName` |
| `enable_security_hub` | Re-enable Security Hub for this account/region | nothing — account/region-scoped |

The "Needs" column is what `responder.py`'s own field extractors pull from the detection event. **Not every extractor understands both sources** — worth checking before wiring `response_module` onto a new rule during setup, since a rule that matches but whose source doesn't carry the needed field will fire and then no-op (logged, not a crash):

- `_extract_user_name`/`_extract_user_and_access_key` (→ `disable_access_key`, `disable_user`, `delete_user`, `revoke_active_sessions`) and `_extract_bucket_name`/`_extract_instance_ids` (→ `block_s3_bucket_public_access`, `quarantine_s3_bucket`, `isolate_ec2_instances`) handle **both** the CloudTrail-shaped path (`raw_event.detail.*`) and the GuardDuty-shaped fallback (`resources[]` by type) — these work regardless of which source triggered the rule.
- `_extract_role_name` (→ `disable_role`) and the `key` half of `_extract_bucket_and_key` (→ `block_s3_object_public_access`) are **CloudTrail-only** today — no GuardDuty `resources[]` fallback exists for either. A GuardDuty-sourced rule using either of these two modules will match and fire, then no-op on missing `role_name`/`key`.
- `_extract_account_id` (→ `block_s3_public_access`, and the optional narrowing on `quarantine_s3_bucket`) reads `cloud_account_id`, a field `processor.py` denormalizes onto every detection at write time regardless of source — no source-specific handling needed.
- `_extract_security_group_rule_change` (→ `deauthorize_security_group_rules`), `_request_parameters(...).get("functionName")` (→ `disable_lambda_function`), `_request_parameters(...).get("secretId")` (→ `disable_secrets_manager_secret`), `_extract_rds_snapshot` (→ `revoke_rds_snapshot_public_access`), `_extract_inline_policy_principal` (→ `delete_inline_policy`), and the three single-field extracts for `enable_cloudtrail_logging`/`enable_guardduty_detector`/`start_config_recorder` are all **CloudTrail-only** — no GuardDuty finding type maps to any of these today, so no fallback is needed (not just unwritten). The security-group extractor additionally only translates **CIDR-based** ingress/egress rules — IPv6 ranges, prefix lists, and security-group-reference sources (`UserIdGroupPairs`) are skipped rather than guessed at; a rule authorized with one of those sources will fire and no-op on an empty rule list.
- `_extract_inline_policy_principal` doesn't support `PutGroupPolicy` — `delete_inline_policy` only takes `user_name`/`role_name` (matching `put_deny_all_inline_policy`'s own scope in `dredge`), so a group-targeted inline policy on rule `010_wildcard_inline_policy` fires and cleanly no-ops rather than guessing at an unsupported `group_name` argument.
- `enable_cloudtrail_logging`/`enable_guardduty_detector`/`start_config_recorder` only undo a *stop/disable* — `DeleteTrail`, `DeleteDetector`, and `DeleteConfigurationRecorder`/`DeleteDeliveryChannel` (all three still covered by rules `012`–`014`'s conditions, for visibility) leave nothing for a "re-enable" call to act on, since the resource itself is gone, not just toggled off. Those surface as a normal API error (or a missing-field no-op, for the two that key off a field only present on the stop/disable event) rather than being specially handled — recreating a deleted trail/detector/recorder isn't in scope for an automated response.
- **`019_rds_snapshot_public`'s condition doesn't yet inspect *which* attribute value was added** — it fires on any `ModifyDBSnapshotAttribute` call, including a legitimate one adding a specific trusted account ID for private cross-account sharing (`revoke_rds_snapshot_public_access` only ever removes `"all"`, so a legitimate account-ID grant is untouched either way, but the notification/IR-action record still fires on a non-incident). Tightening the condition to the specific `valuesToAdd` contents is future work, not done as part of adding the response module itself.

Each module runs through [`dredge`](https://github.com/dbnz-io/dredge) (a pinned dependency, `dredge.aws_ir.response`), not against `responder`'s own credentials — see below.

**CI deploys live (`DREDGE_DRY_RUN=false`) by default** — both an ordinary push to `main` and a manual `workflow_dispatch` run resolve to live unless you explicitly opt into dry-run (see `.github/workflows/ci.yml`'s "Resolve DREDGE_DRY_RUN for this deploy" step and the `workflow_dispatch` "Dry run" checkbox, which now defaults unchecked). This means **any merge to `main` executes real, destructive AWS actions** for any rule with a `response_module` set — there's no separate confirmation step. To deploy in simulation mode instead: run the "OpenCDR CI" workflow manually from the Actions tab and check the "Dry run" box.

`serverless.yml` itself still falls back to `${env:DREDGE_DRY_RUN, 'true'}` — dry-run — if `DREDGE_DRY_RUN` is completely unset. That fallback only matters for a `serverless deploy` run *outside* CI (a developer's local shell with nothing exported); CI's own resolve step always sets the var explicitly before deploying, so this local-only safety net never applies to the documented deploy path.

**Changing it after the fact:**

- **Via CI:** run the "OpenCDR CI" workflow manually from the Actions tab (`workflow_dispatch`) on `main`, with the "Dry run" checkbox checked (simulate) or unchecked (live, the default) as desired. The deploy job logs an explicit `::warning::`/`::notice::` announcing which mode it deployed in.
- **Locally, full redeploy:** `export DREDGE_DRY_RUN=false && npx serverless deploy --stage <stage>` (or `serverless deploy function --function responder`/`rollbackHandler` for a faster, code+config-only deploy of just those two functions).
- **Direct Lambda config patch (fast, but drifts from IaC):** `aws lambda update-function-configuration --function-name <fn> --environment "Variables={DREDGE_DRY_RUN=<true|false>,...<all other existing env vars>...}"` for each of `responder` and `rollbackHandler`. This forces a fresh execution environment (no stale warm container holding a stale-config `Dredge` client), but the *next* deploy of any kind — including a plain push to main — will silently reset it back to live (CI's default), since CloudFormation reconciles the Lambda's config back to match `serverless.yml`/CI's resolved value. **This cuts against you now if you patch to `true` for a temporary safety pause** — the next merge to `main` silently un-pauses it back to live. Treat this as a temporary override, not a persistent change, and don't rely on it for anything you need to stay dry-run past the next deploy.

## Known gaps in automated response coverage

Two GuardDuty-relevant containment capabilities `dredge` doesn't provide today — verified by inspecting the installed package directly, not assumed:

| Gap | Affected finding families | Lift |
|---|---|---|
| EKS/Kubernetes pod or workload isolation | All EKS/Kubernetes-family GuardDuty findings (`CredentialAccess:Kubernetes/*`, `DefenseEvasion:Kubernetes/*`, `PrivilegeEscalation:Kubernetes/*`, `Policy:Kubernetes/*`, ...); `AttackSequence:EKS/CompromisedCluster`; Runtime Monitoring findings where the underlying workload is EKS-hosted | Large — net-new capability. `dredge`'s `AwsServiceRegistry` registers no `eks` boto3 client at all, there's no Kubernetes client dependency anywhere in the package, and it's not on dredge's own upstream roadmap |
| ECS Fargate task network isolation | `AttackSequence:ECS/CompromisedCluster`; Runtime Monitoring findings where the underlying workload is Fargate-hosted | Smaller — `dredge` already has `stop_ecs_service`/`stop_ecs_task` (stop-only, no isolation option), and awsvpc-mode Fargate tasks have assignable security groups, so this is achievable by extending the same SG-swap pattern `isolate_ec2_instances` already uses, not a new capability class |

Runtime Monitoring findings on **EC2-hosted** workloads already have adequate coverage (`isolate_ec2_instances`) — these two gaps are specifically about the non-EC2 compute substrates GuardDuty also monitors. Tracked as future work in the separate `dredge` repository, not addressed here.

## Remediation notifications

A successful action doesn't just log and emit a metric — `responder` also queues a second, notifications-only outbox item (`type: remediation_success`) distinct from the alert that triggered it, so "this was remediated" is as visible as "this was detected" was. Best-effort: a failure to queue this notification is logged but never makes an already-succeeded action look failed.

`notifier` routes this type to green-styled Slack/Discord/email builders rather than the alert ones. Security Hub, Jira, and the custom webhook channel don't support this notification type yet — those builders assume the full alert shape (severity, primary signal, playbook) this item doesn't have, so they're explicitly skipped for it rather than fed a shape they don't expect. See [Notifications](notifications.md#remediation-success-notifications) for the channel-level detail.

Only successful actions notify this way today — a failed action is still visible only in CloudWatch logs and the `ResponderActionsExecuted` metric (see [Observability](observability.md)), not as its own notification.

**Dry-run successes notify too, labeled distinctly.** `dredge` reports `success=True` (with `details["dry_run"] = True`) in dry-run mode as well as live mode — it made no AWS API call, but nothing errored either. `responder` forwards that flag into the notification payload, and `notifier` renders it in a **blue-grey "DRY RUN — SIMULATED"** style instead of the usual green, with a note explaining that no AWS API call was made. This is deliberate: a dry-run notification is the confirmation that detection → response → notify works end-to-end, and that's worth surfacing — but it must never be mistaken for a real fix.

**Dry-run successes still write an IR Action record and can still be "rolled back."** An earlier version of this feature skipped the record entirely for dry-run successes (reasoning: nothing real happened, so nothing to roll back) — that turned out to make IR Actions empty and rollback untestable for the entire time a deployment runs with `DREDGE_DRY_RUN=true`, which is worse than the risk it was guarding against. `rollback_supported` on the written record is still computed correctly either way: most modules naturally come out `False` in dry-run since dredge's dry-run path returns before ever capturing `rollback_state` (see `_build_rollback_kwargs`); the handful of modules that re-derive their rollback kwargs straight from `detection_event` instead (`disable_access_key`, `revoke_active_sessions`, `deauthorize_security_group_rules`, `disable_secrets_manager_secret`) come out `True`, and rolling one back is itself just another dry-run call through the same `DREDGE_DRY_RUN` gate — consistent and harmless, exactly the click-through testability dry-run mode exists for.

**A rolled-back action notifies the same way, deliberately in a different color.** `rollbackHandler` (`src/handlers/ir_rollback.py`) queues its own outbox item (`type: rollback_success`) on a successful rollback — same best-effort, never-blocks-the-real-work discipline as remediation-success above. `notifier` routes it to **purple**-styled Slack/Discord/email builders, distinct from remediation-success's green and from every CRITICAL/HIGH/MEDIUM/LOW alert color: a rollback is the *reverse* of a remediation, and reusing green for it would read as "still contained" when the opposite just happened. Same channel scope as remediation-success (Slack/Discord/email only, Security Hub/Jira/webhook skipped for the same reason). See [Notifications](notifications.md#rollback-success-notifications).

## Rollback

`POST /ir-actions/{detection_id}/rollback` doesn't execute the undo synchronously — it enqueues onto `ir-rollback-queue` and returns `202`, and `rollbackHandler` (`src/handlers/ir_rollback.py`) does the actual work asynchronously, same decoupled shape as the original `processor` → outbox → `responder` pipeline (and the same rate-limit/circuit-breaker/dry-run wiring for free, by going through an equivalent consumer instead of a bespoke synchronous call). Only rollback-*eligible* actions can be rolled back at all — see `ROLLBACK_UNDO_MODULE` in `responder.py` and the "Response modules" table above for which ones capture enough prior state to be reversible.

**`rollback_status` on the IR Action record is what the UI actually reads** — `rolled_back`/`rolled_back_at` (booleans, set together on success) still exist for backward compatibility, but `rollback_status` is the field with real states:

| `rollback_status` | Meaning | Set by |
|---|---|---|
| *(absent)* | Never attempted | — |
| `pending` | Enqueued, not yet processed | `api.py`, synchronously before the `202` response — so a client polling right after enqueue sees it immediately, not "absent" for however long the queue takes to drain |
| `succeeded` | Undo completed successfully | `rollbackHandler`, alongside `rolled_back=true` |
| `failed` | Attempted and did not complete — see `rollback_error` for why | `rollbackHandler`, on **every** failure path (rate limit tripped, role assume failed, unknown/unsupported module, corrupt stored state, or the undo call itself reaching AWS and being rejected) |

`rollback_error` (string, truncated to 1000 chars) is set alongside `failed` and cleared on any subsequent `succeeded`. `POST .../rollback` returns `409` if `rollback_status` is already `pending` (no double-enqueue) but **not** if it's `failed` — a failed rollback isn't terminal, retrying is expected and just re-enqueues normally.

This distinction exists because it didn't always: an earlier version only ever wrote `rolled_back`/`rolled_back_at`, so "enqueued but not yet run," "ran and failed for a specific reason," and "never attempted" were all indistinguishable in the UI — every one of them just showed as "active." `IR_ROLLBACK_FAILED`/the various `IR_ROLLBACK_*` error `event_name`s in CloudWatch logs always had this detail; `rollback_status`/`rollback_error` is what surfaces it to `GET /ir-actions` without needing log access.

## How the responder authorizes itself

`responder`'s own Lambda execution role has **no** destructive AWS permissions — no IAM, no EC2, no S3/S3control grants. The only thing it can do on its own credentials is `sts:AssumeRole`, and only on roles named `${service}-${stage}-ir-role` (e.g. `opencdr-dev-ir-role`) in *any* AWS account — not a blanket grant on every role in every account. Every actual response module runs against the temporary credentials returned by that assumed role, not `responder`'s own.

**`rollbackHandler` (`src/handlers/ir_rollback.py`) is a separate Lambda with its own execution role, and needs the exact same trust relationship independently** — it's not covered by responder's. `sts:AssumeRole` requires two things to line up: the *caller's* own IAM policy must allow calling it (both Lambdas have this — see their respective `iamRoleStatements` in `serverless.yml`), **and** the *target* role's trust policy (`AssumeRolePolicyDocument` on `OpencdrIrRole`) must list that caller as a trusted principal. Granting the first without the second fails silently until someone actually exercises that path: a live deployment can execute real actions successfully (responder's principal was trusted) while every single rollback fails with a plain `AccessDenied` on `sts:AssumeRole` (rollbackHandler's principal wasn't) — indistinguishable from a caller-side permissions bug unless you check the trust policy specifically. `OpencdrIrRole`'s `AssumeRolePolicyDocument` in `serverless.yml` lists both `ResponderIamRoleLambdaExecution` and `RollbackHandlerIamRoleLambdaExecution` as principals; the same applies to any hand-created role in an onboarded account — see [Multi-account](#multi-account-onboard-each-additional-account) below.

Which role gets assumed is resolved **per detection**, from the AWS account the detection came from (`_resolve_role_arn` in `responder.py`, and the equivalent lookup already stored on the IR Action record for `rollbackHandler`):

1. That account has an **enabled** row in the `ir-account-roles-table` DynamoDB table → assume that row's `role_arn`.
2. That account has a row but it's **disabled** → skip the action entirely (logged as `IR_ACCOUNT_DISABLED`) — does **not** fall back to (3). This is a real kill switch.
3. No row for the account, or the account couldn't be determined at all → `OPENCDR_IR_ROLE_ARN`.

Resolved role ARNs are cached per account for `RESPONDER_ROLE_CACHE_TTL_SECONDS` (default 60s); assumed-role credentials are cached per role for close to their session lifetime. Onboarding or disabling an account takes effect within about a minute, not instantly — `responder` isn't calling `sts:AssumeRole` on every single detection.

## Single-account: zero setup

`serverless.yml` auto-creates the home account's IR role (`OpencdrIrRole`) with the trust policy (trusting both responder's and rollbackHandler's execution roles) and permissions already wired, and auto-wires `OPENCDR_IR_ROLE_ARN` to it. `serverless deploy` alone is enough — there's no manual `aws iam create-role` step for the account you deploy into.

## Multi-account: onboard each additional account

A `serverless deploy` in one account can't provision an IAM role in a *different* AWS account, so cross-account IR needs two manual steps per additional account — creating the role there by hand (must be named exactly `opencdr-<stage>-ir-role`, trust policy listing **both** responder's and rollbackHandler's execution role ARNs as principals — missing either one means either actions or rollbacks work for that account but not both) and adding a row via `POST /ir-roles`. The full walkthrough — trust policy example, the exact `iam create-role`/`put-role-policy` commands, the kill-switch API call, and keeping the IAM permissions policy in sync with what the response modules actually need — is in [`docs/ir-role.md`](ir-role.md). This page covers the *behavior*; that one covers the *setup*.

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

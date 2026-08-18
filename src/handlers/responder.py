# src/handlers/responder.py

from __future__ import annotations

import json
import os
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import boto3
from boto3.dynamodb.conditions import Key
from dredge import Dredge, DredgeConfig
from dredge.auth import AwsAuthConfig
from dredge.aws_ir.models import OperationResult

from ..infra.aws_handler import ttl_expires_at
from ..infra.logger import Logger
from ..infra.metrics import emit_metric
from ..infra.partition_keys import day_bucket_key
from ..infra.xray_setup import patch_boto3

patch_boto3()

LAMBDA_NAME = os.getenv("LAMBDA_NAME", "unknown")
_SERVICE = os.getenv("SERVICE_NAME", "OPENCDR")

OUTBOX_TABLE_NAME = os.getenv("OUTBOX_TABLE_NAME", "")
_outbox_table = boto3.resource("dynamodb").Table(OUTBOX_TABLE_NAME) if OUTBOX_TABLE_NAME else None

# Logged once per cold start (not per invocation, to avoid drowning
# CloudWatch in a repeat of this on every SQS message) so live mode is
# visible from the very first log line a container ever produces, not
# just discoverable by reading serverless.yml.
if os.environ.get("DREDGE_DRY_RUN", "true").lower() != "true":
    Logger(service=_SERVICE, source=LAMBDA_NAME).warning(
        event_name="IR_LIVE_MODE_ENABLED",
        message=(
            "DREDGE_DRY_RUN is not 'true' -- responder will execute real, "
            "destructive AWS actions for any detection with a response_module set."
        ),
    )

# ---------------------------------------------------------------------------
# Rate limit / circuit breaker
# ---------------------------------------------------------------------------
#
# Minimal Phase 0 safety net: cap how many *real* (non-dry-run) destructive
# actions responder will execute within a rolling window. This is not a
# per-alert human approval workflow (that's Phase 4) -- it's a circuit
# breaker to stop a detection-logic bug or an attacker-triggered storm of
# detections from causing runaway automated response.

_LOGS_TABLE_NAME = os.getenv("LOGS_TABLE_NAME", "")
_logs_table = boto3.resource("dynamodb").Table(_LOGS_TABLE_NAME) if _LOGS_TABLE_NAME else None

RATE_LIMIT_WINDOW_MINUTES = int(os.getenv("RESPONDER_RATE_LIMIT_WINDOW_MINUTES", "5"))
RATE_LIMIT_MAX_ACTIONS = int(os.getenv("RESPONDER_RATE_LIMIT_MAX_ACTIONS", "20"))

_ACTION_EVENT_NAMES = ("IR_ACTION_SUCCESS", "IR_ACTION_FAILED")


def _recent_action_count() -> int:
    """
    Count real (non-dry-run) responder actions logged in the last
    RATE_LIMIT_WINDOW_MINUTES, via a Query against the logs table's
    (service_bucket, timestamp) key -- no Scan. logs-table-v2's HASH key
    is service_bucket ("<service>#<YYYY-MM-DD>"), not the bare service
    name (see src/infra/partition_keys.py) -- queries one bucket per UTC
    day the window touches (almost always just today, occasionally
    today+yesterday if the window straddles midnight) and merges counts.
    """
    now = datetime.now(UTC)
    cutoff_dt = now - timedelta(minutes=RATE_LIMIT_WINDOW_MINUTES)
    cutoff = cutoff_dt.isoformat()

    count = 0
    day = cutoff_dt.date()
    while day <= now.date():
        bucket = day_bucket_key(_SERVICE, day.isoformat())
        query_kwargs: dict = {
            "KeyConditionExpression": Key("service_bucket").eq(bucket) & Key("timestamp").gte(cutoff),
        }
        while True:
            resp = _logs_table.query(**query_kwargs)
            for item in resp.get("Items", []):
                if item.get("event_name") not in _ACTION_EVENT_NAMES:
                    continue
                operation_result = (item.get("details") or {}).get("operation_result") or {}
                if (operation_result.get("details") or {}).get("dry_run") is True:
                    continue
                count += 1

            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
            query_kwargs["ExclusiveStartKey"] = last_key

        day += timedelta(days=1)

    return count


# ---------------------------------------------------------------------------
# Per-account role resolution + Dredge caching
# ---------------------------------------------------------------------------
#
# The responder's own Lambda execution role is intentionally not granted any
# destructive IAM/EC2/S3 permissions (see serverless.yml) -- every response
# module acts through an assumed role instead, so a compromised responder
# Lambda can't act on its own credentials. Which role to assume depends on
# which AWS account the detection came from:
#
#   - a row in irAccountRolesTable for that account, if it's enabled -> that
#     role_arn
#   - a row that's present but disabled -> no role at all (explicit kill
#     switch; does NOT fall back to the default)
#   - no row for that account, or the account couldn't be determined ->
#     OPENCDR_IR_ROLE_ARN (auto-created for the home account by
#     serverless.yml unless overridden -- see docs/ir-role.md)

IR_ACCOUNT_ROLES_TABLE_NAME = os.getenv("IR_ACCOUNT_ROLES_TABLE_NAME", "")
_ir_account_roles_table = (
    boto3.resource("dynamodb").Table(IR_ACCOUNT_ROLES_TABLE_NAME) if IR_ACCOUNT_ROLES_TABLE_NAME else None
)

IR_ACTIONS_TABLE_NAME = os.getenv("IR_ACTIONS_TABLE_NAME", "")
_ir_actions_table = (
    boto3.resource("dynamodb").Table(IR_ACTIONS_TABLE_NAME) if IR_ACTIONS_TABLE_NAME else None
)

# Admin-configured data (changes rarely) -- short TTL avoids a DynamoDB
# GetItem on every single record while still picking up onboarding/kill-
# switch changes quickly. Same pattern as notifier.py's settings cache.
ROLE_ARN_CACHE_TTL_SECONDS = int(os.getenv("RESPONDER_ROLE_CACHE_TTL_SECONDS", "60"))
# Cache assumed-role Dredge clients close to the assumed session's own
# lifetime (AwsAuthConfig.role_session_duration default 3600s), minus a
# safety buffer, so we're not calling sts:AssumeRole on every record.
_ROLE_SESSION_DURATION_SECONDS = 3600
DREDGE_CACHE_TTL_SECONDS = _ROLE_SESSION_DURATION_SECONDS - 300

# account_id -> (resolved role_arn or None, resolved_at)
_role_arn_cache: dict[str, tuple[str | None, float]] = {}
# role_arn -> (Dredge, built_at)
_dredge_cache: dict[str, tuple[Dredge, float]] = {}


def _resolve_role_arn(account_id: str | None) -> str | None:
    """
    Decide which IAM role ARN responder should assume for this detection.
    See module docstring above for the resolution order.
    """
    default_role_arn = os.environ.get("OPENCDR_IR_ROLE_ARN") or None

    if not account_id:
        return default_role_arn

    now = time.monotonic()
    cached = _role_arn_cache.get(account_id)
    if cached is not None and (now - cached[1]) < ROLE_ARN_CACHE_TTL_SECONDS:
        return cached[0]

    item = None
    if _ir_account_roles_table is not None:
        resp = _ir_account_roles_table.get_item(Key={"aws_account_id": account_id})
        item = resp.get("Item")

    if item is None:
        resolved = default_role_arn
    elif item.get("enabled") is False:
        resolved = None
    else:
        resolved = item.get("role_arn") or default_role_arn

    _role_arn_cache[account_id] = (resolved, now)
    return resolved


def _get_dredge(role_arn: str) -> Dredge:
    """Build (and cache) a Dredge client that assumes role_arn."""
    now = time.monotonic()
    cached = _dredge_cache.get(role_arn)
    if cached is not None and (now - cached[1]) < DREDGE_CACHE_TTL_SECONDS:
        return cached[0]

    region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1"
    dry_run = os.environ.get("DREDGE_DRY_RUN", "true").lower() == "true"

    auth_cfg = AwsAuthConfig(role_arn=role_arn, region_name=region)
    dredge_config = DredgeConfig(region_name=region, dry_run=dry_run)
    dredge = Dredge(auth=auth_cfg, config=dredge_config)

    _dredge_cache[role_arn] = (dredge, now)
    return dredge


# ---------------------------------------------------------------------------
# Lambda entrypoint
# ---------------------------------------------------------------------------


def lambda_handler(event: dict, context) -> dict:
    """
    SQS event handler.

    Expects SQS messages whose body is a JSON-encoded detection event, e.g.:

      {
        "detection_id": "...",
        "rule_id": "...",
        "response_module": "disable_access_key",
        "user_name": "alice",
        "access_key_id": "AKIA...",
        "raw_event": {... CloudTrail event ...}
      }

    For now we focus on:
      - response_module = "disable_access_key"

    You can add more response modules later in RESPONSE_MODULE_HANDLERS.
    """
    request_id = getattr(context, "aws_request_id", None)
    logger = Logger(
        service=_SERVICE,
        source=LAMBDA_NAME,
        request_id=request_id,
    )
    records = event.get("Records", [])

    for record in records:
        receipt_handle = None
        try:
            receipt_handle = record.get("receiptHandle") if isinstance(record, dict) else None
            _process_record(record, request_id, receipt_handle, logger)
        except Exception as e:
            # We *log* but do not re-raise, so the batch is acknowledged.
            # If you prefer at-least-once execution, re-raise instead.
            logger.error(
                event_name="IR_RECORD_PROCESSING_ERROR",
                event_type="ERROR",
                message="Failed to process incident-response SQS record",
                details={
                    "error": repr(e),
                    "receipt_handle": receipt_handle,
                },
            )

    # SQS integration doesn't use this, but it's nice for tests/logs.
    return {
        "statusCode": 200,
        "body": json.dumps({"message": "Incident response processing complete"}),
    }


# ---------------------------------------------------------------------------
# Per-record processing
# ---------------------------------------------------------------------------


def _process_record(
    record: dict,
    request_id: str | None,
    receipt_handle: str | None,
    logger: Logger,
) -> None:
    body = record.get("body", "")

    try:
        payload = json.loads(body) if body else {}
    except json.JSONDecodeError:
        logger.error(
            event_name="IR_INVALID_JSON",
            event_type="ERROR",
            message="SQS message body is not valid JSON",
            details={"receipt_handle": receipt_handle, "body": body},
        )
        return

    # If the event is wrapped, unwrap it:
    detection_event = payload.get("detection_event", payload)

    response_module = detection_event.get("response_module")
    detection_id = detection_event.get("detection_id")
    rule_id = detection_event.get("rule_id")

    if not response_module:
        logger.info(
            event_name="IR_NO_RESPONSE_MODULE",
            event_type="PROCESSING",
            message="No response_module configured for detection, skipping",
            details={
                "detection_id": detection_id,
                "rule_id": rule_id,
                "receipt_handle": receipt_handle,
            },
        )
        return

    handler = RESPONSE_MODULE_HANDLERS.get(response_module)

    if not handler:
        logger.info(
            event_name="IR_UNKNOWN_RESPONSE_MODULE",
            event_type="PROCESSING",
            message="Unknown response_module, skipping automated response",
            details={
                "detection_id": detection_id,
                "rule_id": rule_id,
                "response_module": response_module,
                "receipt_handle": receipt_handle,
            },
        )
        return

    # Structural backstop, independent of whatever conditions the rule
    # itself declares: an API call AWS denied produces the exact same
    # signal shape as one that succeeded, so without this a rule author
    # who forgets an explicit `api.error_code not_exists` condition would
    # let a denied/probing API call trigger a real destructive action.
    error_code = _detection_error_code(detection_event)
    if error_code:
        logger.info(
            event_name="IR_SKIPPED_FAILED_API_CALL",
            event_type="PROCESSING",
            message=(
                "Detection's underlying API call was denied or errored; "
                "skipping automated response regardless of rule conditions"
            ),
            details={
                "detection_id": detection_id,
                "rule_id": rule_id,
                "response_module": response_module,
                "error_code": error_code,
                "receipt_handle": receipt_handle,
            },
        )
        return

    account_id = _extract_account_id(detection_event)

    try:
        role_arn = _resolve_role_arn(account_id)
    except Exception as e:
        logger.error(
            event_name="IR_ROLE_RESOLUTION_FAILED",
            event_type="ERROR",
            message="Failed to resolve which IAM role to assume; skipping action",
            details={
                "detection_id": detection_id,
                "rule_id": rule_id,
                "response_module": response_module,
                "account_id": account_id,
                "error": repr(e),
                "receipt_handle": receipt_handle,
            },
        )
        return

    if not role_arn:
        logger.info(
            event_name="IR_ACCOUNT_DISABLED",
            event_type="PROCESSING",
            message="No IR role available for this account (disabled, or not "
            "onboarded and no default OPENCDR_IR_ROLE_ARN configured); skipping",
            details={
                "detection_id": detection_id,
                "rule_id": rule_id,
                "response_module": response_module,
                "account_id": account_id,
                "receipt_handle": receipt_handle,
            },
        )
        return

    # Circuit breaker: fail closed (skip the action) both when the limit is
    # tripped and when we can't determine the recent count at all.
    try:
        recent_count = _recent_action_count()
    except Exception as e:
        logger.error(
            event_name="IR_RATE_LIMIT_CHECK_FAILED",
            event_type="ERROR",
            message="Failed to check responder rate limit; skipping action",
            details={
                "detection_id": detection_id,
                "rule_id": rule_id,
                "response_module": response_module,
                "error": repr(e),
                "receipt_handle": receipt_handle,
            },
        )
        return

    if recent_count >= RATE_LIMIT_MAX_ACTIONS:
        logger.error(
            event_name="IR_CIRCUIT_BREAKER_TRIPPED",
            event_type="PROCESSING",
            message=(
                f"Circuit breaker tripped: {recent_count} actions in the last "
                f"{RATE_LIMIT_WINDOW_MINUTES}m (limit {RATE_LIMIT_MAX_ACTIONS}); "
                "skipping this action"
            ),
            details={
                "detection_id": detection_id,
                "rule_id": rule_id,
                "response_module": response_module,
                "recent_action_count": recent_count,
                "rate_limit_window_minutes": RATE_LIMIT_WINDOW_MINUTES,
                "rate_limit_max_actions": RATE_LIMIT_MAX_ACTIONS,
                "receipt_handle": receipt_handle,
            },
        )
        return

    try:
        dredge = _get_dredge(role_arn)
    except Exception as e:
        logger.error(
            event_name="IR_ASSUME_ROLE_FAILED",
            event_type="ERROR",
            message="Failed to assume the resolved IR role; skipping action",
            details={
                "detection_id": detection_id,
                "rule_id": rule_id,
                "response_module": response_module,
                "account_id": account_id,
                "role_arn": role_arn,
                "error": repr(e),
                "receipt_handle": receipt_handle,
            },
        )
        return

    # Execute the IR action using dredge
    try:
        result = handler(dredge, detection_event)
    except Exception as e:
        logger.error(
            event_name="IR_ACTION_EXCEPTION",
            event_type="ERROR",
            message="Exception while executing incident response action",
            details={
                "detection_id": detection_id,
                "rule_id": rule_id,
                "response_module": response_module,
                "error": repr(e),
                "receipt_handle": receipt_handle,
            },
        )
        return

    # Log success / failure
    log_fn = logger.info if result.success else logger.error
    event_name = "IR_ACTION_SUCCESS" if result.success else "IR_ACTION_FAILED"

    emit_metric(
        "ResponderActionsExecuted",
        dimensions={
            "response_module": str(response_module),
            "result": "success" if result.success else "failure",
        },
    )

    log_fn(
        event_name=event_name,
        event_type="PROCESSING",
        message=f"Executed incident response action: {response_module}",
        details={
            "detection_id": detection_id,
            "rule_id": rule_id,
            "response_module": response_module,
            "operation_result": _operation_result_to_dict(result),
            "receipt_handle": receipt_handle,
        },
    )

    if result.success and _outbox_table is not None:
        _notify_remediation_success(
            detection_event=detection_event,
            detection_id=detection_id,
            rule_id=rule_id,
            response_module=response_module,
            account_id=account_id,
            result=result,
            logger=logger,
        )

    # Dry-run mode is still fully simulated end-to-end deliberately (not
    # just the initial action): the record written here has
    # rollback_supported computed the normal way, which for most modules
    # already comes out False in dry-run since dredge's dry-run path
    # returns before ever capturing rollback_state (see
    # _build_rollback_kwargs) -- and for the handful of modules that
    # re-derive their rollback kwargs straight from detection_event
    # instead (disable_access_key, revoke_active_sessions,
    # deauthorize_security_group_rules, disable_secrets_manager_secret),
    # a "rollback" of a dry-run action is itself just another dry-run
    # call through the same DREDGE_DRY_RUN gate -- consistent, harmless,
    # and exactly the click-through testability dry-run mode exists for.
    if result.success and response_module in ROLLBACK_UNDO_MODULE:
        _write_ir_action_record(
            detection_event=detection_event,
            detection_id=detection_id,
            rule_id=rule_id,
            response_module=response_module,
            result=result,
            account_id=account_id,
            role_arn=role_arn,
            logger=logger,
        )


def _notify_remediation_success(
    *,
    detection_event: dict,
    detection_id: str | None,
    rule_id: str | None,
    response_module: str | None,
    account_id: str | None,
    result: OperationResult,
    logger: Logger,
) -> None:
    """
    Queues a notifications-only outbox item so a successful IR action shows
    up as a distinct (green) message, not silently just a CloudWatch log
    line. Best-effort: a failure here must never make an already-succeeded
    IR action look failed, so it's logged and swallowed, not raised.

    Fires the same way whether DREDGE_DRY_RUN is on or off -- dredge sets
    `result.details["dry_run"] = True` and still reports success in that
    mode (see dredge/aws_ir/response.py), so without forwarding that flag
    a simulated run and a real one produce an identical-looking
    notification. Carrying `dry_run` through lets notifier.py label it
    clearly, which is the whole point: a dry-run notification is proof the
    detection -> response -> notify pipeline works end-to-end, without
    implying the AWS API call actually happened.
    """
    try:
        payload = {
            "type": "remediation_success",
            "notify": True,
            "detection_id": detection_id,
            "rule_id": rule_id,
            "severity": detection_event.get("severity", "UNKNOWN"),
            "response_module": response_module,
            "cloud_account_id": account_id,
            "operation": result.operation,
            "target": result.target,
            "dry_run": bool(result.details.get("dry_run")),
            "timestamp": datetime.now(UTC).isoformat(),
        }
        _outbox_table.put_item(
            Item={
                "outbox_id": str(uuid.uuid4()),
                "timestamp": datetime.now(UTC).isoformat(),
                "status": "PENDING",
                "payload": json.dumps(payload),
                "destinations": json.dumps(["notifications"]),
                "attempts": 0,
                "expires_at": ttl_expires_at(),
            }
        )
    except Exception as e:
        logger.error(
            event_name="IR_REMEDIATION_NOTIFY_FAILED",
            event_type="ERROR",
            message="Executed IR action successfully but failed to queue the success notification",
            details={
                "detection_id": detection_id,
                "rule_id": rule_id,
                "response_module": response_module,
                "error": repr(e),
            },
        )


# ---------------------------------------------------------------------------
# Rollback: which response modules dredge can undo, and how to build the
# exact kwargs the corresponding undo function needs. See
# dredge/aws_ir/response.py's "Rollback / undo actions" section -- each
# entry here corresponds 1:1 to one of those 12 functions. disable_user/
# disable_role/quarantine_s3_bucket/isolate_ec2_instances (the second
# batch) previously destroyed data without ever reading it first (inline
# policies, bucket policy, original SGs) -- dredge now captures that too,
# EXCEPT disable_role's trust policy, deliberately: restoring it needs
# iam:UpdateAssumeRolePolicy, an account-wide trust-policy-rewrite
# primitive OpencdrIrRole does not hold (see serverless.yml's IamRoles
# comment) -- a manual fix stays required for that one piece. Genuine
# deletions (delete_user/delete_access_key/delete_mfa_devices) are still
# out of scope entirely -- no amount of capture makes those reversible.
# See docs/incident-response.md#rollback.
# ---------------------------------------------------------------------------

ROLLBACK_UNDO_MODULE: dict[str, str] = {
    "disable_access_key": "enable_access_key",
    "revoke_active_sessions": "revoke_deny_all_session_policy",
    "deauthorize_security_group_rules": "authorize_security_group_rules",
    "block_s3_public_access": "restore_s3_account_public_access_block",
    "block_s3_bucket_public_access": "restore_s3_bucket_public_access_block_and_acl",
    "block_s3_object_public_access": "restore_s3_object_acl",
    "disable_lambda_function": "restore_lambda_concurrency",
    "disable_secrets_manager_secret": "restore_secrets_manager_secret",
    "disable_user": "restore_user",
    "disable_role": "restore_role",
    "quarantine_s3_bucket": "restore_s3_bucket_quarantine",
    "isolate_ec2_instances": "restore_ec2_instance_security_groups",
    "revoke_rds_snapshot_public_access": "restore_rds_snapshot_public_access",
    "delete_inline_policy": "restore_inline_policy",
}


def _build_rollback_kwargs(response_module: str, detection_event: dict, result: OperationResult) -> dict | None:
    """
    Build the exact kwargs the undo function named in ROLLBACK_UNDO_MODULE
    needs, re-deriving identifiers from detection_event the same way the
    original _handle_* function did (cheap, deterministic, no new
    extraction logic). Returns None when the module needs a prior-state
    capture that itself failed (result.details has no "rollback_state") --
    the action still happened and its row is still written, just marked
    rollback_supported=False rather than silently dropped.
    """
    if response_module == "disable_access_key":
        user_name, access_key_id = _extract_user_and_access_key(detection_event)
        return {"user_name": user_name, "access_key_id": access_key_id}

    if response_module == "revoke_active_sessions":
        return {"user_name": _extract_user_name(detection_event)}

    if response_module == "deauthorize_security_group_rules":
        group_id, ingress_rules, egress_rules = _extract_security_group_rule_change(detection_event)
        return {
            "group_id": group_id,
            "ingress_rules": ingress_rules or None,
            "egress_rules": egress_rules or None,
        }

    if response_module == "disable_secrets_manager_secret":
        return {"secret_id": _request_parameters(detection_event).get("secretId")}

    if response_module == "disable_user":
        # access_keys_disabled/groups_removed/managed_policies_detached are
        # always present (possibly empty lists) -- disable_user captured
        # them before this rollback feature existed. inline_policies is the
        # new, best-effort piece: absent means either nothing to restore
        # (the user had none) or its own capture failed -- either way the
        # other three pieces are still fully restorable, so this doesn't
        # gate rollback_supported the way an all-or-nothing rollback_state
        # does for the S3/Lambda modules above.
        return {
            "user_name": _extract_user_name(detection_event),
            "access_keys_disabled": result.details.get("access_keys_disabled"),
            "groups_removed": result.details.get("groups_removed"),
            "managed_policies_detached": result.details.get("managed_policies_detached"),
            "inline_policies": result.details.get("inline_policies"),
        }

    if response_module == "disable_role":
        # Same reasoning as disable_user above. Trust policy is never
        # captured (see ROLLBACK_UNDO_MODULE's module comment) -- restore_role
        # doesn't take it as an argument at all.
        return {
            "role_name": _extract_role_name(detection_event),
            "managed_policies_detached": result.details.get("managed_policies_detached"),
            "inline_policies": result.details.get("inline_policies"),
        }

    rollback_state = result.details.get("rollback_state")
    if rollback_state is None:
        return None

    if response_module == "quarantine_s3_bucket":
        return {
            "bucket_name": _extract_bucket_name(detection_event),
            "public_access_block_configuration": rollback_state.get("public_access_block_configuration"),
            "bucket_policy": rollback_state.get("bucket_policy"),
        }

    if response_module == "isolate_ec2_instances":
        instance_security_groups = rollback_state.get("instance_security_groups")
        if not instance_security_groups:
            return None
        return {"instance_security_groups": instance_security_groups}

    if response_module == "block_s3_public_access":
        return {
            "account_id": _extract_account_id(detection_event),
            "public_access_block_configuration": rollback_state.get("public_access_block_configuration"),
        }

    if response_module == "block_s3_bucket_public_access":
        return {
            "bucket_name": _extract_bucket_name(detection_event),
            "public_access_block_configuration": rollback_state.get("public_access_block_configuration"),
            "access_control_policy": rollback_state.get("access_control_policy"),
        }

    if response_module == "block_s3_object_public_access":
        access_control_policy = rollback_state.get("access_control_policy")
        if access_control_policy is None:
            return None
        bucket_name, key = _extract_bucket_and_key(detection_event)
        return {"bucket_name": bucket_name, "key": key, "access_control_policy": access_control_policy}

    if response_module == "disable_lambda_function":
        return {
            "function_name": _request_parameters(detection_event).get("functionName"),
            "reserved_concurrent_executions": rollback_state.get("reserved_concurrent_executions"),
        }

    if response_module == "revoke_rds_snapshot_public_access":
        snapshot_id, snapshot_type = _extract_rds_snapshot(detection_event)
        return {
            "snapshot_id": snapshot_id,
            "snapshot_type": snapshot_type,
            "restore_values": rollback_state.get("restore_values", []),
        }

    if response_module == "delete_inline_policy":
        user_name, role_name, policy_name = _extract_inline_policy_principal(detection_event)
        return {
            "user_name": user_name,
            "role_name": role_name,
            "policy_name": policy_name,
            "policy_document": rollback_state["policy_document"],
        }

    return None


def _write_ir_action_record(
    *,
    detection_event: dict,
    detection_id: str | None,
    rule_id: str | None,
    response_module: str,
    result: OperationResult,
    account_id: str | None,
    role_arn: str,
    logger: Logger,
) -> None:
    """
    Persist one row to irActionsTable for a successful, rollback-eligible
    action. Best-effort, same as _notify_remediation_success: a failure
    here must never make an already-succeeded IR action look failed.
    """
    if _ir_actions_table is None or not detection_id:
        return

    try:
        rollback_kwargs = _build_rollback_kwargs(response_module, detection_event, result)
        item: dict[str, Any] = {
            "detection_id": detection_id,
            "rule_id": rule_id,
            "response_module": response_module,
            "undo_module": ROLLBACK_UNDO_MODULE[response_module],
            "target": result.target,
            "account_id": account_id,
            "role_arn": role_arn,
            "rollback_supported": rollback_kwargs is not None,
            "rolled_back": False,
            "timestamp": datetime.now(UTC).isoformat(),
            "expires_at": ttl_expires_at(),
        }
        if rollback_kwargs is not None:
            item["rollback_kwargs"] = json.dumps(rollback_kwargs)
        _ir_actions_table.put_item(Item=item)
    except Exception as e:
        logger.error(
            event_name="IR_ACTION_RECORD_WRITE_FAILED",
            event_type="ERROR",
            message="Executed IR action successfully but failed to record it for rollback",
            details={
                "detection_id": detection_id,
                "rule_id": rule_id,
                "response_module": response_module,
                "error": repr(e),
            },
        )


# ---------------------------------------------------------------------------
# Response-module handlers
# ---------------------------------------------------------------------------


def _operation_result_to_dict(result: OperationResult) -> dict:
    """Convert OperationResult into a JSON-serializable dict."""
    return {
        "operation": result.operation,
        "target": result.target,
        "success": result.success,
        "details": result.details,
        "errors": result.errors,
    }


# -------------------------
# Extractors / helpers
# -------------------------


def _detection_error_code(event: dict) -> str | None:
    """
    The AWS API error code on the event that triggered a detection, if
    any -- checked on both a signal-level event's own "api" block and a
    correlation alert's primary_signal.api (same dual-shape reasoning as
    _request_parameters below).
    """
    api = event.get("api") or {}
    if isinstance(api, dict):
        error_code = api.get("error_code")
        if error_code:
            return error_code

    primary_signal = event.get("primary_signal") or {}
    if isinstance(primary_signal, dict):
        api = primary_signal.get("api") or {}
        if isinstance(api, dict):
            return api.get("error_code") or None

    return None


def _request_parameters(event: dict) -> dict:
    """
    Locate CloudTrail's requestParameters wherever it lives on a detection
    event.

    A signal-triggered alert (processor.py's alert_item) forwards the real
    raw_event verbatim, so requestParameters sits at
    raw_event.detail.requestParameters. A correlation alert
    (correlation_engine.py's _build_alert) has no top-level raw_event at
    all -- the closest equivalent is the trimmed
    primary_signal.raw_event_min.detail.requestParameters snapshot. Every
    extractor below that reads requestParameters goes through here so both
    shapes work without duplicating the fallback five times.
    """
    raw_event = event.get("raw_event") or {}
    if isinstance(raw_event, dict):
        detail = raw_event.get("detail") or {}
        if isinstance(detail, dict):
            req = detail.get("requestParameters")
            if isinstance(req, dict) and req:
                return req

    primary_signal = event.get("primary_signal") or {}
    if isinstance(primary_signal, dict):
        raw_min = primary_signal.get("raw_event_min") or {}
        if isinstance(raw_min, dict):
            detail = raw_min.get("detail") or {}
            if isinstance(detail, dict):
                req = detail.get("requestParameters")
                if isinstance(req, dict):
                    return req

    return {}


def _resource_by_type(event: dict, *types: str) -> dict | None:
    """
    Fallback for source == "guardduty" (and any future non-CloudTrail
    source) where the raw_event.detail.{responseElements,userIdentity,
    requestParameters} fields the extractors below are built around
    don't exist. Reads the normalized `resources` list processor.py
    forwards on alert_item (see src/domain/ocsf_min_parser.py's resource
    extraction) -- each entry is a ResourceRef.__dict__ (type/id/name).
    """
    for r in event.get("resources") or []:
        if isinstance(r, dict) and r.get("type") in types:
            return r
    return None


def _extract_user_and_access_key(event: dict) -> tuple[str | None, str | None]:
    """
    For CreateAccessKey / access-key detections.
    Try to pull both user_name and access_key_id.
    """
    user_name: str | None = None
    access_key_id: str | None = None

    raw_event = event.get("raw_event") or {}
    if isinstance(raw_event, dict):
        detail = raw_event.get("detail") or {}
        # userName from responseElements.accessKey.userName
        resp = detail.get("responseElements") or {}
        if isinstance(resp, dict):
            access_key_obj = resp.get("accessKey") or {}
            if isinstance(access_key_obj, dict):
                user_name = access_key_obj.get("userName")
                access_key_id = access_key_obj.get("accessKeyId")

        # Fallback: userIdentity.userName
        if not user_name:
            user_identity = detail.get("userIdentity") or {}
            if isinstance(user_identity, dict):
                user_name = user_identity.get("userName") or user_identity.get("principalId")

    if not user_name:
        r = _resource_by_type(event, "AWS::IAM::User")
        if r:
            user_name = r.get("id") or r.get("name")
    if not access_key_id:
        r = _resource_by_type(event, "AWS::IAM::AccessKey")
        if r:
            access_key_id = r.get("id") or r.get("name")

    return user_name, access_key_id


def _extract_user_name(event: dict) -> str | None:
    user_name: str | None = event.get("user_name")

    raw_event = event.get("raw_event") or {}
    if isinstance(raw_event, dict) and not user_name:
        detail = raw_event.get("detail") or {}
        user_identity = detail.get("userIdentity") or {}
        if isinstance(user_identity, dict):
            user_name = user_identity.get("userName") or user_identity.get("principalId")

        # Some IAM calls put userName in requestParameters
        if not user_name:
            req = detail.get("requestParameters") or {}
            if isinstance(req, dict):
                user_name = req.get("userName")

    # GuardDuty-sourced signals have no CloudTrail-shaped raw_event.detail
    # -- fall back to the normalized resources list (see
    # _resource_by_type). Checked before the correlation-specific
    # fallbacks below since those are alerter.py-only concepts.
    if not user_name:
        r = _resource_by_type(event, "AWS::IAM::User")
        if r:
            user_name = r.get("id") or r.get("name")

    # Correlation alerts have no raw_event at all -- the identity being
    # correlated on is group_value (when the rule groups by actor.user_name)
    # or, failing that, the primary signal's own actor.user_name.
    if not user_name:
        if event.get("group_by") == "actor.user_name":
            user_name = event.get("group_value") or None

    if not user_name:
        primary_signal = event.get("primary_signal") or {}
        if isinstance(primary_signal, dict):
            actor = primary_signal.get("actor") or {}
            if isinstance(actor, dict):
                user_name = actor.get("user_name") or None

    return user_name


def _extract_role_name(event: dict) -> str | None:
    role_name: str | None = event.get("target_value")
    return role_name or _request_parameters(event).get("roleName")


def _extract_account_id(event: dict) -> str | None:
    """
    Pull the originating AWS account off a detection_event.

    Checked in order:
      1) top-level "cloud_account_id" -- signal-level alerts
         (processor.py's alert_item; also used for role selection).
      2) "primary_signal.cloud_account_id" -- correlation-level alerts
         (correlation_engine.py's alert has no top-level account field;
         the account lives on the signal snapshot instead).
      3) "primary_signal.raw_event_min.account" -- same shape, deeper
         fallback if cloud_account_id itself is empty.
      4) legacy/hand-crafted event shapes: top-level "aws_account_id",
         raw_event.account, raw_event.detail.recipientAccountId.
    """
    account_id: str | None = event.get("cloud_account_id") or None

    if not account_id:
        primary_signal = event.get("primary_signal") or {}
        if isinstance(primary_signal, dict):
            account_id = primary_signal.get("cloud_account_id") or None
            if not account_id:
                raw_event_min = primary_signal.get("raw_event_min") or {}
                if isinstance(raw_event_min, dict):
                    account_id = raw_event_min.get("account") or None

    if not account_id:
        account_id = event.get("aws_account_id")

        raw_event = event.get("raw_event") or {}
        if isinstance(raw_event, dict):
            account_id = account_id or raw_event.get("account")
            detail = raw_event.get("detail") or {}
            if isinstance(detail, dict):
                account_id = account_id or detail.get("recipientAccountId")

    return account_id


def _extract_bucket_name(event: dict) -> str | None:
    bucket: str | None = event.get("target_value")
    bucket = bucket or _request_parameters(event).get("bucketName")
    if not bucket:
        r = _resource_by_type(event, "AWS::S3::Bucket")
        if r:
            bucket = r.get("id") or r.get("name")
    return bucket


def _extract_bucket_and_key(event: dict) -> tuple[str | None, str | None]:
    bucket = _extract_bucket_name(event)
    req = _request_parameters(event)
    # CloudTrail commonly uses "key" for S3 object key
    key: str | None = req.get("key") or req.get("keyName")

    return bucket, key


def _extract_rds_snapshot(event: dict) -> tuple[str | None, str]:
    """
    For ModifyDBSnapshotAttribute detections (rule 019_rds_snapshot_public).
    Returns (snapshot_id, snapshot_type) -- "instance" or "cluster",
    whichever CloudTrail's requestParameters actually carries.
    """
    req = _request_parameters(event)
    snapshot_id = req.get("dBSnapshotIdentifier")
    if snapshot_id:
        return snapshot_id, "instance"
    return req.get("dBClusterSnapshotIdentifier"), "cluster"


def _extract_inline_policy_principal(event: dict) -> tuple[str | None, str | None, str | None]:
    """
    For PutUserPolicy/PutRolePolicy/PutGroupPolicy detections (rule
    010_wildcard_inline_policy). Returns (user_name, role_name, policy_name).
    Group policies aren't supported by dredge's delete_inline_policy today
    -- user_name/role_name only, matching put_deny_all_inline_policy's own
    scope -- so a PutGroupPolicy event comes back with both None, which the
    caller treats as unsupported rather than guessing at a group_name arg
    dredge doesn't accept.
    """
    req = _request_parameters(event)
    return req.get("userName"), req.get("roleName"), req.get("policyName")


def _extract_instance_ids(event: dict) -> list[str]:
    """
    Try to get one or more EC2 instance IDs.
    """
    instance_ids: list[str] = []

    # Simple heuristic: target_value might be a single instance id
    target_value = event.get("target_value")
    if isinstance(target_value, str) and target_value.startswith("i-"):
        instance_ids.append(target_value)

    req = _request_parameters(event)

    # Some APIs pass a list or a single id
    ids = req.get("instancesSet") or req.get("instanceIds") or []
    if isinstance(ids, list):
        for item in ids:
            if isinstance(item, str) and item.startswith("i-"):
                instance_ids.append(item)
            elif isinstance(item, dict) and "instanceId" in item:
                instance_ids.append(item["instanceId"])

    # Fallback: single instanceId
    single_id = req.get("instanceId")
    if isinstance(single_id, str) and single_id.startswith("i-"):
        instance_ids.append(single_id)

    # GuardDuty-sourced signals: collect every matching resource, not
    # just the first (a finding can in principle list more than one).
    for r in event.get("resources") or []:
        if isinstance(r, dict) and r.get("type") == "AWS::EC2::Instance":
            rid = r.get("id") or r.get("name")
            if rid:
                instance_ids.append(rid)

    # Deduplicate
    return sorted(set(instance_ids))


def _extract_security_group_rule_change(event: dict) -> tuple[str | None, list[dict], list[dict]]:
    """
    Translate a CloudTrail AuthorizeSecurityGroupIngress/Egress event's
    requestParameters into the (group_id, ingress_rules, egress_rules)
    shape dredge.aws_ir.response.deauthorize_security_group_rules expects.

    CloudTrail's own shape is camelCase and wraps repeated structs under
    "items" (ipPermissions.items[].ipRanges.items[].cidrIp); dredge/boto3
    expects flat PascalCase IpPermissions dicts (IpProtocol/FromPort/
    ToPort/IpRanges). Only CIDR-based rules are translated -- IPv6 ranges,
    prefix lists, and security-group-reference sources (UserIdGroupPairs)
    are out of scope for this pass and are silently skipped rather than
    guessed at; see docs/incident-response.md.

    Always CloudTrail-sourced (no GuardDuty finding type maps to a
    security-group rule change), so no resources[]-based fallback is
    needed the way other extractors have one.
    """
    req = _request_parameters(event)
    group_id = req.get("groupId")
    if not isinstance(group_id, str) or not group_id:
        group_id = None

    def _translate(raw_permissions: Any) -> list[dict]:
        items = (raw_permissions or {}).get("items") if isinstance(raw_permissions, dict) else None
        translated: list[dict] = []
        for perm in items or []:
            if not isinstance(perm, dict):
                continue
            ip_ranges = [
                {"CidrIp": r["cidrIp"]}
                for r in (perm.get("ipRanges") or {}).get("items", [])
                if isinstance(r, dict) and r.get("cidrIp")
            ]
            if not ip_ranges:
                continue
            translated_perm: dict = {"IpProtocol": perm.get("ipProtocol", "-1"), "IpRanges": ip_ranges}
            if perm.get("fromPort") is not None:
                translated_perm["FromPort"] = perm["fromPort"]
            if perm.get("toPort") is not None:
                translated_perm["ToPort"] = perm["toPort"]
            translated.append(translated_perm)
        return translated

    activity_name = event.get("activity_name", "")
    ingress_rules: list[dict] = []
    egress_rules: list[dict] = []
    if activity_name == "AuthorizeSecurityGroupIngress":
        ingress_rules = _translate(req.get("ipPermissions"))
    elif activity_name == "AuthorizeSecurityGroupEgress":
        egress_rules = _translate(req.get("ipPermissions"))

    return group_id, ingress_rules, egress_rules


# -------------------------
# Individual response handlers
# -------------------------


def _handle_disable_access_key(dredge: Dredge, event: dict) -> OperationResult:
    """
    Response module: disable_access_key
    Used for detections like "new access key created" or "suspicious key usage".
    """
    user_name, access_key_id = _extract_user_and_access_key(event)

    if not user_name or not access_key_id:
        return OperationResult(
            operation="disable_access_key",
            target=f"user={user_name},access_key_id={access_key_id}",
            success=False,
            details={
                "reason": "Missing user_name or access_key_id in detection_event",
                "event_excerpt": {
                    "user_name": user_name,
                    "access_key_id": access_key_id,
                },
            },
            errors=["Missing user_name or access_key_id"],
        )

    return dredge.aws_ir.response.disable_access_key(
        user_name=user_name,
        access_key_id=access_key_id,
    )


def _handle_disable_user(dredge: Dredge, event: dict) -> OperationResult:
    """
    Disable an IAM user completely (keys, groups, policies, login profile).
    """
    user_name = _extract_user_name(event)

    if not user_name:
        return OperationResult(
            operation="disable_user",
            target="user=None",
            success=False,
            details={"reason": "Missing user_name in detection_event"},
            errors=["Missing user_name"],
        )

    return dredge.aws_ir.response.disable_user(user_name=user_name)


def _handle_delete_user(dredge: Dredge, event: dict) -> OperationResult:
    """
    Disable + delete an IAM user.
    """
    user_name = _extract_user_name(event)

    if not user_name:
        return OperationResult(
            operation="delete_user",
            target="user=None",
            success=False,
            details={"reason": "Missing user_name in detection_event"},
            errors=["Missing user_name"],
        )

    return dredge.aws_ir.response.delete_user(user_name=user_name)


def _handle_disable_role(dredge: Dredge, event: dict) -> OperationResult:
    """
    Detach policies + clear trust relationship for a role.
    """
    role_name = _extract_role_name(event)

    if not role_name:
        return OperationResult(
            operation="disable_role",
            target="role=None",
            success=False,
            details={"reason": "Missing role_name / target_value in detection_event"},
            errors=["Missing role_name"],
        )

    return dredge.aws_ir.response.disable_role(role_name=role_name)


def _handle_revoke_active_sessions(dredge: Dredge, event: dict) -> OperationResult:
    """
    Attach a deny-all inline policy conditioned on aws:TokenIssueTime --
    invalidates active STS sessions without touching permanent access
    keys (narrower than disable_user, useful when the credential itself
    isn't confirmed compromised but an active session might be).
    """
    user_name = _extract_user_name(event)

    if not user_name:
        return OperationResult(
            operation="revoke_active_sessions",
            target="user=None",
            success=False,
            details={"reason": "Missing user_name in detection_event"},
            errors=["Missing user_name"],
        )

    return dredge.aws_ir.response.revoke_active_sessions(user_name=user_name)


def _handle_block_s3_public_access(dredge: Dredge, event: dict) -> OperationResult:
    """
    Enable S3 Block Public Access at the *account* level.
    """
    account_id = _extract_account_id(event)

    if not account_id:
        return OperationResult(
            operation="block_s3_public_access",
            target="account=None",
            success=False,
            details={"reason": "Missing aws_account_id / account in detection_event"},
            errors=["Missing aws_account_id"],
        )

    return dredge.aws_ir.response.block_s3_public_access(account_id=account_id)


def _handle_block_s3_bucket_public_access(dredge: Dredge, event: dict) -> OperationResult:
    """
    Make a bucket private (BlockPublicAccess + private ACL + drop policy).
    """
    bucket_name = _extract_bucket_name(event)

    if not bucket_name:
        return OperationResult(
            operation="block_s3_bucket_public_access",
            target="bucket=None",
            success=False,
            details={"reason": "Missing bucketName / target_value in detection_event"},
            errors=["Missing bucket_name"],
        )

    return dredge.aws_ir.response.block_s3_bucket_public_access(bucket_name=bucket_name)


def _handle_quarantine_s3_bucket(dredge: Dredge, event: dict) -> OperationResult:
    """
    Block Public Access + a deny-all bucket policy for any principal
    outside this account -- broader containment than
    block_s3_bucket_public_access, which only strips public exposure and
    leaves cross-account access untouched.
    """
    bucket_name = _extract_bucket_name(event)

    if not bucket_name:
        return OperationResult(
            operation="quarantine_s3_bucket",
            target="bucket=None",
            success=False,
            details={"reason": "Missing bucketName / target_value in detection_event"},
            errors=["Missing bucket_name"],
        )

    return dredge.aws_ir.response.quarantine_s3_bucket(
        bucket_name=bucket_name,
        account_id=_extract_account_id(event),
    )


def _handle_block_s3_object_public_access(dredge: Dredge, event: dict) -> OperationResult:
    """
    Make a single S3 object private (ACL=private).
    """
    bucket_name, key = _extract_bucket_and_key(event)

    if not bucket_name or not key:
        return OperationResult(
            operation="block_s3_object_public_access",
            target=f"bucket={bucket_name},key={key}",
            success=False,
            details={
                "reason": "Missing bucket or key in detection_event",
                "event_excerpt": {"bucket": bucket_name, "key": key},
            },
            errors=["Missing bucket or key"],
        )

    return dredge.aws_ir.response.block_s3_object_public_access(
        bucket_name=bucket_name,
        key=key,
    )


def _handle_isolate_ec2_instances(dredge: Dredge, event: dict) -> OperationResult:
    """
    Replace SGs of one or more instances with a forensic isolation SG.
    """
    instance_ids = _extract_instance_ids(event)

    if not instance_ids:
        return OperationResult(
            operation="isolate_ec2_instances",
            target="instances=[]",
            success=False,
            details={"reason": "No instance_ids found in detection_event"},
            errors=["Missing instance_ids"],
        )

    return dredge.aws_ir.response.isolate_ec2_instances(instance_ids=instance_ids)


def _handle_deauthorize_security_group_rules(dredge: Dredge, event: dict) -> OperationResult:
    """
    Revoke the specific ingress/egress rule a CloudTrail
    AuthorizeSecurityGroupIngress/Egress event just added -- narrower than
    isolate_ec2_instances (only the one rule, not every instance in the
    group), for rule 011_security_group_opened.
    """
    group_id, ingress_rules, egress_rules = _extract_security_group_rule_change(event)

    if not group_id or (not ingress_rules and not egress_rules):
        return OperationResult(
            operation="deauthorize_security_group_rules",
            target=f"sg={group_id}",
            success=False,
            details={
                "reason": "Missing group_id or a translatable ingress/egress rule in detection_event",
                "event_excerpt": {"group_id": group_id, "ingress_rules": ingress_rules, "egress_rules": egress_rules},
            },
            errors=["Missing group_id or rule"],
        )

    return dredge.aws_ir.response.deauthorize_security_group_rules(
        group_id=group_id,
        ingress_rules=ingress_rules or None,
        egress_rules=egress_rules or None,
    )


def _handle_disable_lambda_function(dredge: Dredge, event: dict) -> OperationResult:
    """
    Throttle a Lambda function to zero reserved concurrency, for rule
    008_lambda_modified.
    """
    function_name = _request_parameters(event).get("functionName")

    if not function_name:
        return OperationResult(
            operation="disable_lambda_function",
            target="function=None",
            success=False,
            details={"reason": "Missing functionName in detection_event"},
            errors=["Missing function_name"],
        )

    return dredge.aws_ir.response.disable_lambda_function(function_name=function_name)


def _handle_disable_secrets_manager_secret(dredge: Dredge, event: dict) -> OperationResult:
    """
    Schedule a Secrets Manager secret for deletion (recoverable within the
    default 7-day window), for rule 016_secretsmanager_accessed. The
    riskiest of the three modules added this pass -- a real deletion
    schedule on a single credential-access signal, not a reversible
    toggle like the other two.
    """
    secret_id = _request_parameters(event).get("secretId")

    if not secret_id:
        return OperationResult(
            operation="disable_secrets_manager_secret",
            target="secret=None",
            success=False,
            details={"reason": "Missing secretId in detection_event"},
            errors=["Missing secret_id"],
        )

    return dredge.aws_ir.response.disable_secrets_manager_secret(secret_id=secret_id)


def _handle_enable_cloudtrail_logging(dredge: Dredge, event: dict) -> OperationResult:
    """
    Re-enable a stopped/tampered CloudTrail trail, for rule
    012_cloudtrail_tampered. Only fixes StopLogging/UpdateTrail --
    DeleteTrail leaves nothing for start_logging to re-enable (the trail
    itself is gone), which surfaces as a normal TrailNotFoundException
    failure rather than being special-cased here.
    """
    trail_name = _request_parameters(event).get("name")

    if not trail_name:
        return OperationResult(
            operation="enable_cloudtrail_logging",
            target="trail=None",
            success=False,
            details={"reason": "Missing name in detection_event"},
            errors=["Missing trail_name"],
        )

    return dredge.aws_ir.response.enable_cloudtrail_logging(trail_name=trail_name)


def _handle_enable_guardduty_detector(dredge: Dredge, event: dict) -> OperationResult:
    """
    Re-enable a disabled GuardDuty detector, for rule
    013_guardduty_tampered. Only fixes UpdateDetector -- DeleteDetector/
    DisassociateFromMasterAccount/DisassociateMembers carry no usable
    detector_id (or the detector itself is gone), surfacing as a
    missing-field failure here rather than being special-cased.
    """
    detector_id = _request_parameters(event).get("detectorId")

    if not detector_id:
        return OperationResult(
            operation="enable_guardduty_detector",
            target="detector=None",
            success=False,
            details={"reason": "Missing detectorId in detection_event"},
            errors=["Missing detector_id"],
        )

    return dredge.aws_ir.response.enable_guardduty_detector(detector_id=detector_id)


def _handle_start_config_recorder(dredge: Dredge, event: dict) -> OperationResult:
    """
    Re-start a stopped AWS Config recorder, for rule
    014_config_recorder_stopped. Only fixes StopConfigurationRecorder --
    DeleteConfigurationRecorder/DeleteDeliveryChannel carry no
    configurationRecorderName, surfacing as a missing-field failure here
    rather than being special-cased.
    """
    recorder_name = _request_parameters(event).get("configurationRecorderName")

    if not recorder_name:
        return OperationResult(
            operation="start_config_recorder",
            target="recorder=None",
            success=False,
            details={"reason": "Missing configurationRecorderName in detection_event"},
            errors=["Missing recorder_name"],
        )

    return dredge.aws_ir.response.start_config_recorder(recorder_name=recorder_name)


def _handle_enable_security_hub(dredge: Dredge, event: dict) -> OperationResult:
    """
    Re-enable Security Hub for this account/region, for rule
    015_security_hub_disabled. No identifiers needed from the event --
    DisableSecurityHub is account/region-scoped, and responder already
    assumed the right account's IR role before this handler runs.
    """
    return dredge.aws_ir.response.enable_security_hub()


def _handle_revoke_rds_snapshot_public_access(dredge: Dredge, event: dict) -> OperationResult:
    """
    Remove "all" from an RDS/cluster snapshot's restore attribute, for
    rule 019_rds_snapshot_public.
    """
    snapshot_id, snapshot_type = _extract_rds_snapshot(event)

    if not snapshot_id:
        return OperationResult(
            operation="revoke_rds_snapshot_public_access",
            target="snapshot=None",
            success=False,
            details={"reason": "Missing dBSnapshotIdentifier/dBClusterSnapshotIdentifier in detection_event"},
            errors=["Missing snapshot_id"],
        )

    return dredge.aws_ir.response.revoke_rds_snapshot_public_access(
        snapshot_id=snapshot_id, snapshot_type=snapshot_type
    )


def _handle_delete_inline_policy(dredge: Dredge, event: dict) -> OperationResult:
    """
    Remove a single offending inline policy, for rule
    010_wildcard_inline_policy. Group policies (PutGroupPolicy) aren't
    supported -- see _extract_inline_policy_principal.
    """
    user_name, role_name, policy_name = _extract_inline_policy_principal(event)

    if not policy_name or (not user_name and not role_name):
        return OperationResult(
            operation="delete_inline_policy",
            target="policy=None",
            success=False,
            details={
                "reason": (
                    "Missing policyName, or missing both userName/roleName "
                    "(group inline policies are not supported), in detection_event"
                ),
            },
            errors=["Missing user_name/role_name or policy_name"],
        )

    return dredge.aws_ir.response.delete_inline_policy(
        user_name=user_name, role_name=role_name, policy_name=policy_name
    )


# ---------------------------------------------------------------------------
# Mapping: response_module -> handler
# ---------------------------------------------------------------------------

# EKS/Kubernetes pod isolation and ECS Fargate task network isolation are
# NOT available as response modules -- dredge has no support for either
# today (no eks boto3 client registered, no Kubernetes client dependency
# at all). See docs/incident-response.md#known-gaps-in-automated-response-coverage
# before assuming a missing "isolate_eks_pod"-style entry here is a typo.
RESPONSE_MODULE_HANDLERS: dict[str, Callable[[Dredge, dict], OperationResult]] = {
    # IAM keys / users / roles
    "disable_access_key": _handle_disable_access_key,
    "disable_user": _handle_disable_user,
    "delete_user": _handle_delete_user,
    "disable_role": _handle_disable_role,
    "revoke_active_sessions": _handle_revoke_active_sessions,
    "delete_inline_policy": _handle_delete_inline_policy,
    # S3 containment
    "block_s3_public_access": _handle_block_s3_public_access,
    "block_s3_bucket_public_access": _handle_block_s3_bucket_public_access,
    "block_s3_object_public_access": _handle_block_s3_object_public_access,
    "quarantine_s3_bucket": _handle_quarantine_s3_bucket,
    # EC2
    "isolate_ec2_instances": _handle_isolate_ec2_instances,
    "deauthorize_security_group_rules": _handle_deauthorize_security_group_rules,
    # Lambda
    "disable_lambda_function": _handle_disable_lambda_function,
    # Secrets Manager
    "disable_secrets_manager_secret": _handle_disable_secrets_manager_secret,
    # RDS
    "revoke_rds_snapshot_public_access": _handle_revoke_rds_snapshot_public_access,
    # Security tooling re-enablement (see docs/incident-response.md#known-gaps-in-automated-response-coverage)
    "enable_cloudtrail_logging": _handle_enable_cloudtrail_logging,
    "enable_guardduty_detector": _handle_enable_guardduty_detector,
    "start_config_recorder": _handle_start_config_recorder,
    "enable_security_hub": _handle_enable_security_hub,
}

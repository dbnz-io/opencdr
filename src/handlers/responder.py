# src/handlers/responder.py

from __future__ import annotations

import json
import os
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import boto3
from boto3.dynamodb.conditions import Key

from dredge import Dredge, DredgeConfig
from dredge.auth import AwsAuthConfig
from dredge.aws_ir.models import OperationResult

from ..infra.logger import Logger
from ..infra.metrics import emit_metric
from ..infra.xray_setup import patch_boto3

patch_boto3()

LAMBDA_NAME = os.getenv("LAMBDA_NAME", "unknown")
_SERVICE = os.getenv("SERVICE_NAME", "OPENCDR")

OUTBOX_TABLE_NAME = os.getenv("OUTBOX_TABLE_NAME", "")
_outbox_table = boto3.resource("dynamodb").Table(OUTBOX_TABLE_NAME) if OUTBOX_TABLE_NAME else None

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
    (service, timestamp) key -- no Scan.
    """
    cutoff = (datetime.now(UTC) - timedelta(minutes=RATE_LIMIT_WINDOW_MINUTES)).isoformat()

    count = 0
    query_kwargs: dict = {
        "KeyConditionExpression": Key("service").eq(_SERVICE) & Key("timestamp").gte(cutoff),
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
            return count
        query_kwargs["ExclusiveStartKey"] = last_key
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
    dry_run = os.environ.get("DREDGE_DRY_RUN", "false").lower() == "true"

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


def _extract_user_and_access_key(event: dict) -> tuple[str | None, str | None]:
    """
    For CreateAccessKey / access-key detections.
    Try to pull both user_name and access_key_id.
    """
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

    return user_name


def _extract_role_name(event: dict) -> str | None:
    role_name: str | None = event.get("target_value")

    raw_event = event.get("raw_event") or {}
    if isinstance(raw_event, dict):
        detail = raw_event.get("detail") or {}
        req = detail.get("requestParameters") or {}
        if isinstance(req, dict):
            role_name = role_name or req.get("roleName")

    return role_name


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

    raw_event = event.get("raw_event") or {}
    if isinstance(raw_event, dict):
        detail = raw_event.get("detail") or {}
        req = detail.get("requestParameters") or {}
        if isinstance(req, dict):
            bucket = bucket or req.get("bucketName")

    return bucket


def _extract_bucket_and_key(event: dict) -> tuple[str | None, str | None]:
    bucket = _extract_bucket_name(event)
    key: str | None = None

    raw_event = event.get("raw_event") or {}
    if isinstance(raw_event, dict):
        detail = raw_event.get("detail") or {}
        req = detail.get("requestParameters") or {}
        if isinstance(req, dict):
            # CloudTrail commonly uses "key" for S3 object key
            key = req.get("key") or req.get("keyName") or key

    return bucket, key


def _extract_instance_ids(event: dict) -> list[str]:
    """
    Try to get one or more EC2 instance IDs.
    """
    instance_ids: list[str] = []

    # Simple heuristic: target_value might be a single instance id
    target_value = event.get("target_value")
    if isinstance(target_value, str) and target_value.startswith("i-"):
        instance_ids.append(target_value)

    raw_event = event.get("raw_event") or {}
    if isinstance(raw_event, dict):
        detail = raw_event.get("detail") or {}
        req = detail.get("requestParameters") or {}

        if isinstance(req, dict):
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

    # Deduplicate
    return sorted(set(instance_ids))


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


# ---------------------------------------------------------------------------
# Mapping: response_module -> handler
# ---------------------------------------------------------------------------

RESPONSE_MODULE_HANDLERS: dict[str, Callable[[Dredge, dict], OperationResult]] = {
    # IAM keys / users / roles
    "disable_access_key": _handle_disable_access_key,
    "disable_user": _handle_disable_user,
    "delete_user": _handle_delete_user,
    "disable_role": _handle_disable_role,
    # S3 containment
    "block_s3_public_access": _handle_block_s3_public_access,
    "block_s3_bucket_public_access": _handle_block_s3_bucket_public_access,
    "block_s3_object_public_access": _handle_block_s3_object_public_access,
    # EC2
    "isolate_ec2_instances": _handle_isolate_ec2_instances,
}

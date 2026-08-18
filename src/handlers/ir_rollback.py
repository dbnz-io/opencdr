# src/handlers/ir_rollback.py

from __future__ import annotations

import json
import os
import uuid
from collections.abc import Callable
from datetime import UTC, datetime

import boto3
from dredge import Dredge
from dredge.aws_ir.models import OperationResult

from ..infra.aws_handler import ttl_expires_at
from ..infra.logger import Logger
from ..infra.metrics import emit_metric
from ..infra.xray_setup import patch_boto3
from .responder import (
    RATE_LIMIT_MAX_ACTIONS,
    RATE_LIMIT_WINDOW_MINUTES,
    _get_dredge,
    _operation_result_to_dict,
    _recent_action_count,
)

patch_boto3()

LAMBDA_NAME = os.getenv("LAMBDA_NAME", "unknown")
# Deliberately its own SERVICE_NAME (see serverless.yml's rollbackHandler
# environment), not responder's -- _recent_action_count() partitions the
# rate-limit query by this value (day_bucket_key(_SERVICE, ...)), so a
# distinct value gives rollbacks their own circuit-breaker budget rather
# than sharing/competing with responder's. Simpler to reason about than a
# cross-Lambda shared counter, and just as safe: neither a rollback storm
# nor a containment-action storm can starve the other's budget.
_SERVICE = os.getenv("SERVICE_NAME", "OPENCDR")

IR_ACTIONS_TABLE_NAME = os.getenv("IR_ACTIONS_TABLE_NAME", "")
_ir_actions_table = (
    boto3.resource("dynamodb").Table(IR_ACTIONS_TABLE_NAME) if IR_ACTIONS_TABLE_NAME else None
)

OUTBOX_TABLE_NAME = os.getenv("OUTBOX_TABLE_NAME", "")
_outbox_table = boto3.resource("dynamodb").Table(OUTBOX_TABLE_NAME) if OUTBOX_TABLE_NAME else None


def _mark_rollback_status(detection_id: str, *, status: str, logger: Logger, error: str | None = None) -> None:
    """
    Writes rollback_status ("pending" is set by api.py at enqueue time,
    not here) so GET /ir-actions reflects something more specific than
    the binary rolled_back flag ever could -- "pending" vs "failed, here's
    why" vs "never attempted" all used to collapse into the same "active"
    state in the UI. Best-effort: a status-write failure must never be
    treated as the rollback itself failing (if status="succeeded") or
    crash processing of an already-identified failure (if status="failed").
    """
    if _ir_actions_table is None:
        return
    try:
        expr = "SET rollback_status = :status, rollback_updated_at = :ts"
        values: dict = {":status": status, ":ts": datetime.now(UTC).isoformat()}
        if error is not None:
            expr += ", rollback_error = :err"
            values[":err"] = error[:1000]  # bound a runaway exception message
        else:
            expr += " REMOVE rollback_error"
        _ir_actions_table.update_item(
            Key={"detection_id": detection_id},
            UpdateExpression=expr,
            ExpressionAttributeValues=values,
        )
    except Exception as e:
        logger.error(
            event_name="IR_ROLLBACK_STATUS_UPDATE_FAILED",
            event_type="ERROR",
            message="Failed to write rollback_status",
            details={"detection_id": detection_id, "status": status, "error": repr(e)},
        )


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
            event_name="IR_ROLLBACK_INVALID_JSON",
            event_type="ERROR",
            message="SQS message body is not valid JSON",
            details={"receipt_handle": receipt_handle, "body": body},
        )
        return

    detection_id = payload.get("detection_id")

    if not detection_id:
        logger.error(
            event_name="IR_ROLLBACK_MISSING_DETECTION_ID",
            event_type="ERROR",
            message="Rollback message has no detection_id, skipping",
            details={"receipt_handle": receipt_handle},
        )
        return

    if _ir_actions_table is None:
        logger.error(
            event_name="IR_ROLLBACK_NO_TABLE",
            event_type="ERROR",
            message="IR_ACTIONS_TABLE_NAME not configured, cannot process rollback",
            details={"detection_id": detection_id, "receipt_handle": receipt_handle},
        )
        return

    resp = _ir_actions_table.get_item(Key={"detection_id": detection_id})
    item = resp.get("Item")

    if not item:
        logger.error(
            event_name="IR_ROLLBACK_ACTION_NOT_FOUND",
            event_type="ERROR",
            message="No recorded IR action for this detection_id, skipping rollback",
            details={"detection_id": detection_id, "receipt_handle": receipt_handle},
        )
        return

    response_module = item.get("response_module")

    if not item.get("rollback_supported"):
        logger.error(
            event_name="IR_ROLLBACK_NOT_SUPPORTED",
            event_type="ERROR",
            message="This action's rollback is not supported (no captured rollback state), skipping",
            details={"detection_id": detection_id, "response_module": response_module},
        )
        _mark_rollback_status(detection_id, status="failed", logger=logger, error="Rollback is not supported for this action")
        return

    if item.get("rolled_back"):
        logger.info(
            event_name="IR_ROLLBACK_ALREADY_DONE",
            event_type="PROCESSING",
            message="Action already rolled back, skipping",
            details={"detection_id": detection_id, "response_module": response_module},
        )
        return

    handler = ROLLBACK_MODULE_HANDLERS.get(response_module)

    if not handler:
        logger.error(
            event_name="IR_ROLLBACK_UNKNOWN_MODULE",
            event_type="ERROR",
            message="No rollback handler registered for this response_module",
            details={"detection_id": detection_id, "response_module": response_module},
        )
        _mark_rollback_status(detection_id, status="failed", logger=logger, error=f"No rollback handler registered for {response_module}")
        return

    role_arn = item.get("role_arn")

    if not role_arn:
        logger.error(
            event_name="IR_ROLLBACK_NO_ROLE_ARN",
            event_type="ERROR",
            message="Recorded action has no role_arn, cannot assume role for rollback",
            details={"detection_id": detection_id, "response_module": response_module},
        )
        _mark_rollback_status(detection_id, status="failed", logger=logger, error="Recorded action has no role_arn")
        return

    try:
        rollback_kwargs = json.loads(item.get("rollback_kwargs") or "{}")
    except json.JSONDecodeError as e:
        logger.error(
            event_name="IR_ROLLBACK_INVALID_STATE",
            event_type="ERROR",
            message="Stored rollback_kwargs is not valid JSON",
            details={"detection_id": detection_id, "response_module": response_module, "error": repr(e)},
        )
        _mark_rollback_status(detection_id, status="failed", logger=logger, error="Stored rollback state is corrupt (invalid JSON)")
        return

    # Circuit breaker: fail closed both when the limit is tripped and when
    # we can't determine the recent count at all -- same policy as
    # responder.py's original-action path.
    try:
        recent_count = _recent_action_count()
    except Exception as e:
        logger.error(
            event_name="IR_ROLLBACK_RATE_LIMIT_CHECK_FAILED",
            event_type="ERROR",
            message="Failed to check rollback rate limit; skipping",
            details={"detection_id": detection_id, "response_module": response_module, "error": repr(e)},
        )
        _mark_rollback_status(detection_id, status="failed", logger=logger, error="Failed to check the rollback rate limit")
        return

    if recent_count >= RATE_LIMIT_MAX_ACTIONS:
        logger.error(
            event_name="IR_ROLLBACK_CIRCUIT_BREAKER_TRIPPED",
            event_type="PROCESSING",
            message=(
                f"Circuit breaker tripped: {recent_count} actions in the last "
                f"{RATE_LIMIT_WINDOW_MINUTES}m (limit {RATE_LIMIT_MAX_ACTIONS}); "
                "skipping this rollback"
            ),
            details={
                "detection_id": detection_id,
                "response_module": response_module,
                "recent_action_count": recent_count,
                "rate_limit_window_minutes": RATE_LIMIT_WINDOW_MINUTES,
                "rate_limit_max_actions": RATE_LIMIT_MAX_ACTIONS,
            },
        )
        _mark_rollback_status(
            detection_id,
            status="failed",
            logger=logger,
            error=f"Rollback rate limit exceeded ({recent_count}/{RATE_LIMIT_MAX_ACTIONS} in {RATE_LIMIT_WINDOW_MINUTES}m) -- try again shortly",
        )
        return

    try:
        dredge = _get_dredge(role_arn)
    except Exception as e:
        logger.error(
            event_name="IR_ROLLBACK_ASSUME_ROLE_FAILED",
            event_type="ERROR",
            message="Failed to assume the recorded IR role; skipping rollback",
            details={
                "detection_id": detection_id,
                "response_module": response_module,
                "role_arn": role_arn,
                "error": repr(e),
            },
        )
        _mark_rollback_status(detection_id, status="failed", logger=logger, error=f"Failed to assume {role_arn}: {e}")
        return

    try:
        result = handler(dredge, rollback_kwargs)
    except Exception as e:
        logger.error(
            event_name="IR_ROLLBACK_EXCEPTION",
            event_type="ERROR",
            message="Exception while executing rollback action",
            details={"detection_id": detection_id, "response_module": response_module, "error": repr(e)},
        )
        _mark_rollback_status(detection_id, status="failed", logger=logger, error=str(e))
        return

    log_fn = logger.info if result.success else logger.error
    event_name = "IR_ROLLBACK_SUCCESS" if result.success else "IR_ROLLBACK_FAILED"

    emit_metric(
        "ResponderRollbacksExecuted",
        dimensions={
            "response_module": str(response_module),
            "result": "success" if result.success else "failure",
        },
    )

    log_fn(
        event_name=event_name,
        event_type="PROCESSING",
        message=f"Executed rollback for: {response_module}",
        details={
            "detection_id": detection_id,
            "response_module": response_module,
            "undo_module": item.get("undo_module"),
            "operation_result": _operation_result_to_dict(result),
            "receipt_handle": receipt_handle,
        },
    )

    if result.success:
        try:
            _ir_actions_table.update_item(
                Key={"detection_id": detection_id},
                UpdateExpression=(
                    "SET rolled_back = :true, rolled_back_at = :ts, "
                    "rollback_status = :status, rollback_updated_at = :ts "
                    "REMOVE rollback_error"
                ),
                ExpressionAttributeValues={":true": True, ":ts": datetime.now(UTC).isoformat(), ":status": "succeeded"},
            )
        except Exception as e:
            logger.error(
                event_name="IR_ROLLBACK_STATE_UPDATE_FAILED",
                event_type="ERROR",
                message="Rollback executed successfully but failed to mark it as rolled back",
                details={"detection_id": detection_id, "response_module": response_module, "error": repr(e)},
            )

        if _outbox_table is not None:
            _notify_rollback_success(
                item=item,
                detection_id=detection_id,
                response_module=response_module,
                result=result,
                logger=logger,
            )
    else:
        # The undo call itself reached AWS and was rejected (permissions,
        # the resource no longer existing, etc.) -- distinct from every
        # earlier return above, which are all "never even attempted the
        # AWS call" failures. Previously invisible to the UI entirely:
        # result.success=False just fell through to the end of this
        # function with nothing written back to the item.
        _mark_rollback_status(
            detection_id,
            status="failed",
            logger=logger,
            error="; ".join(result.errors) if result.errors else "Rollback action failed (no error detail returned)",
        )


def _notify_rollback_success(
    *,
    item: dict,
    detection_id: str | None,
    response_module: str | None,
    result: OperationResult,
    logger: Logger,
) -> None:
    """
    Queues a notifications-only outbox item so a successful rollback shows
    up as a distinct (purple) message -- separate from the green
    remediation-success notification responder.py emits for the original
    action, so a rolled-back containment doesn't read as "still contained."
    Best-effort, same as responder.py's _notify_remediation_success: a
    failure here must never make an already-succeeded rollback look failed.
    """
    try:
        payload = {
            "type": "rollback_success",
            "notify": True,
            "detection_id": detection_id,
            "rule_id": item.get("rule_id"),
            "severity": "UNKNOWN",
            "response_module": response_module,
            "undo_module": item.get("undo_module"),
            "cloud_account_id": item.get("account_id"),
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
                "expires_at": ttl_expires_at(),
            }
        )
    except Exception as e:
        logger.error(
            event_name="IR_ROLLBACK_NOTIFY_FAILED",
            event_type="ERROR",
            message="Rollback executed successfully but failed to queue the success notification",
            details={"detection_id": detection_id, "response_module": response_module, "error": repr(e)},
        )


def lambda_handler(event: dict, context) -> dict:
    """
    SQS event handler. Expects messages whose body is JSON containing at
    least {"detection_id": "..."} -- see api.py's POST /ir-actions/{id}/rollback,
    the only producer of this queue's messages.
    """
    request_id = getattr(context, "aws_request_id", None)
    logger = Logger(
        service=_SERVICE,
        source=LAMBDA_NAME,
        request_id=request_id,
    )

    for record in event.get("Records", []):
        _process_record(record, request_id, record.get("receiptHandle"), logger)

    return {"statusCode": 200}


# ---------------------------------------------------------------------------
# Rollback-module handlers: response_module -> undo function
#
# Mirrors RESPONSE_MODULE_HANDLERS's shape (responder.py) exactly, but
# dispatches to dredge's undo functions (dredge/aws_ir/response.py,
# "Rollback / undo actions" section) with kwargs read straight out of the
# stored irActionsTable row rather than re-extracted from a detection
# event.
# ---------------------------------------------------------------------------


def _handle_enable_access_key(dredge: Dredge, kwargs: dict) -> OperationResult:
    return dredge.aws_ir.response.enable_access_key(**kwargs)


def _handle_revoke_deny_all_session_policy(dredge: Dredge, kwargs: dict) -> OperationResult:
    return dredge.aws_ir.response.revoke_deny_all_session_policy(**kwargs)


def _handle_authorize_security_group_rules(dredge: Dredge, kwargs: dict) -> OperationResult:
    return dredge.aws_ir.response.authorize_security_group_rules(**kwargs)


def _handle_restore_s3_account_public_access_block(dredge: Dredge, kwargs: dict) -> OperationResult:
    return dredge.aws_ir.response.restore_s3_account_public_access_block(**kwargs)


def _handle_restore_s3_bucket_public_access_block_and_acl(dredge: Dredge, kwargs: dict) -> OperationResult:
    return dredge.aws_ir.response.restore_s3_bucket_public_access_block_and_acl(**kwargs)


def _handle_restore_s3_object_acl(dredge: Dredge, kwargs: dict) -> OperationResult:
    return dredge.aws_ir.response.restore_s3_object_acl(**kwargs)


def _handle_restore_lambda_concurrency(dredge: Dredge, kwargs: dict) -> OperationResult:
    return dredge.aws_ir.response.restore_lambda_concurrency(**kwargs)


def _handle_restore_secrets_manager_secret(dredge: Dredge, kwargs: dict) -> OperationResult:
    return dredge.aws_ir.response.restore_secrets_manager_secret(**kwargs)


def _handle_restore_user(dredge: Dredge, kwargs: dict) -> OperationResult:
    return dredge.aws_ir.response.restore_user(**kwargs)


def _handle_restore_role(dredge: Dredge, kwargs: dict) -> OperationResult:
    return dredge.aws_ir.response.restore_role(**kwargs)


def _handle_restore_s3_bucket_quarantine(dredge: Dredge, kwargs: dict) -> OperationResult:
    return dredge.aws_ir.response.restore_s3_bucket_quarantine(**kwargs)


def _handle_restore_ec2_instance_security_groups(dredge: Dredge, kwargs: dict) -> OperationResult:
    return dredge.aws_ir.response.restore_ec2_instance_security_groups(**kwargs)


def _handle_restore_rds_snapshot_public_access(dredge: Dredge, kwargs: dict) -> OperationResult:
    return dredge.aws_ir.response.restore_rds_snapshot_public_access(**kwargs)


def _handle_restore_inline_policy(dredge: Dredge, kwargs: dict) -> OperationResult:
    return dredge.aws_ir.response.restore_inline_policy(**kwargs)


ROLLBACK_MODULE_HANDLERS: dict[str, Callable[[Dredge, dict], OperationResult]] = {
    "disable_access_key": _handle_enable_access_key,
    "revoke_active_sessions": _handle_revoke_deny_all_session_policy,
    "deauthorize_security_group_rules": _handle_authorize_security_group_rules,
    "block_s3_public_access": _handle_restore_s3_account_public_access_block,
    "block_s3_bucket_public_access": _handle_restore_s3_bucket_public_access_block_and_acl,
    "block_s3_object_public_access": _handle_restore_s3_object_acl,
    "disable_lambda_function": _handle_restore_lambda_concurrency,
    "disable_secrets_manager_secret": _handle_restore_secrets_manager_secret,
    "disable_user": _handle_restore_user,
    "disable_role": _handle_restore_role,
    "quarantine_s3_bucket": _handle_restore_s3_bucket_quarantine,
    "isolate_ec2_instances": _handle_restore_ec2_instance_security_groups,
    "revoke_rds_snapshot_public_access": _handle_restore_rds_snapshot_public_access,
    "delete_inline_policy": _handle_restore_inline_policy,
}

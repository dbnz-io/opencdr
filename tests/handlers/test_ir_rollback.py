"""Tests for the ir-rollback Lambda handler (src/handlers/ir_rollback.py)."""
from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

import os

os.environ.setdefault("LOGS_TABLE_NAME", "test-logs-table")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

from dredge.aws_ir.models import OperationResult
from src.handlers import ir_rollback


def make_record(body_obj) -> dict:
    return {"body": json.dumps(body_obj), "receiptHandle": "rh-1"}


def ok_result(operation="op", target="t") -> OperationResult:
    return OperationResult(operation=operation, target=target, success=True, details={"ok": True})


def make_item(**overrides) -> dict:
    item = {
        "detection_id": "d-1",
        "rule_id": "r-1",
        "response_module": "disable_access_key",
        "undo_module": "enable_access_key",
        "target": "user=alice,access_key_id=AKIA1",
        "account_id": "123456789012",
        "role_arn": "arn:aws:iam::123456789012:role/opencdr-dev-ir-role",
        "rollback_supported": True,
        "rollback_kwargs": json.dumps({"user_name": "alice", "access_key_id": "AKIA1"}),
        "rolled_back": False,
    }
    item.update(overrides)
    return item


@pytest.fixture()
def mock_dredge(monkeypatch):
    dredge = MagicMock()
    monkeypatch.setattr(ir_rollback, "_get_dredge", lambda role_arn=None: dredge)
    return dredge


@pytest.fixture()
def mock_table(monkeypatch):
    table = MagicMock()
    monkeypatch.setattr(ir_rollback, "_ir_actions_table", table)
    return table


@pytest.fixture()
def mock_outbox(monkeypatch):
    table = MagicMock()
    monkeypatch.setattr(ir_rollback, "_outbox_table", table)
    return table


@pytest.fixture(autouse=True)
def no_rate_limit(monkeypatch):
    monkeypatch.setattr(ir_rollback, "_recent_action_count", lambda: 0)


class TestRollbackModuleHandlersRegistry:
    def test_has_exactly_fourteen_entries(self):
        assert len(ir_rollback.ROLLBACK_MODULE_HANDLERS) == 14

    def test_dispatches_to_matching_dredge_undo_function(self, mock_dredge):
        mock_dredge.aws_ir.response.enable_access_key.return_value = ok_result()
        handler = ir_rollback.ROLLBACK_MODULE_HANDLERS["disable_access_key"]
        result = handler(mock_dredge, {"user_name": "alice", "access_key_id": "AKIA1"})
        mock_dredge.aws_ir.response.enable_access_key.assert_called_once_with(
            user_name="alice", access_key_id="AKIA1"
        )
        assert result.success is True

    def test_all_registered_handlers_call_the_expected_dredge_method(self, mock_dredge):
        expectations = {
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
        for response_module, dredge_method in expectations.items():
            getattr(mock_dredge.aws_ir.response, dredge_method).return_value = ok_result()
            ir_rollback.ROLLBACK_MODULE_HANDLERS[response_module](mock_dredge, {})
            getattr(mock_dredge.aws_ir.response, dredge_method).assert_called_once()


class TestMarkRollbackStatus:
    def test_writes_status_and_timestamp(self, mock_table):
        ir_rollback._mark_rollback_status("d-1", status="succeeded", logger=MagicMock())
        call_kwargs = mock_table.update_item.call_args.kwargs
        assert call_kwargs["Key"] == {"detection_id": "d-1"}
        assert call_kwargs["ExpressionAttributeValues"][":status"] == "succeeded"
        assert "rollback_updated_at" in call_kwargs["UpdateExpression"]

    def test_error_present_sets_rollback_error(self, mock_table):
        ir_rollback._mark_rollback_status("d-1", status="failed", logger=MagicMock(), error="AccessDenied")
        call_kwargs = mock_table.update_item.call_args.kwargs
        assert call_kwargs["ExpressionAttributeValues"][":err"] == "AccessDenied"
        assert "REMOVE rollback_error" not in call_kwargs["UpdateExpression"]

    def test_no_error_removes_rollback_error(self, mock_table):
        ir_rollback._mark_rollback_status("d-1", status="succeeded", logger=MagicMock())
        call_kwargs = mock_table.update_item.call_args.kwargs
        assert "REMOVE rollback_error" in call_kwargs["UpdateExpression"]
        assert ":err" not in call_kwargs["ExpressionAttributeValues"]

    def test_error_message_is_truncated(self, mock_table):
        ir_rollback._mark_rollback_status("d-1", status="failed", logger=MagicMock(), error="x" * 5000)
        call_kwargs = mock_table.update_item.call_args.kwargs
        assert len(call_kwargs["ExpressionAttributeValues"][":err"]) == 1000

    def test_no_table_configured_is_a_noop(self, monkeypatch):
        monkeypatch.setattr(ir_rollback, "_ir_actions_table", None)
        # Must not raise.
        ir_rollback._mark_rollback_status("d-1", status="failed", logger=MagicMock(), error="boom")

    def test_write_failure_is_logged_not_raised(self, mock_table):
        mock_table.update_item.side_effect = RuntimeError("dynamo down")
        logger = MagicMock()
        ir_rollback._mark_rollback_status("d-1", status="failed", logger=logger, error="boom")
        assert logger.error.call_args.kwargs["event_name"] == "IR_ROLLBACK_STATUS_UPDATE_FAILED"


class TestProcessRecordDispatch:
    def test_invalid_json_body_logged_and_skipped(self, mock_table):
        logger = MagicMock()
        record = {"body": "{not-json", "receiptHandle": "rh-1"}
        ir_rollback._process_record(record, "req-1", "rh-1", logger)
        logger.error.assert_called_once()
        assert logger.error.call_args.kwargs["event_name"] == "IR_ROLLBACK_INVALID_JSON"

    def test_missing_detection_id_logged_and_skipped(self, mock_table):
        logger = MagicMock()
        record = make_record({})
        ir_rollback._process_record(record, "req-1", "rh-1", logger)
        assert logger.error.call_args.kwargs["event_name"] == "IR_ROLLBACK_MISSING_DETECTION_ID"

    def test_no_table_configured_logged_and_skipped(self, monkeypatch):
        monkeypatch.setattr(ir_rollback, "_ir_actions_table", None)
        logger = MagicMock()
        record = make_record({"detection_id": "d-1"})
        ir_rollback._process_record(record, "req-1", "rh-1", logger)
        assert logger.error.call_args.kwargs["event_name"] == "IR_ROLLBACK_NO_TABLE"

    def test_action_not_found_logged_and_skipped(self, mock_table):
        mock_table.get_item.return_value = {}
        logger = MagicMock()
        record = make_record({"detection_id": "d-1"})
        ir_rollback._process_record(record, "req-1", "rh-1", logger)
        assert logger.error.call_args.kwargs["event_name"] == "IR_ROLLBACK_ACTION_NOT_FOUND"

    def test_rollback_not_supported_logged_and_skipped(self, mock_table):
        mock_table.get_item.return_value = {"Item": make_item(rollback_supported=False)}
        logger = MagicMock()
        record = make_record({"detection_id": "d-1"})
        ir_rollback._process_record(record, "req-1", "rh-1", logger)
        assert logger.error.call_args.kwargs["event_name"] == "IR_ROLLBACK_NOT_SUPPORTED"
        call_kwargs = mock_table.update_item.call_args.kwargs
        assert call_kwargs["ExpressionAttributeValues"][":status"] == "failed"
        assert "rollback is not supported" in call_kwargs["ExpressionAttributeValues"][":err"].lower()

    def test_already_rolled_back_logged_and_skipped(self, mock_table):
        mock_table.get_item.return_value = {"Item": make_item(rolled_back=True)}
        logger = MagicMock()
        record = make_record({"detection_id": "d-1"})
        ir_rollback._process_record(record, "req-1", "rh-1", logger)
        assert logger.info.call_args.kwargs["event_name"] == "IR_ROLLBACK_ALREADY_DONE"
        # Nothing to correct here -- rollback_status should already say
        # "succeeded" from whenever it actually completed; this early
        # return doesn't touch it either way.
        mock_table.update_item.assert_not_called()

    def test_unknown_response_module_logged_and_skipped(self, mock_table):
        mock_table.get_item.return_value = {"Item": make_item(response_module="not_a_real_module")}
        logger = MagicMock()
        record = make_record({"detection_id": "d-1"})
        ir_rollback._process_record(record, "req-1", "rh-1", logger)
        assert logger.error.call_args.kwargs["event_name"] == "IR_ROLLBACK_UNKNOWN_MODULE"
        assert mock_table.update_item.call_args.kwargs["ExpressionAttributeValues"][":status"] == "failed"

    def test_missing_role_arn_logged_and_skipped(self, mock_table):
        mock_table.get_item.return_value = {"Item": make_item(role_arn=None)}
        logger = MagicMock()
        record = make_record({"detection_id": "d-1"})
        ir_rollback._process_record(record, "req-1", "rh-1", logger)
        assert logger.error.call_args.kwargs["event_name"] == "IR_ROLLBACK_NO_ROLE_ARN"
        assert mock_table.update_item.call_args.kwargs["ExpressionAttributeValues"][":status"] == "failed"

    def test_invalid_rollback_kwargs_json_logged_and_skipped(self, mock_table):
        mock_table.get_item.return_value = {"Item": make_item(rollback_kwargs="{not-json")}
        logger = MagicMock()
        record = make_record({"detection_id": "d-1"})
        ir_rollback._process_record(record, "req-1", "rh-1", logger)
        assert logger.error.call_args.kwargs["event_name"] == "IR_ROLLBACK_INVALID_STATE"
        assert mock_table.update_item.call_args.kwargs["ExpressionAttributeValues"][":status"] == "failed"

    def test_circuit_breaker_tripped_skips_action(self, mock_table, mock_dredge, monkeypatch):
        monkeypatch.setattr(ir_rollback, "_recent_action_count", lambda: 999)
        mock_table.get_item.return_value = {"Item": make_item()}
        logger = MagicMock()
        record = make_record({"detection_id": "d-1"})
        ir_rollback._process_record(record, "req-1", "rh-1", logger)
        assert logger.error.call_args.kwargs["event_name"] == "IR_ROLLBACK_CIRCUIT_BREAKER_TRIPPED"
        mock_dredge.aws_ir.response.enable_access_key.assert_not_called()
        assert mock_table.update_item.call_args.kwargs["ExpressionAttributeValues"][":status"] == "failed"

    def test_rate_limit_check_failure_fails_closed(self, mock_table, mock_dredge, monkeypatch):
        def boom():
            raise RuntimeError("dynamo down")

        monkeypatch.setattr(ir_rollback, "_recent_action_count", boom)
        mock_table.get_item.return_value = {"Item": make_item()}
        logger = MagicMock()
        record = make_record({"detection_id": "d-1"})
        ir_rollback._process_record(record, "req-1", "rh-1", logger)
        assert logger.error.call_args.kwargs["event_name"] == "IR_ROLLBACK_RATE_LIMIT_CHECK_FAILED"
        mock_dredge.aws_ir.response.enable_access_key.assert_not_called()
        assert mock_table.update_item.call_args.kwargs["ExpressionAttributeValues"][":status"] == "failed"

    def test_assume_role_failure_logged_and_skipped(self, mock_table, monkeypatch):
        def boom(role_arn=None):
            raise RuntimeError("AccessDenied: not authorized to perform sts:AssumeRole")

        monkeypatch.setattr(ir_rollback, "_get_dredge", boom)
        mock_table.get_item.return_value = {"Item": make_item()}
        logger = MagicMock()
        record = make_record({"detection_id": "d-1"})
        ir_rollback._process_record(record, "req-1", "rh-1", logger)
        assert logger.error.call_args.kwargs["event_name"] == "IR_ROLLBACK_ASSUME_ROLE_FAILED"
        call_kwargs = mock_table.update_item.call_args.kwargs
        assert call_kwargs["ExpressionAttributeValues"][":status"] == "failed"
        # The underlying reason (e.g. AccessDenied vs. a trust-policy gap)
        # must actually reach the stored error, not just a generic
        # "failed to assume <arn>" -- that's the whole point of surfacing
        # this in the UI instead of requiring a CloudWatch log dig.
        assert "AccessDenied: not authorized to perform sts:AssumeRole" in call_kwargs["ExpressionAttributeValues"][":err"]

    def test_handler_exception_logged_and_skipped(self, mock_table, mock_dredge):
        mock_dredge.aws_ir.response.enable_access_key.side_effect = RuntimeError("boom")
        mock_table.get_item.return_value = {"Item": make_item()}
        logger = MagicMock()
        record = make_record({"detection_id": "d-1"})
        ir_rollback._process_record(record, "req-1", "rh-1", logger)
        assert logger.error.call_args.kwargs["event_name"] == "IR_ROLLBACK_EXCEPTION"
        call_kwargs = mock_table.update_item.call_args.kwargs
        assert call_kwargs["ExpressionAttributeValues"][":status"] == "failed"
        assert call_kwargs["ExpressionAttributeValues"][":err"] == "boom"

    def test_successful_rollback_logs_success_and_marks_rolled_back(self, mock_table, mock_dredge):
        mock_dredge.aws_ir.response.enable_access_key.return_value = ok_result(
            "enable_access_key", "user=alice,access_key_id=AKIA1"
        )
        mock_table.get_item.return_value = {"Item": make_item()}
        logger = MagicMock()
        record = make_record({"detection_id": "d-1"})
        ir_rollback._process_record(record, "req-1", "rh-1", logger)

        mock_dredge.aws_ir.response.enable_access_key.assert_called_once_with(
            user_name="alice", access_key_id="AKIA1"
        )
        assert logger.info.call_args.kwargs["event_name"] == "IR_ROLLBACK_SUCCESS"

        mock_table.update_item.assert_called_once()
        call_kwargs = mock_table.update_item.call_args.kwargs
        assert call_kwargs["Key"] == {"detection_id": "d-1"}
        assert call_kwargs["ExpressionAttributeValues"][":true"] is True
        assert call_kwargs["ExpressionAttributeValues"][":status"] == "succeeded"

    def test_failed_rollback_logs_error_and_marks_rollback_status_failed(self, mock_table, mock_dredge):
        # The undo call reached AWS and was rejected (permissions, the
        # resource no longer existing, etc.) -- rolled_back correctly
        # stays False, but this must still be visible in the UI as
        # "failed", not silently indistinguishable from "never attempted".
        mock_dredge.aws_ir.response.enable_access_key.return_value = OperationResult(
            operation="enable_access_key", target="t", success=False, errors=["boom"]
        )
        mock_table.get_item.return_value = {"Item": make_item()}
        logger = MagicMock()
        record = make_record({"detection_id": "d-1"})
        ir_rollback._process_record(record, "req-1", "rh-1", logger)
        assert logger.error.call_args.kwargs["event_name"] == "IR_ROLLBACK_FAILED"
        mock_table.update_item.assert_called_once()
        call_kwargs = mock_table.update_item.call_args.kwargs
        assert call_kwargs["Key"] == {"detection_id": "d-1"}
        assert call_kwargs["ExpressionAttributeValues"][":status"] == "failed"
        assert call_kwargs["ExpressionAttributeValues"][":err"] == "boom"
        assert "rolled_back" not in call_kwargs["UpdateExpression"]

    def test_update_item_failure_after_success_is_logged_not_raised(self, mock_table, mock_dredge):
        mock_dredge.aws_ir.response.enable_access_key.return_value = ok_result()
        mock_table.get_item.return_value = {"Item": make_item()}
        mock_table.update_item.side_effect = RuntimeError("dynamo down")
        logger = MagicMock()
        record = make_record({"detection_id": "d-1"})
        ir_rollback._process_record(record, "req-1", "rh-1", logger)
        event_names = [c.kwargs.get("event_name") for c in logger.error.call_args_list]
        assert "IR_ROLLBACK_STATE_UPDATE_FAILED" in event_names

    def test_successful_rollback_writes_purple_notification(self, mock_table, mock_dredge, mock_outbox):
        mock_dredge.aws_ir.response.enable_access_key.return_value = ok_result(
            "enable_access_key", "user=alice,access_key_id=AKIA1"
        )
        mock_table.get_item.return_value = {"Item": make_item()}
        record = make_record({"detection_id": "d-1"})
        ir_rollback._process_record(record, "req-1", "rh-1", MagicMock())

        mock_outbox.put_item.assert_called_once()
        item = mock_outbox.put_item.call_args.kwargs["Item"]
        assert item["status"] == "PENDING"
        assert item["destinations"] == json.dumps(["notifications"])
        payload = json.loads(item["payload"])
        assert payload["type"] == "rollback_success"
        assert payload["notify"] is True
        assert payload["detection_id"] == "d-1"
        assert payload["response_module"] == "disable_access_key"
        assert payload["undo_module"] == "enable_access_key"
        assert payload["operation"] == "enable_access_key"

    def test_failed_rollback_does_not_write_notification(self, mock_table, mock_dredge, mock_outbox):
        mock_dredge.aws_ir.response.enable_access_key.return_value = OperationResult(
            operation="enable_access_key", target="t", success=False, errors=["boom"]
        )
        mock_table.get_item.return_value = {"Item": make_item()}
        record = make_record({"detection_id": "d-1"})
        ir_rollback._process_record(record, "req-1", "rh-1", MagicMock())
        mock_outbox.put_item.assert_not_called()

    def test_no_outbox_table_configured_is_a_noop(self, mock_table, mock_dredge, monkeypatch):
        monkeypatch.setattr(ir_rollback, "_outbox_table", None)
        mock_dredge.aws_ir.response.enable_access_key.return_value = ok_result()
        mock_table.get_item.return_value = {"Item": make_item()}
        logger = MagicMock()
        record = make_record({"detection_id": "d-1"})
        # Must not raise even though there's nowhere to write the notification.
        ir_rollback._process_record(record, "req-1", "rh-1", logger)
        assert logger.error.call_args is None or "IR_ROLLBACK_NOTIFY_FAILED" not in [
            c.kwargs.get("event_name") for c in logger.error.call_args_list
        ]

    def test_notify_failure_is_logged_not_raised(self, mock_table, mock_dredge, mock_outbox):
        mock_outbox.put_item.side_effect = RuntimeError("dynamo down")
        mock_dredge.aws_ir.response.enable_access_key.return_value = ok_result()
        mock_table.get_item.return_value = {"Item": make_item()}
        logger = MagicMock()
        record = make_record({"detection_id": "d-1"})
        ir_rollback._process_record(record, "req-1", "rh-1", logger)
        event_names = [c.kwargs.get("event_name") for c in logger.error.call_args_list]
        assert "IR_ROLLBACK_NOTIFY_FAILED" in event_names
        # Rollback itself still succeeded and was still marked as such.
        mock_table.update_item.assert_called_once()


class TestLambdaHandler:
    def test_returns_200_with_no_records(self):
        ctx = MagicMock()
        ctx.aws_request_id = "req-1"
        result = ir_rollback.lambda_handler({"Records": []}, ctx)
        assert result["statusCode"] == 200

    def test_processes_each_record(self, mock_table, mock_dredge):
        mock_dredge.aws_ir.response.enable_access_key.return_value = ok_result()
        mock_table.get_item.return_value = {"Item": make_item()}
        ctx = MagicMock()
        ctx.aws_request_id = "req-1"
        event = {"Records": [make_record({"detection_id": "d-1"}), make_record({"detection_id": "d-1"})]}
        result = ir_rollback.lambda_handler(event, ctx)
        assert result["statusCode"] == 200
        assert mock_dredge.aws_ir.response.enable_access_key.call_count == 2

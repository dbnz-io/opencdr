"""Tests for the remediation-success outbox notification added to responder.

Covers `_notify_remediation_success` directly and its wiring into
`_process_record`: fires only on a successful action, is a no-op when no
outbox table is configured, and never lets a notify failure look like the
IR action itself failed.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock

import os

os.environ.setdefault("LOGS_TABLE_NAME", "test-logs-table")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

import pytest

from dredge.aws_ir.models import OperationResult
from src.handlers import responder


def make_context():
    ctx = MagicMock()
    ctx.aws_request_id = "test-req-id"
    return ctx


def make_record(body_obj) -> dict:
    return {"body": json.dumps(body_obj), "receiptHandle": "rh-1"}


def ok_result(operation="disable_user", target="user=bob") -> OperationResult:
    return OperationResult(operation=operation, target=target, success=True, details={"ok": True})


@pytest.fixture()
def mock_dredge(monkeypatch):
    dredge = MagicMock()
    monkeypatch.setattr(responder, "_get_dredge", lambda role_arn=None: dredge)
    return dredge


@pytest.fixture()
def mock_outbox_table(monkeypatch):
    table = MagicMock()
    monkeypatch.setattr(responder, "_outbox_table", table)
    return table


class TestNotifyRemediationSuccessDirect:
    def test_writes_expected_outbox_item_shape(self, mock_outbox_table):
        logger = MagicMock()
        responder._notify_remediation_success(
            detection_event={"severity": "MEDIUM"},
            detection_id="d-1",
            rule_id="006_access_key_created",
            response_module="disable_access_key",
            account_id="123456789012",
            result=ok_result("disable_access_key", "user=alice,access_key_id=AKIA123"),
            logger=logger,
        )
        mock_outbox_table.put_item.assert_called_once()
        item = mock_outbox_table.put_item.call_args.kwargs["Item"]
        assert item["status"] == "PENDING"
        assert json.loads(item["destinations"]) == ["notifications"]
        payload = json.loads(item["payload"])
        assert payload["type"] == "remediation_success"
        assert payload["notify"] is True
        assert payload["rule_id"] == "006_access_key_created"
        assert payload["response_module"] == "disable_access_key"
        assert payload["severity"] == "MEDIUM"
        assert payload["target"] == "user=alice,access_key_id=AKIA123"
        logger.error.assert_not_called()

    def test_missing_severity_defaults_to_unknown(self, mock_outbox_table):
        responder._notify_remediation_success(
            detection_event={},
            detection_id="d-1",
            rule_id="r-1",
            response_module="disable_user",
            account_id=None,
            result=ok_result(),
            logger=MagicMock(),
        )
        payload = json.loads(mock_outbox_table.put_item.call_args.kwargs["Item"]["payload"])
        assert payload["severity"] == "UNKNOWN"

    def test_outbox_write_failure_is_logged_not_raised(self, mock_outbox_table):
        mock_outbox_table.put_item.side_effect = RuntimeError("throttled")
        logger = MagicMock()
        responder._notify_remediation_success(
            detection_event={},
            detection_id="d-1",
            rule_id="r-1",
            response_module="disable_user",
            account_id=None,
            result=ok_result(),
            logger=logger,
        )
        logger.error.assert_called_once()
        assert logger.error.call_args.kwargs["event_name"] == "IR_REMEDIATION_NOTIFY_FAILED"


class TestProcessRecordWiresNotification:
    def test_success_triggers_outbox_write(self, mock_dredge, mock_outbox_table):
        mock_dredge.aws_ir.response.disable_user.return_value = ok_result("disable_user", "user=bob")
        record = make_record({"response_module": "disable_user", "user_name": "bob", "detection_id": "d-1"})
        responder._process_record(record, "req-1", "rh-1", MagicMock())
        mock_outbox_table.put_item.assert_called_once()

    def test_failure_does_not_trigger_outbox_write(self, mock_dredge, mock_outbox_table):
        mock_dredge.aws_ir.response.disable_user.return_value = OperationResult(
            operation="disable_user", target="user=bob", success=False, errors=["boom"]
        )
        record = make_record({"response_module": "disable_user", "user_name": "bob", "detection_id": "d-1"})
        responder._process_record(record, "req-1", "rh-1", MagicMock())
        mock_outbox_table.put_item.assert_not_called()

    def test_no_outbox_table_configured_is_a_silent_noop(self, mock_dredge, monkeypatch):
        monkeypatch.setattr(responder, "_outbox_table", None)
        mock_dredge.aws_ir.response.disable_user.return_value = ok_result("disable_user", "user=bob")
        logger = MagicMock()
        record = make_record({"response_module": "disable_user", "user_name": "bob", "detection_id": "d-1"})
        responder._process_record(record, "req-1", "rh-1", logger)
        # Only the one IR_ACTION_SUCCESS log -- no notify attempt, no error either.
        logger.info.assert_called_once()
        logger.error.assert_not_called()

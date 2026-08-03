"""Tests for the responder's rate limit / circuit breaker
(src.handlers.responder._recent_action_count and its use in
_process_record). Phase 0 safety net: cap real (non-dry-run) destructive
actions per rolling window, independent of the per-alert approval workflow
planned for Phase 4.
"""
from __future__ import annotations

import json
import os
from unittest.mock import MagicMock

import pytest

os.environ.setdefault("LOGS_TABLE_NAME", "test-logs-table")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

from dredge.aws_ir.models import OperationResult
from src.handlers import responder


def make_record(body_obj) -> dict:
    return {"body": json.dumps(body_obj), "receiptHandle": "rh-1"}


def ok_result(operation="op", target="t", dry_run=False) -> OperationResult:
    details = {"ok": True}
    if dry_run:
        details["dry_run"] = True
    return OperationResult(operation=operation, target=target, success=True, details=details)


@pytest.fixture()
def mock_dredge(monkeypatch):
    dredge = MagicMock()
    monkeypatch.setattr(responder, "_get_dredge", lambda role_arn=None: dredge)
    return dredge


@pytest.fixture()
def mock_logs_table(monkeypatch):
    table = MagicMock()
    table.query.return_value = {"Items": []}
    monkeypatch.setattr(responder, "_logs_table", table)
    return table


def action_log_item(event_name: str, *, dry_run: bool = False) -> dict:
    return {
        "service": responder._SERVICE,
        "timestamp": "2026-07-27T00:00:00+00:00",
        "event_name": event_name,
        "details": {
            "operation_result": {
                "operation": "disable_user",
                "details": {"dry_run": True} if dry_run else {},
            }
        },
    }


class TestRecentActionCount:
    def test_no_items_returns_zero(self, mock_logs_table):
        mock_logs_table.query.return_value = {"Items": []}
        assert responder._recent_action_count() == 0

    def test_counts_success_and_failed_action_events(self, mock_logs_table):
        mock_logs_table.query.return_value = {
            "Items": [
                action_log_item("IR_ACTION_SUCCESS"),
                action_log_item("IR_ACTION_FAILED"),
            ]
        }
        assert responder._recent_action_count() == 2

    def test_ignores_unrelated_event_names(self, mock_logs_table):
        mock_logs_table.query.return_value = {
            "Items": [
                action_log_item("IR_ACTION_SUCCESS"),
                {"service": responder._SERVICE, "timestamp": "t", "event_name": "IR_NO_RESPONSE_MODULE", "details": {}},
            ]
        }
        assert responder._recent_action_count() == 1

    def test_excludes_dry_run_actions(self, mock_logs_table):
        mock_logs_table.query.return_value = {
            "Items": [
                action_log_item("IR_ACTION_SUCCESS", dry_run=True),
                action_log_item("IR_ACTION_SUCCESS", dry_run=False),
            ]
        }
        assert responder._recent_action_count() == 1

    def test_paginates_through_all_pages(self, mock_logs_table):
        page_1 = {"Items": [action_log_item("IR_ACTION_SUCCESS")], "LastEvaluatedKey": {"k": "v"}}
        page_2 = {"Items": [action_log_item("IR_ACTION_SUCCESS")]}
        mock_logs_table.query.side_effect = [page_1, page_2]
        assert responder._recent_action_count() == 2
        assert mock_logs_table.query.call_count == 2
        assert "ExclusiveStartKey" in mock_logs_table.query.call_args_list[1].kwargs


class TestProcessRecordCircuitBreaker:
    def test_under_limit_executes_normally(self, mock_dredge, mock_logs_table, monkeypatch):
        monkeypatch.setattr(responder, "RATE_LIMIT_MAX_ACTIONS", 5)
        mock_logs_table.query.return_value = {"Items": []}
        mock_dredge.aws_ir.response.disable_user.return_value = ok_result("disable_user", "user=bob")
        logger = MagicMock()
        record = make_record({"response_module": "disable_user", "user_name": "bob", "detection_id": "d-1"})

        responder._process_record(record, "req-1", "rh-1", logger)

        mock_dredge.aws_ir.response.disable_user.assert_called_once_with(user_name="bob")
        assert logger.info.call_args.kwargs["event_name"] == "IR_ACTION_SUCCESS"

    def test_at_limit_skips_action_and_logs_tripped(self, mock_dredge, mock_logs_table, monkeypatch):
        monkeypatch.setattr(responder, "RATE_LIMIT_MAX_ACTIONS", 2)
        mock_logs_table.query.return_value = {
            "Items": [action_log_item("IR_ACTION_SUCCESS"), action_log_item("IR_ACTION_FAILED")]
        }
        logger = MagicMock()
        record = make_record({"response_module": "disable_user", "user_name": "bob", "detection_id": "d-1"})

        responder._process_record(record, "req-1", "rh-1", logger)

        mock_dredge.aws_ir.response.disable_user.assert_not_called()
        logger.error.assert_called_once()
        assert logger.error.call_args.kwargs["event_name"] == "IR_CIRCUIT_BREAKER_TRIPPED"

    def test_over_limit_skips_action(self, mock_dredge, mock_logs_table, monkeypatch):
        monkeypatch.setattr(responder, "RATE_LIMIT_MAX_ACTIONS", 1)
        mock_logs_table.query.return_value = {
            "Items": [action_log_item("IR_ACTION_SUCCESS"), action_log_item("IR_ACTION_FAILED")]
        }
        logger = MagicMock()
        record = make_record({"response_module": "disable_user", "user_name": "bob", "detection_id": "d-1"})

        responder._process_record(record, "req-1", "rh-1", logger)

        mock_dredge.aws_ir.response.disable_user.assert_not_called()
        assert logger.error.call_args.kwargs["event_name"] == "IR_CIRCUIT_BREAKER_TRIPPED"

    def test_dry_run_actions_dont_count_toward_limit(self, mock_dredge, mock_logs_table, monkeypatch):
        monkeypatch.setattr(responder, "RATE_LIMIT_MAX_ACTIONS", 1)
        mock_logs_table.query.return_value = {
            "Items": [action_log_item("IR_ACTION_SUCCESS", dry_run=True)] * 5
        }
        mock_dredge.aws_ir.response.disable_user.return_value = ok_result("disable_user", "user=bob")
        logger = MagicMock()
        record = make_record({"response_module": "disable_user", "user_name": "bob", "detection_id": "d-1"})

        responder._process_record(record, "req-1", "rh-1", logger)

        mock_dredge.aws_ir.response.disable_user.assert_called_once_with(user_name="bob")

    def test_rate_limit_check_error_fails_closed(self, mock_dredge, mock_logs_table):
        mock_logs_table.query.side_effect = RuntimeError("dynamodb unavailable")
        logger = MagicMock()
        record = make_record({"response_module": "disable_user", "user_name": "bob", "detection_id": "d-1"})

        responder._process_record(record, "req-1", "rh-1", logger)

        mock_dredge.aws_ir.response.disable_user.assert_not_called()
        logger.error.assert_called_once()
        assert logger.error.call_args.kwargs["event_name"] == "IR_RATE_LIMIT_CHECK_FAILED"

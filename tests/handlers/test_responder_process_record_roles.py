"""Integration tests for how _process_record uses per-account IR role
resolution (src/handlers/responder.py): the three new skip/error branches
between "handler resolved" and "action executed" -- role-resolution
failure, an explicitly disabled account, and an assume-role failure. Unit
tests for the resolution/caching logic itself live in
tests/handlers/test_responder_init.py.
"""
from __future__ import annotations

import json
import os
from unittest.mock import MagicMock

import pytest

os.environ.setdefault("LOGS_TABLE_NAME", "test-logs-table")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

from src.handlers import responder


def make_record(body_obj) -> dict:
    return {"body": json.dumps(body_obj), "receiptHandle": "rh-1"}


@pytest.fixture()
def mock_logs_table(monkeypatch):
    table = MagicMock()
    table.query.return_value = {"Items": []}
    monkeypatch.setattr(responder, "_logs_table", table)
    return table


class TestRoleResolutionFailed:
    def test_resolution_exception_skips_and_logs(self, monkeypatch, mock_logs_table):
        monkeypatch.setattr(
            responder,
            "_resolve_role_arn",
            lambda account_id: (_ for _ in ()).throw(RuntimeError("dynamodb unavailable")),
        )
        get_dredge = MagicMock()
        monkeypatch.setattr(responder, "_get_dredge", get_dredge)
        logger = MagicMock()

        record = make_record({"response_module": "disable_user", "user_name": "bob"})
        responder._process_record(record, "req-1", "rh-1", logger)

        get_dredge.assert_not_called()
        logger.error.assert_called_once()
        assert logger.error.call_args.kwargs["event_name"] == "IR_ROLE_RESOLUTION_FAILED"


class TestAccountDisabled:
    def test_no_role_arn_skips_and_logs(self, monkeypatch, mock_logs_table):
        monkeypatch.setattr(responder, "_resolve_role_arn", lambda account_id: None)
        get_dredge = MagicMock()
        monkeypatch.setattr(responder, "_get_dredge", get_dredge)
        logger = MagicMock()

        record = make_record({"response_module": "disable_user", "user_name": "bob"})
        responder._process_record(record, "req-1", "rh-1", logger)

        get_dredge.assert_not_called()
        logger.info.assert_called_once()
        assert logger.info.call_args.kwargs["event_name"] == "IR_ACCOUNT_DISABLED"


class TestAssumeRoleFailed:
    def test_get_dredge_exception_skips_and_logs(self, monkeypatch, mock_logs_table):
        monkeypatch.setattr(
            responder, "_resolve_role_arn", lambda account_id: "arn:aws:iam::222222222222:role/opencdr-ir-role"
        )

        def _raise(role_arn):
            raise RuntimeError("AccessDenied assuming role")

        monkeypatch.setattr(responder, "_get_dredge", _raise)
        logger = MagicMock()

        record = make_record({"response_module": "disable_user", "user_name": "bob"})
        responder._process_record(record, "req-1", "rh-1", logger)

        logger.error.assert_called_once()
        assert logger.error.call_args.kwargs["event_name"] == "IR_ASSUME_ROLE_FAILED"
        assert (
            logger.error.call_args.kwargs["details"]["role_arn"]
            == "arn:aws:iam::222222222222:role/opencdr-ir-role"
        )

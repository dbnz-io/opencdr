"""Tests for two additions to src/infra/logger.py:

1. Every log_item now carries an expires_at attribute (DynamoDB TTL,
   default 90 days) -- logs are archived to S3 first (see
   src/handlers/archiver.py) before they'd ever actually expire.
2. LOGS_MIN_LEVEL_TO_STORE (optional, unset by default) can narrow which
   levels actually get persisted to DynamoDB, independent of the always-
   happens print() to stdout/CloudWatch.
"""
from __future__ import annotations

import json
import os
import time
from unittest.mock import MagicMock

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

import src.infra.logger as logger_module
from src.infra.logger import Logger, _should_store_in_dynamodb, _ttl_expires_at


def make_logger() -> Logger:
    return Logger(service="TEST", source="test.source", request_id="req-1")


class TestTtlExpiresAt:
    def test_returns_epoch_seconds_about_90_days_out_by_default(self, monkeypatch):
        monkeypatch.delenv("DYNAMODB_TTL_DAYS", raising=False)
        now = int(time.time())
        expires = _ttl_expires_at()
        assert (89 * 86400) < (expires - now) < (91 * 86400)

    def test_respects_dynamodb_ttl_days_env_var(self, monkeypatch):
        monkeypatch.setenv("DYNAMODB_TTL_DAYS", "7")
        now = int(time.time())
        expires = _ttl_expires_at()
        assert (6 * 86400) < (expires - now) < (8 * 86400)


class TestLogItemCarriesExpiresAt:
    def test_expires_at_present_in_dynamodb_write(self, monkeypatch, capsys):
        mock_table = MagicMock()
        monkeypatch.setattr(logger_module, "_logs_table", mock_table)

        make_logger().info(event_name="TEST_EVENT", message="hello")

        written_item = mock_table.put_item.call_args.kwargs["Item"]
        assert "expires_at" in written_item
        assert isinstance(written_item["expires_at"], int)

    def test_expires_at_present_in_stdout_line_too(self, monkeypatch, capsys):
        monkeypatch.setattr(logger_module, "_logs_table", MagicMock())
        make_logger().info(event_name="TEST_EVENT", message="hello")
        printed = json.loads(capsys.readouterr().out.strip())
        assert "expires_at" in printed


class TestLogItemCarriesServiceBucket:
    """service_bucket is logs-table-v2's actual HASH key (see
    src/infra/partition_keys.py) -- a separate attribute, never a rename
    of `service` (which stays clean for archiver.py's flatten_log and
    responder.py's own _recent_action_count rate-limit query)."""

    def test_service_bucket_derived_from_service_and_today(self, monkeypatch, capsys):
        monkeypatch.setattr(logger_module, "_logs_table", MagicMock())
        make_logger().info(event_name="TEST_EVENT", message="hello")
        printed = json.loads(capsys.readouterr().out.strip())

        today = time.strftime("%Y-%m-%d", time.gmtime())
        assert printed["service_bucket"] == f"TEST#{today}"
        assert printed["service"] == "TEST"  # untouched, still clean

    def test_service_bucket_present_in_dynamodb_write_too(self, monkeypatch):
        mock_table = MagicMock()
        monkeypatch.setattr(logger_module, "_logs_table", mock_table)

        make_logger().info(event_name="TEST_EVENT", message="hello")

        written_item = mock_table.put_item.call_args.kwargs["Item"]
        assert written_item["service_bucket"].startswith("TEST#")


class TestShouldStoreInDynamoDb:
    def test_unset_env_var_stores_everything(self, monkeypatch):
        monkeypatch.delenv("LOGS_MIN_LEVEL_TO_STORE", raising=False)
        assert _should_store_in_dynamodb("INFO") is True
        assert _should_store_in_dynamodb("WARNING") is True
        assert _should_store_in_dynamodb("ERROR") is True

    def test_min_level_warning_excludes_info(self, monkeypatch):
        monkeypatch.setenv("LOGS_MIN_LEVEL_TO_STORE", "WARNING")
        assert _should_store_in_dynamodb("INFO") is False
        assert _should_store_in_dynamodb("WARNING") is True
        assert _should_store_in_dynamodb("ERROR") is True

    def test_min_level_error_excludes_info_and_warning(self, monkeypatch):
        monkeypatch.setenv("LOGS_MIN_LEVEL_TO_STORE", "ERROR")
        assert _should_store_in_dynamodb("INFO") is False
        assert _should_store_in_dynamodb("WARNING") is False
        assert _should_store_in_dynamodb("ERROR") is True

    def test_garbage_value_falls_back_to_store_everything(self, monkeypatch):
        # Fails safe: a typo'd env var value shouldn't silently start
        # dropping logs -- it should behave as if unset.
        monkeypatch.setenv("LOGS_MIN_LEVEL_TO_STORE", "not-a-real-level")
        assert _should_store_in_dynamodb("INFO") is True

    def test_lowercase_value_still_works(self, monkeypatch):
        monkeypatch.setenv("LOGS_MIN_LEVEL_TO_STORE", "warning")
        assert _should_store_in_dynamodb("INFO") is False
        assert _should_store_in_dynamodb("WARNING") is True


class TestLevelGateAppliedInPractice:
    def test_info_log_skipped_from_dynamodb_when_min_level_is_warning(self, monkeypatch):
        monkeypatch.setenv("LOGS_MIN_LEVEL_TO_STORE", "WARNING")
        mock_table = MagicMock()
        monkeypatch.setattr(logger_module, "_logs_table", mock_table)

        make_logger().info(event_name="ROUTINE_EVENT", message="just flow, not audit-worthy")

        mock_table.put_item.assert_not_called()

    def test_warning_log_still_stored_when_min_level_is_warning(self, monkeypatch):
        monkeypatch.setenv("LOGS_MIN_LEVEL_TO_STORE", "WARNING")
        mock_table = MagicMock()
        monkeypatch.setattr(logger_module, "_logs_table", mock_table)

        make_logger().warning(event_name="SOMETHING_OFF", message="worth keeping")

        mock_table.put_item.assert_called_once()

    def test_info_log_still_printed_to_stdout_even_when_dynamodb_skipped(self, monkeypatch, capsys):
        monkeypatch.setenv("LOGS_MIN_LEVEL_TO_STORE", "ERROR")
        monkeypatch.setattr(logger_module, "_logs_table", MagicMock())

        make_logger().info(event_name="ROUTINE_EVENT", message="still visible in CloudWatch")

        printed = json.loads(capsys.readouterr().out.strip())
        assert printed["event_name"] == "ROUTINE_EVENT"

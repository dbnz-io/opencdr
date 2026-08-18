"""Tests for the TTL wiring added to aws_handler.py's domain write methods
(put_signal_if_not_exists, put_alert_if_not_exists, put_outbox_record) --
every signal/alert/outbox item now gets an expires_at attribute so
DynamoDB's native TTL can expire it (default 90 days, DYNAMODB_TTL_DAYS).
Signals/alerts are archived to S3 first (src/handlers/archiver.py) before
they'd ever actually expire -- see docs/data-archival.md.
"""
from __future__ import annotations

import os
import time
from unittest.mock import MagicMock

os.environ.setdefault("LOGS_TABLE_NAME", "test-logs-table")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

from src.infra.aws_handler import AwsHandler, ttl_expires_at


def make_handler() -> AwsHandler:
    logger = MagicMock()
    logger.request_id = "req-test"
    logger.source = "test"
    aws = AwsHandler(logger=logger)
    aws._ddb = MagicMock()
    aws._ddb_resource = MagicMock()
    return aws


class TestTtlExpiresAt:
    def test_returns_epoch_seconds_in_the_future(self):
        now = int(time.time())
        expires = ttl_expires_at()
        assert expires > now
        # Default 90 days -- roughly 89-91 days out, generous bound to
        # avoid flaking on slow CI.
        assert (89 * 86400) < (expires - now) < (91 * 86400)

    def test_custom_days_respected(self):
        now = int(time.time())
        expires = ttl_expires_at(days=7)
        assert (6 * 86400) < (expires - now) < (8 * 86400)


class TestPutSignalIfNotExistsSetsExpiresAt:
    def test_expires_at_present_on_written_item(self):
        aws = make_handler()
        table = MagicMock()
        aws._ddb_resource.Table.return_value = table

        aws.put_signal_if_not_exists(
            table_name="signals-table",
            signal_item={"detection_id": "d-1", "severity": "HIGH"},
        )

        written_item = table.put_item.call_args.kwargs["Item"]
        assert "expires_at" in written_item
        assert isinstance(written_item["expires_at"], int)
        assert written_item["expires_at"] > int(time.time())

    def test_does_not_mutate_caller_dict(self):
        aws = make_handler()
        aws._ddb_resource.Table.return_value = MagicMock()
        original = {"detection_id": "d-1"}
        aws.put_signal_if_not_exists(table_name="t", signal_item=original)
        assert "expires_at" not in original


class TestPutSignalIfNotExistsSetsSeverityBucket:
    """severity_bucket is signals-table-v2's actual HASH key (see
    src/infra/partition_keys.py) -- a separate attribute injected here,
    never a rename of `severity` (which stays clean for archiver.py's
    flatten_signal and the S3/Athena archive)."""

    def test_severity_bucket_derived_from_severity_and_timestamp(self):
        aws = make_handler()
        table = MagicMock()
        aws._ddb_resource.Table.return_value = table

        aws.put_signal_if_not_exists(
            table_name="signals-table-v2",
            signal_item={"detection_id": "d-1", "severity": "HIGH", "timestamp": "2026-08-12T14:00:00Z"},
        )

        written_item = table.put_item.call_args.kwargs["Item"]
        assert written_item["severity_bucket"] == "HIGH#2026-08-12"
        assert written_item["severity"] == "HIGH"  # untouched, still clean

    def test_missing_severity_falls_back_to_unknown_bucket(self):
        aws = make_handler()
        table = MagicMock()
        aws._ddb_resource.Table.return_value = table

        aws.put_signal_if_not_exists(
            table_name="signals-table-v2",
            signal_item={"detection_id": "d-1", "timestamp": "2026-08-12T14:00:00Z"},
        )

        written_item = table.put_item.call_args.kwargs["Item"]
        assert written_item["severity_bucket"] == "UNKNOWN#2026-08-12"


class TestPutAlertIfNotExistsSetsExpiresAt:
    def test_expires_at_present_on_written_item(self):
        aws = make_handler()
        table = MagicMock()
        aws._ddb_resource.Table.return_value = table

        aws.put_alert_if_not_exists(
            table_name="alerts-table",
            alert_item={"alert_key": "k-1", "severity": "CRITICAL"},
        )

        written_item = table.put_item.call_args.kwargs["Item"]
        assert "expires_at" in written_item
        assert isinstance(written_item["expires_at"], int)


class TestPutOutboxRecordSetsExpiresAt:
    def test_expires_at_present_in_raw_attribute_value_format(self):
        aws = make_handler()
        aws.put_outbox_record(table_name="t", payload={}, destinations=["notifications"])

        written_item = aws._ddb.put_item.call_args.kwargs["Item"]
        assert "expires_at" in written_item
        # put_outbox_record uses the raw client (attribute-value) format,
        # not the resource format signals/alerts use.
        assert written_item["expires_at"]["N"].isdigit()

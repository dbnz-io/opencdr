"""Tests for src/handlers/archiver.py -- the DynamoDB-stream-triggered
Lambda that flattens new signals/alerts/logs and forwards them to
Kinesis Data Firehose for S3/Parquet archival (see
docs/data-archival.md). Covers the pure flatten/partition/routing
functions directly, plus lambda_handler's INSERT-only filtering,
per-record flatten isolation, and delivery-failure-raises-for-retry
behavior.
"""
from __future__ import annotations

import json
import os
from unittest.mock import MagicMock

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("LAMBDA_NAME", "test-archiver")

import pytest

from src.handlers import archiver

# ---------------------------------------------------------------------------
# partition_fields
# ---------------------------------------------------------------------------


class TestPartitionFields:
    def test_derives_from_iso_timestamp_and_account(self):
        pf = archiver.partition_fields("2026-03-15T14:30:00Z", "123456789012")
        assert pf == {"account": "123456789012", "year": "2026", "month": "03", "day": "15", "hour": "14"}

    def test_missing_account_falls_back_to_none(self):
        pf = archiver.partition_fields("2026-03-15T14:30:00Z", None)
        assert pf["account"] == "none"

    def test_missing_timestamp_falls_back_to_now_not_raise(self):
        pf = archiver.partition_fields(None, "123456789012")
        assert len(pf["year"]) == 4
        assert pf["account"] == "123456789012"

    def test_garbage_timestamp_falls_back_to_now_not_raise(self):
        pf = archiver.partition_fields("not-a-timestamp", "123456789012")
        assert len(pf["year"]) == 4

    def test_padding_is_zero_filled(self):
        pf = archiver.partition_fields("2026-01-05T03:00:00Z", "123")
        assert pf["month"] == "01"
        assert pf["day"] == "05"
        assert pf["hour"] == "03"


# ---------------------------------------------------------------------------
# Flatteners
# ---------------------------------------------------------------------------


class TestFlattenSignal:
    def test_flattens_expected_fields(self):
        item = {
            "detection_id": "d-1",
            "event_id": "e-1",
            "rule_id": "009_admin_policy_attached",
            "severity": "CRITICAL",
            "timestamp": "2026-03-15T14:30:00Z",
            "category": "iam",
            "activity_name": "AttachUserPolicy",
            "cloud_account_id": "123456789012",
            "cloud_region": "us-east-1",
            "source": "cloudtrail",
            "actor": {"user_name": "attacker", "type": "IAMUser"},
        }
        flat = archiver.flatten_signal(item)
        assert flat["detection_id"] == "d-1"
        assert flat["actor_user_name"] == "attacker"
        assert flat["account"] == "123456789012"
        assert json.loads(flat["raw_item"])["detection_id"] == "d-1"

    def test_missing_actor_does_not_raise(self):
        flat = archiver.flatten_signal({"detection_id": "d-1"})
        assert flat["actor_user_name"] == ""


class TestFlattenAlert:
    def test_account_comes_from_primary_signal(self):
        item = {
            "alert_id": "a-1",
            "alert_key": "k-1",
            "rule_id": "021_correlation_iam_activity_burst",
            "severity": "CRITICAL",
            "timestamp": "2026-03-15T14:35:00Z",
            "type": "correlation",
            "group_value": "attacker",
            "match_count": 5,
            "primary_signal": {"cloud_account_id": "123456789012"},
        }
        flat = archiver.flatten_alert(item)
        assert flat["cloud_account_id"] == "123456789012"
        assert flat["account"] == "123456789012"
        assert flat["match_count"] == 5

    def test_missing_primary_signal_does_not_raise(self):
        flat = archiver.flatten_alert({"alert_id": "a-1"})
        assert flat["account"] == "none"
        assert flat["match_count"] == 0


class TestFlattenLog:
    def test_account_from_details_when_present(self):
        item = {
            "log_id": "l-1",
            "event_name": "IR_ACTION_SUCCESS",
            "service": "OPENCDR-RESPONDER",
            "timestamp": "2026-03-15T14:36:00Z",
            "details": {"level": "INFO", "account_id": "123456789012"},
        }
        flat = archiver.flatten_log(item)
        assert flat["account"] == "123456789012"
        assert flat["level"] == "INFO"

    def test_no_account_in_details_uses_none_not_error(self):
        item = {"log_id": "l-1", "details": {"level": "INFO"}}
        flat = archiver.flatten_log(item)
        assert flat["account"] == "none"


# ---------------------------------------------------------------------------
# _record_id
# ---------------------------------------------------------------------------


class TestRecordId:
    def test_picks_detection_id_for_signals(self):
        assert archiver._record_id({"detection_id": "d-1", "alert_id": "", "log_id": ""}) == "d-1"

    def test_picks_alert_id_for_alerts(self):
        assert archiver._record_id({"detection_id": "", "alert_id": "a-1", "log_id": ""}) == "a-1"

    def test_picks_log_id_for_logs(self):
        assert archiver._record_id({"detection_id": "", "alert_id": "", "log_id": "l-1"}) == "l-1"

    def test_no_id_present_returns_empty_string(self):
        assert archiver._record_id({}) == ""


# ---------------------------------------------------------------------------
# _route_for
# ---------------------------------------------------------------------------


class TestRouteFor:
    def test_signals_table_routes_correctly(self):
        arn = "arn:aws:dynamodb:us-east-1:123:table/opencdr-dev-signals-table/stream/2026"
        assert archiver._route_for(arn) == ("SIGNALS_FIREHOSE_STREAM_NAME", "signal")

    def test_alerts_table_routes_correctly(self):
        arn = "arn:aws:dynamodb:us-east-1:123:table/opencdr-dev-alerts-table/stream/2026"
        assert archiver._route_for(arn) == ("ALERTS_FIREHOSE_STREAM_NAME", "alert")

    def test_logs_table_routes_correctly(self):
        arn = "arn:aws:dynamodb:us-east-1:123:table/opencdr-dev-logs-table/stream/2026"
        assert archiver._route_for(arn) == ("LOGS_FIREHOSE_STREAM_NAME", "log")

    def test_unrelated_table_returns_none(self):
        arn = "arn:aws:dynamodb:us-east-1:123:table/opencdr-dev-outbox-table/stream/2026"
        assert archiver._route_for(arn) is None


# ---------------------------------------------------------------------------
# lambda_handler
# ---------------------------------------------------------------------------


def _raise(message: str):
    def _fn(_item: dict):
        raise ValueError(message)

    return _fn


def _stream_record(event_name: str, table: str, item: dict) -> dict:
    from boto3.dynamodb.types import TypeSerializer

    serializer = TypeSerializer()
    return {
        "eventName": event_name,
        "eventSourceARN": f"arn:aws:dynamodb:us-east-1:123:table/opencdr-dev-{table}-table/stream/2026",
        "dynamodb": {"NewImage": {k: serializer.serialize(v) for k, v in item.items()}},
    }


class TestLambdaHandler:
    def test_insert_forwarded_to_firehose(self, monkeypatch):
        mock_firehose = MagicMock()
        mock_firehose.put_record_batch.return_value = {"FailedPutCount": 0}
        monkeypatch.setattr(archiver, "_firehose", mock_firehose)
        monkeypatch.setenv("SIGNALS_FIREHOSE_STREAM_NAME", "opencdr-dev-archive-signals")

        event = {
            "Records": [
                _stream_record("INSERT", "signals", {"detection_id": "d-1", "severity": "HIGH"})
            ]
        }
        result = archiver.lambda_handler(event, context=None)

        mock_firehose.put_record_batch.assert_called_once()
        call = mock_firehose.put_record_batch.call_args
        assert call.kwargs["DeliveryStreamName"] == "opencdr-dev-archive-signals"
        assert len(call.kwargs["Records"]) == 1
        assert result["sent"] == 1

    def test_archived_ids_traceable_in_summary_log(self, monkeypatch, capsys):
        """A post-deploy check (or a real operator) needs to confirm a
        specific detection_id actually made it through archival -- this
        is what makes that possible without waiting on the slower,
        eventually-consistent S3/Parquet write itself. Asserts against
        real stdout (the Logger's own print()), not a mock seam --
        lambda_handler builds its own Logger internally, so this is
        exactly what a CloudWatch Logs search would actually see."""
        import src.infra.logger as logger_module

        mock_firehose = MagicMock()
        mock_firehose.put_record_batch.return_value = {"FailedPutCount": 0}
        monkeypatch.setattr(archiver, "_firehose", mock_firehose)
        monkeypatch.setenv("SIGNALS_FIREHOSE_STREAM_NAME", "opencdr-dev-archive-signals")
        # Avoid the logger's own DynamoDB-write fallback (a second,
        # pretty-printed "Failed to write log entry" dump to stdout when
        # the logs table isn't reachable) muddying the single-line JSON
        # this test actually wants to parse.
        monkeypatch.setattr(logger_module, "_logs_table", MagicMock())

        event = {
            "Records": [_stream_record("INSERT", "signals", {"detection_id": "ci-canary-123"})]
        }
        archiver.lambda_handler(event, context=None)

        lines = [line for line in capsys.readouterr().out.splitlines() if line.strip()]
        summary_lines = []
        for line in lines:
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                continue
            if parsed.get("event_name") == "ARCHIVE_BATCH_COMPLETE":
                summary_lines.append(parsed)

        assert len(summary_lines) == 1
        assert "ci-canary-123" in summary_lines[0]["details"]["archived_ids"]

    def test_remove_event_ignored_not_archived(self, monkeypatch):
        mock_firehose = MagicMock()
        monkeypatch.setattr(archiver, "_firehose", mock_firehose)
        monkeypatch.setenv("SIGNALS_FIREHOSE_STREAM_NAME", "opencdr-dev-archive-signals")

        event = {"Records": [_stream_record("REMOVE", "signals", {"detection_id": "d-1"})]}
        result = archiver.lambda_handler(event, context=None)

        mock_firehose.put_record_batch.assert_not_called()
        assert result["skipped"] == 1

    def test_modify_event_ignored_not_archived(self, monkeypatch):
        mock_firehose = MagicMock()
        monkeypatch.setattr(archiver, "_firehose", mock_firehose)
        monkeypatch.setenv("SIGNALS_FIREHOSE_STREAM_NAME", "opencdr-dev-archive-signals")

        event = {"Records": [_stream_record("MODIFY", "signals", {"detection_id": "d-1"})]}
        result = archiver.lambda_handler(event, context=None)

        mock_firehose.put_record_batch.assert_not_called()
        assert result["skipped"] == 1

    def test_missing_stream_name_env_var_skips_gracefully(self, monkeypatch):
        mock_firehose = MagicMock()
        monkeypatch.setattr(archiver, "_firehose", mock_firehose)
        monkeypatch.delenv("SIGNALS_FIREHOSE_STREAM_NAME", raising=False)

        event = {"Records": [_stream_record("INSERT", "signals", {"detection_id": "d-1"})]}
        result = archiver.lambda_handler(event, context=None)

        mock_firehose.put_record_batch.assert_not_called()
        assert result["skipped"] == 1

    def test_delivery_failure_raises_for_stream_retry(self, monkeypatch):
        mock_firehose = MagicMock()
        mock_firehose.put_record_batch.return_value = {"FailedPutCount": 1}
        monkeypatch.setattr(archiver, "_firehose", mock_firehose)
        monkeypatch.setenv("SIGNALS_FIREHOSE_STREAM_NAME", "opencdr-dev-archive-signals")

        event = {"Records": [_stream_record("INSERT", "signals", {"detection_id": "d-1"})]}
        with pytest.raises(RuntimeError, match="rejected by Firehose"):
            archiver.lambda_handler(event, context=None)

    def test_multiple_records_batched_into_one_put_record_batch_call(self, monkeypatch):
        mock_firehose = MagicMock()
        mock_firehose.put_record_batch.return_value = {"FailedPutCount": 0}
        monkeypatch.setattr(archiver, "_firehose", mock_firehose)
        monkeypatch.setenv("SIGNALS_FIREHOSE_STREAM_NAME", "opencdr-dev-archive-signals")

        event = {
            "Records": [
                _stream_record("INSERT", "signals", {"detection_id": "d-1"}),
                _stream_record("INSERT", "signals", {"detection_id": "d-2"}),
                _stream_record("INSERT", "signals", {"detection_id": "d-3"}),
            ]
        }
        result = archiver.lambda_handler(event, context=None)

        mock_firehose.put_record_batch.assert_called_once()
        assert len(mock_firehose.put_record_batch.call_args.kwargs["Records"]) == 3
        assert result["sent"] == 3

    def test_unrelated_table_stream_skipped(self, monkeypatch):
        mock_firehose = MagicMock()
        monkeypatch.setattr(archiver, "_firehose", mock_firehose)

        event = {"Records": [_stream_record("INSERT", "outbox", {"outbox_id": "o-1"})]}
        result = archiver.lambda_handler(event, context=None)

        mock_firehose.put_record_batch.assert_not_called()
        assert result["skipped"] == 1

    def test_missing_new_image_skipped_gracefully(self, monkeypatch):
        mock_firehose = MagicMock()
        monkeypatch.setattr(archiver, "_firehose", mock_firehose)
        monkeypatch.setenv("SIGNALS_FIREHOSE_STREAM_NAME", "opencdr-dev-archive-signals")

        record = _stream_record("INSERT", "signals", {"detection_id": "d-1"})
        record["dynamodb"] = {}  # no NewImage at all
        result = archiver.lambda_handler({"Records": [record]}, context=None)

        mock_firehose.put_record_batch.assert_not_called()
        assert result["skipped"] == 1

    def test_one_bad_record_does_not_take_down_the_rest_of_the_batch(self, monkeypatch):
        mock_firehose = MagicMock()
        mock_firehose.put_record_batch.return_value = {"FailedPutCount": 0}
        monkeypatch.setattr(archiver, "_firehose", mock_firehose)
        monkeypatch.setattr(
            archiver, "_FLATTENERS", {**archiver._FLATTENERS, "signal": _raise("boom")}
        )
        monkeypatch.setenv("SIGNALS_FIREHOSE_STREAM_NAME", "opencdr-dev-archive-signals")

        event = {"Records": [_stream_record("INSERT", "signals", {"detection_id": "d-1"})]}
        result = archiver.lambda_handler(event, context=None)

        mock_firehose.put_record_batch.assert_not_called()
        assert result["flatten_failed"] == 1

"""Tests for the signalWriter Lambda (src/handlers/signal_writer.py) --
the SQS-buffered consumer that performs the actual signals-table-v2
write processor.py/alerter.py now enqueue to instead of writing
directly. Deliberately does NOT swallow every failure like
responder.py/notifier.py -- uses ReportBatchItemFailures so a genuinely
failed write is retried by SQS rather than silently dropped, which is
the whole point of the buffer.
"""
from __future__ import annotations

import json
import os
from decimal import Decimal
from unittest.mock import MagicMock, patch

os.environ.setdefault("SIGNALS_TABLE_NAME", "test-signals-table-v2")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

from src.handlers import signal_writer


def make_record(body: dict | str, message_id: str = "msg-1") -> dict:
    return {
        "messageId": message_id,
        "body": body if isinstance(body, str) else json.dumps(body),
    }


def make_event(records: list[dict]) -> dict:
    return {"Records": records}


def make_context():
    ctx = MagicMock()
    ctx.aws_request_id = "test-req-id"
    return ctx


def patched_aws_handler(*, inserted=True, raises=None):
    instance = MagicMock()
    if raises is not None:
        instance.put_signal_if_not_exists.side_effect = raises
    else:
        instance.put_signal_if_not_exists.return_value = inserted
    return patch("src.handlers.signal_writer.AwsHandler", return_value=instance), instance


class TestHappyPath:
    def test_inserted_signal_writes_and_emits_metric(self):
        patcher, instance = patched_aws_handler(inserted=True)
        with patcher, patch("src.handlers.signal_writer.emit_metric") as mock_metric:
            record = make_record({"detection_id": "d-1", "rule_id": "rule-001", "severity": "HIGH"})
            result = signal_writer.lambda_handler(make_event([record]), make_context())

        assert result == {"batchItemFailures": []}
        instance.put_signal_if_not_exists.assert_called_once()
        kwargs = instance.put_signal_if_not_exists.call_args.kwargs
        assert kwargs["table_name"] == "test-signals-table-v2"
        assert kwargs["signal_item"]["detection_id"] == "d-1"
        mock_metric.assert_called_once()
        assert mock_metric.call_args.args[0] == "SignalsCreated"
        assert mock_metric.call_args.kwargs["dimensions"]["severity"] == "HIGH"


class TestDuplicate:
    def test_duplicate_is_not_a_batch_failure_and_no_metric(self):
        patcher, instance = patched_aws_handler(inserted=False)
        with patcher, patch("src.handlers.signal_writer.emit_metric") as mock_metric:
            record = make_record({"detection_id": "d-1"})
            result = signal_writer.lambda_handler(make_event([record]), make_context())

        assert result == {"batchItemFailures": []}
        mock_metric.assert_not_called()


class TestRetryableFailure:
    def test_write_exception_is_reported_as_batch_item_failure(self):
        patcher, instance = patched_aws_handler(raises=RuntimeError("throttled"))
        with patcher, patch("src.handlers.signal_writer.emit_metric") as mock_metric:
            record = make_record({"detection_id": "d-1"}, message_id="msg-fail")
            result = signal_writer.lambda_handler(make_event([record]), make_context())

        assert result == {"batchItemFailures": [{"itemIdentifier": "msg-fail"}]}
        mock_metric.assert_not_called()


class TestMalformedMessage:
    def test_unparseable_body_is_dropped_not_retried(self):
        patcher, instance = patched_aws_handler(inserted=True)
        with patcher:
            record = make_record("not valid json{{{", message_id="msg-poison")
            result = signal_writer.lambda_handler(make_event([record]), make_context())

        # Dropped (acked), not added to batchItemFailures -- it would
        # never parse on retry either.
        assert result == {"batchItemFailures": []}
        instance.put_signal_if_not_exists.assert_not_called()


class TestFloatToDecimalConversion:
    """
    A GuardDuty-sourced detection's raw_event carries AWS's own float
    severity (e.g. 8.0) nested inside raw_event.detail.severity. Written
    natively via DynamoDB's high-level Table.put_item resource API (as
    put_signal_if_not_exists does), a Python float raises
    "Float types are not supported. Use Decimal types instead." --
    confirmed against the exact message body pulled from the real DLQ
    after this failed in live CI (see CHANGELOG/roadmap). CloudTrail
    items have no floats anywhere in their raw_event, which is why this
    was invisible until a real GuardDuty finding went through this path.
    """

    def test_nested_float_in_raw_event_becomes_decimal(self):
        patcher, instance = patched_aws_handler(inserted=True)
        with patcher, patch("src.handlers.signal_writer.emit_metric"):
            record = make_record(
                {
                    "detection_id": "d-gd-1",
                    "rule_id": "024_guardduty_iam_credential_compromise",
                    "severity": "HIGH",
                    "source": "guardduty",
                    "raw_event": {
                        "source": "aws.guardduty",
                        "detail-type": "GuardDuty Finding",
                        "detail": {"type": "UnauthorizedAccess:IAMUser/TorIPCaller", "severity": 8.0},
                    },
                },
                message_id="msg-gd",
            )
            result = signal_writer.lambda_handler(make_event([record]), make_context())

        assert result == {"batchItemFailures": []}
        signal_item = instance.put_signal_if_not_exists.call_args.kwargs["signal_item"]
        observed_severity = signal_item["raw_event"]["detail"]["severity"]
        assert isinstance(observed_severity, Decimal)
        assert observed_severity == Decimal("8.0")

    def test_top_level_string_fields_unaffected(self):
        # The fix must not touch non-numeric-looking fields -- rule_id/
        # severity/source stay plain strings, same as every other test
        # in this file already asserts elsewhere.
        patcher, instance = patched_aws_handler(inserted=True)
        with patcher, patch("src.handlers.signal_writer.emit_metric"):
            record = make_record(
                {"detection_id": "d-gd-2", "rule_id": "rule-x", "severity": "HIGH"},
                message_id="msg-gd-2",
            )
            signal_writer.lambda_handler(make_event([record]), make_context())

        signal_item = instance.put_signal_if_not_exists.call_args.kwargs["signal_item"]
        assert signal_item["rule_id"] == "rule-x"
        assert signal_item["severity"] == "HIGH"


class TestMixedBatch:
    def test_one_bad_record_does_not_affect_the_rest_of_the_batch(self):
        instance = MagicMock()

        def fake_put(*, table_name, signal_item):
            if signal_item["detection_id"] == "d-bad":
                raise RuntimeError("throttled")
            return True

        instance.put_signal_if_not_exists.side_effect = fake_put
        with (
            patch("src.handlers.signal_writer.AwsHandler", return_value=instance),
            patch("src.handlers.signal_writer.emit_metric"),
        ):
            records = [
                make_record({"detection_id": "d-good-1"}, message_id="msg-1"),
                make_record({"detection_id": "d-bad"}, message_id="msg-2"),
                make_record({"detection_id": "d-good-2"}, message_id="msg-3"),
            ]
            result = signal_writer.lambda_handler(make_event(records), make_context())

        assert result == {"batchItemFailures": [{"itemIdentifier": "msg-2"}]}
        assert instance.put_signal_if_not_exists.call_count == 3

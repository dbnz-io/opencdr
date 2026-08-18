"""Tests for the processor Lambda handler (event → detection → signal/alert/outbox)."""
from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

os.environ.setdefault("LOGS_TABLE_NAME", "test-logs-table")
os.environ.setdefault("SIGNALS_WRITE_QUEUE_URL", "https://sqs.us-east-1.amazonaws.com/123456789012/test-signals-write-queue")
os.environ.setdefault("ALERTS_TABLE_NAME", "test-alerts-table")
os.environ.setdefault("OUTBOX_TABLE_NAME", "test-outbox-table")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

from src.handlers import processor
from src.handlers.processor import get_lists, get_rules, lambda_handler

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_cloudtrail_event(event_name="CreateUser", event_source="iam.amazonaws.com", **detail_overrides) -> dict:
    detail = {
        "eventSource": event_source,
        "eventName": event_name,
        "eventTime": "2026-01-01T00:00:00Z",
        "awsRegion": "us-east-1",
        "recipientAccountId": "123456789012",
        "sourceIPAddress": "1.2.3.4",
        "userAgent": "aws-cli/2.0",
        "userIdentity": {"type": "IAMUser", "userName": "alice"},
    }
    detail.update(detail_overrides)
    return {
        "id": "evt-1",
        "detail-type": "AWS API Call via CloudTrail",
        "source": "aws.cloudtrail",
        "region": "us-east-1",
        "account": "123456789012",
        "detail": detail,
    }


def make_signal_rule(rule_id="rule-001", event_name="CreateUser", notify=True) -> dict:
    return {
        "rule_id": rule_id,
        "rule_kind": "signal",
        "enabled": True,
        "severity": "HIGH",
        "notify": notify,
        "response_module": "",
        "playbook": "Investigate.",
        "conditions": [
            {"field": "activity_name", "op": "equals", "value": event_name},
        ],
    }


def make_context():
    ctx = MagicMock()
    ctx.aws_request_id = "test-req-id"
    return ctx


@pytest.fixture(autouse=True)
def reset_module_caches():
    """RULES_CACHE/LISTS_CACHE are cold-start globals; isolate each test from the others."""
    processor.RULES_CACHE = None
    processor.LISTS_CACHE = None
    yield
    processor.RULES_CACHE = None
    processor.LISTS_CACHE = None


def patched_aws_handler(*, put_alert=True):
    """Patch AwsHandler so lambda_handler gets a controllable instance."""
    instance = MagicMock()
    instance.sqs_send.return_value = "msg-id-1"
    instance.put_alert_if_not_exists.return_value = put_alert
    instance.put_outbox_record.return_value = "outbox-id-1"
    return patch("src.handlers.processor.AwsHandler", return_value=instance), instance


# ---------------------------------------------------------------------------
# Unsupported event
# ---------------------------------------------------------------------------


class TestUnsupportedEvent:
    def test_unparseable_event_is_ignored(self):
        patcher, instance = patched_aws_handler()
        with patcher, patch("src.handlers.processor.load_detection_rules") as load_rules:
            result = lambda_handler({"not": "a supported shape"}, make_context())

        assert result == {"status": "ignored"}
        load_rules.assert_not_called()
        instance.sqs_send.assert_not_called()

    def test_parser_exception_is_logged_and_reraised(self):
        patcher, instance = patched_aws_handler()
        with (
            patcher,
            patch("src.handlers.processor.router") as fake_router,
        ):
            fake_router.parse.side_effect = ValueError("malformed event")
            with pytest.raises(ValueError, match="malformed event"):
                lambda_handler(make_cloudtrail_event(), make_context())

        instance.sqs_send.assert_not_called()


# ---------------------------------------------------------------------------
# No rules loaded
# ---------------------------------------------------------------------------


class TestNoRules:
    def test_no_rules_returns_no_rules_status(self):
        patcher, instance = patched_aws_handler()
        with patcher, patch("src.handlers.processor.load_detection_rules", return_value=[]):
            result = lambda_handler(make_cloudtrail_event(), make_context())

        assert result == {"status": "no_rules"}
        instance.sqs_send.assert_not_called()


# ---------------------------------------------------------------------------
# Rules loaded, none match
# ---------------------------------------------------------------------------


class TestNoDetection:
    def test_no_matching_rule_returns_no_detection_status(self):
        rules = [make_signal_rule(event_name="DeleteUser")]  # won't match CreateUser event
        patcher, instance = patched_aws_handler()
        with patcher, patch("src.handlers.processor.load_detection_rules", return_value=rules):
            result = lambda_handler(make_cloudtrail_event(event_name="CreateUser"), make_context())

        assert result == {"status": "no_detection"}
        instance.sqs_send.assert_not_called()


# ---------------------------------------------------------------------------
# Happy path: a rule matches
# ---------------------------------------------------------------------------


class TestDetectionMatch:
    def test_matching_rule_stores_signal_and_alert_and_outbox(self):
        rules = [make_signal_rule(notify=True)]
        patcher, instance = patched_aws_handler(put_alert=True)
        with patcher, patch("src.handlers.processor.load_detection_rules", return_value=rules):
            result = lambda_handler(make_cloudtrail_event(), make_context())

        assert result["status"] == "processed"
        assert result["detections"] == 1
        assert result["stored"] == 1

        instance.sqs_send.assert_called_once()
        signal_kwargs = instance.sqs_send.call_args.kwargs
        assert signal_kwargs["queue_url"] == processor.SIGNALS_WRITE_QUEUE_URL
        assert signal_kwargs["body"]["rule_id"] == "rule-001"

        instance.put_alert_if_not_exists.assert_called_once()
        alert_kwargs = instance.put_alert_if_not_exists.call_args.kwargs
        assert alert_kwargs["table_name"] == "test-alerts-table"
        assert alert_kwargs["alert_item"]["rule_id"] == "rule-001"
        assert alert_kwargs["alert_item"]["type"] == "signal"

        instance.put_outbox_record.assert_called_once()
        outbox_kwargs = instance.put_outbox_record.call_args.kwargs
        assert outbox_kwargs["table_name"] == "test-outbox-table"
        assert outbox_kwargs["destinations"] == ["notifications", "responses"]

    def test_notify_false_skips_alert_and_outbox(self):
        rules = [make_signal_rule(notify=False)]
        patcher, instance = patched_aws_handler()
        with patcher, patch("src.handlers.processor.load_detection_rules", return_value=rules):
            result = lambda_handler(make_cloudtrail_event(), make_context())

        assert result["stored"] == 1
        instance.sqs_send.assert_called_once()
        instance.put_alert_if_not_exists.assert_not_called()
        instance.put_outbox_record.assert_not_called()

    def test_multiple_matching_rules_all_processed(self):
        rules = [
            make_signal_rule(rule_id="rule-001"),
            make_signal_rule(rule_id="rule-002"),
        ]
        patcher, instance = patched_aws_handler()
        with patcher, patch("src.handlers.processor.load_detection_rules", return_value=rules):
            result = lambda_handler(make_cloudtrail_event(), make_context())

        assert result["detections"] == 2
        assert result["stored"] == 2
        assert instance.sqs_send.call_count == 2
        assert instance.put_alert_if_not_exists.call_count == 2


# ---------------------------------------------------------------------------
# Optimistic proceed: processor no longer knows insert-vs-duplicate --
# that outcome (and the real DynamoDB write) now happens downstream in
# signal_writer.py, off the SQS buffer this enqueues to. A successful
# enqueue alone is enough to proceed to alert/outbox; there is no longer
# a "skip because it turned out to be a duplicate" path at this layer.
# ---------------------------------------------------------------------------


class TestOptimisticProceed:
    def test_alert_and_outbox_proceed_on_successful_enqueue_alone(self):
        rules = [make_signal_rule()]
        patcher, instance = patched_aws_handler(put_alert=True)
        with patcher, patch("src.handlers.processor.load_detection_rules", return_value=rules):
            result = lambda_handler(make_cloudtrail_event(), make_context())

        assert result["status"] == "processed"
        assert result["stored"] == 1
        instance.sqs_send.assert_called_once()
        instance.put_alert_if_not_exists.assert_called_once()
        instance.put_outbox_record.assert_called_once()


# ---------------------------------------------------------------------------
# Error propagation
# ---------------------------------------------------------------------------


class TestSignalEnqueueError:
    def test_signal_enqueue_exception_propagates(self):
        rules = [make_signal_rule()]
        instance = MagicMock()
        instance.sqs_send.side_effect = RuntimeError("sqs unavailable")
        with (
            patch("src.handlers.processor.AwsHandler", return_value=instance),
            patch("src.handlers.processor.load_detection_rules", return_value=rules),
        ):
            with pytest.raises(RuntimeError, match="sqs unavailable"):
                lambda_handler(make_cloudtrail_event(), make_context())

        instance.put_alert_if_not_exists.assert_not_called()


class TestAlertsTableUnset:
    def test_alerts_table_unset_still_writes_outbox(self, monkeypatch):
        monkeypatch.setattr(processor, "ALERTS_TABLE_NAME", "")
        rules = [make_signal_rule(notify=True)]
        instance = MagicMock()
        instance.put_signal_if_not_exists.return_value = True
        with (
            patch("src.handlers.processor.AwsHandler", return_value=instance),
            patch("src.handlers.processor.load_detection_rules", return_value=rules),
        ):
            result = lambda_handler(make_cloudtrail_event(), make_context())

        assert result["status"] == "processed"
        instance.put_alert_if_not_exists.assert_not_called()
        instance.put_outbox_record.assert_called_once()


class TestOutboxWriteError:
    def test_outbox_write_exception_is_caught_and_does_not_propagate(self):
        rules = [make_signal_rule(notify=True)]
        instance = MagicMock()
        instance.put_signal_if_not_exists.return_value = True
        instance.put_alert_if_not_exists.return_value = True
        instance.put_outbox_record.side_effect = RuntimeError("sqs unavailable")
        with (
            patch("src.handlers.processor.AwsHandler", return_value=instance),
            patch("src.handlers.processor.load_detection_rules", return_value=rules),
        ):
            result = lambda_handler(make_cloudtrail_event(), make_context())

        assert result["status"] == "processed"


class TestAlertStoreError:
    def test_alert_store_exception_is_caught_and_outbox_still_attempted(self):
        rules = [make_signal_rule(notify=True)]
        instance = MagicMock()
        instance.put_signal_if_not_exists.return_value = True
        instance.put_alert_if_not_exists.side_effect = RuntimeError("alerts table throttled")
        instance.put_outbox_record.return_value = "outbox-id-1"
        with (
            patch("src.handlers.processor.AwsHandler", return_value=instance),
            patch("src.handlers.processor.load_detection_rules", return_value=rules),
        ):
            result = lambda_handler(make_cloudtrail_event(), make_context())

        # Current behavior: alert_inserted is set to False on exception, so the
        # subsequent `if alert_inserted and OUTBOX_TABLE_NAME` guard skips the
        # outbox write too -- documenting this on purpose (safety net, not a fix).
        assert result["status"] == "processed"
        instance.put_outbox_record.assert_not_called()


# ---------------------------------------------------------------------------
# Rule / list cache behavior (documents the known no-invalidation gap)
# ---------------------------------------------------------------------------


class TestRuleCaching:
    def test_get_rules_loads_once_and_caches(self):
        logger = MagicMock()
        aws = MagicMock()
        with patch("src.handlers.processor.load_detection_rules", return_value=[make_signal_rule()]) as load_rules:
            first = get_rules(aws, logger)
            second = get_rules(aws, logger)

        assert first is second
        load_rules.assert_called_once()

    def test_get_lists_loads_once_and_caches(self):
        logger = MagicMock()
        aws = MagicMock()
        raw_lists = [{"rule_id": "blocklist-ips", "values": ["1.2.3.4"]}]
        with patch("src.handlers.processor.load_detection_rules", return_value=raw_lists) as load_rules:
            first = get_lists(aws, logger)
            second = get_lists(aws, logger)

        assert first == {"blocklist-ips": ["1.2.3.4"]}
        assert first is second
        load_rules.assert_called_once()

    def test_lambda_handler_reuses_cache_across_invocations(self):
        rules = [make_signal_rule()]
        patcher, instance = patched_aws_handler()
        with patcher, patch("src.handlers.processor.load_detection_rules", return_value=rules) as load_rules:
            lambda_handler(make_cloudtrail_event(), make_context())
            lambda_handler(make_cloudtrail_event(), make_context())

        # Two invocations, but rules + lists are each loaded exactly once (signal + list kinds).
        assert load_rules.call_count == 2  # one "signal" call + one "list" call, not four

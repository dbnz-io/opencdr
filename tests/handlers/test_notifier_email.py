"""Tests for email (SNS) notification channel in notifier handler."""
from __future__ import annotations

import json
import os
from unittest.mock import MagicMock, patch

import pytest

# Must be set before src.infra.logger is imported (it raises at module level if missing,
# and boto3 requires a region even for client construction at import time)
os.environ.setdefault("LOGS_TABLE_NAME", "test-logs-table")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

from src.handlers.notifier import (
    _route_channels,
    build_email_message,
    lambda_handler,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_alert(**overrides) -> dict:
    base = {
        "alert_id": "alert-001",
        "alert_key": "rule-001#alice",
        "severity": "HIGH",
        "rule_id": "rule-001",
        "playbook": "Revoke credentials immediately.",
        "match_count": 3,
        "primary_signal": {
            "actor": {"user_name": "alice"},
            "network": {"source_ip": "1.2.3.4"},
            "api": {"operation": "AssumeRole"},
        },
        "signal_refs": [
            {"timestamp": "2026-01-01T00:00:00Z", "rule_id": "rule-001", "detection_id": "det-aabbcc"},
            {"timestamp": "2026-01-01T00:01:00Z", "rule_id": "rule-001", "detection_id": "det-ddeeff"},
        ],
    }
    base.update(overrides)
    return base


def make_settings(*, email_enabled=True, topic_arn="arn:aws:sns:us-east-1:123:alerts", routing=None) -> dict:
    return {
        "notifications_enabled": True,
        "channels": {
            "slack": {"enabled": False, "webhook_url": ""},
            "discord": {"enabled": False, "webhook_url": ""},
            "email": {"enabled": email_enabled, "topic_arn": topic_arn},
        },
        "routing": routing or {},
    }


def make_sqs_event(item: dict) -> dict:
    return {"Records": [{"body": json.dumps(item)}]}


def make_context():
    ctx = MagicMock()
    ctx.aws_request_id = "test-req-id"
    return ctx


# ---------------------------------------------------------------------------
# build_email_message
# ---------------------------------------------------------------------------


class TestBuildEmailMessage:
    def test_subject_contains_severity_and_rule(self):
        subject, _ = build_email_message(make_alert())
        assert "HIGH" in subject
        assert "rule-001" in subject

    def test_subject_prefix(self):
        subject, _ = build_email_message(make_alert())
        assert subject.startswith("[OpenCDR]")

    def test_body_contains_key_fields(self):
        _, body = build_email_message(make_alert())
        assert "alice" in body
        assert "1.2.3.4" in body
        assert "AssumeRole" in body
        assert "Revoke credentials immediately." in body

    def test_body_contains_signal_refs(self):
        _, body = build_email_message(make_alert())
        assert "det-aabb" in body  # truncated to 8 chars

    def test_body_contains_alert_id_and_key(self):
        _, body = build_email_message(make_alert())
        assert "alert-001" in body
        assert "rule-001#alice" in body

    def test_missing_primary_signal_falls_back_to_item(self):
        alert = make_alert()
        del alert["primary_signal"]
        subject, body = build_email_message(alert)
        assert "HIGH" in subject

    def test_no_signal_refs_omits_related_signals_section(self):
        _, body = build_email_message(make_alert(signal_refs=[]))
        assert "Related Signals" not in body

    def test_critical_severity_in_subject(self):
        subject, _ = build_email_message(make_alert(severity="CRITICAL"))
        assert "CRITICAL" in subject

    def test_match_count_in_body(self):
        _, body = build_email_message(make_alert(match_count=7))
        assert "7" in body

    def test_returns_strings(self):
        subject, body = build_email_message(make_alert())
        assert isinstance(subject, str)
        assert isinstance(body, str)


# ---------------------------------------------------------------------------
# _route_channels — email routing
# ---------------------------------------------------------------------------


class TestRouteChannelsEmail:
    def test_auto_fanout_includes_email_when_enabled(self):
        settings = make_settings(email_enabled=True, topic_arn="arn:aws:sns:us-east-1:123:alerts")
        channels = _route_channels(make_alert(), settings)
        assert "email" in channels

    def test_auto_fanout_excludes_email_when_disabled(self):
        settings = make_settings(email_enabled=False)
        channels = _route_channels(make_alert(), settings)
        assert "email" not in channels

    def test_auto_fanout_excludes_email_when_no_topic_arn(self):
        settings = make_settings(email_enabled=True, topic_arn="")
        with patch("src.handlers.notifier.ALERTS_SNS_TOPIC_ARN", ""):
            channels = _route_channels(make_alert(), settings)
        assert "email" not in channels

    def test_auto_fanout_includes_email_via_env_topic_arn(self):
        settings = make_settings(email_enabled=True, topic_arn="")
        with patch("src.handlers.notifier.ALERTS_SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:123:alerts"):
            channels = _route_channels(make_alert(), settings)
        assert "email" in channels

    def test_severity_routing_string_email(self):
        settings = make_settings()
        settings["routing"] = {"HIGH": "email"}
        channels = _route_channels(make_alert(severity="HIGH"), settings)
        assert channels == ["email"]

    def test_severity_routing_list_includes_email(self):
        settings = make_settings()
        settings["routing"] = {"HIGH": ["slack", "email"]}
        channels = _route_channels(make_alert(severity="HIGH"), settings)
        assert "email" in channels
        assert "slack" in channels

    def test_severity_routing_deduplicates(self):
        settings = make_settings()
        settings["routing"] = {"HIGH": ["email", "email"]}
        channels = _route_channels(make_alert(severity="HIGH"), settings)
        assert channels.count("email") == 1

    def test_env_override_email(self):
        settings = make_settings(email_enabled=False)
        with patch("src.handlers.notifier.DEFAULT_CHANNEL", "email"):
            channels = _route_channels(make_alert(), settings)
        assert channels == ["email"]

    def test_invalid_channel_in_routing_list_ignored(self):
        settings = make_settings()
        settings["routing"] = {"HIGH": ["email", "carrier_pigeon"]}
        channels = _route_channels(make_alert(severity="HIGH"), settings)
        assert channels == ["email"]
        assert "carrier_pigeon" not in channels


# ---------------------------------------------------------------------------
# lambda_handler — email dispatch
# ---------------------------------------------------------------------------


class TestLambdaHandlerEmail:
    def _make_aws_mock(self, topic_arn="arn:aws:sns:us-east-1:123:alerts"):
        aws = MagicMock()
        aws._sns.publish.return_value = {"MessageId": "msg-001"}
        return aws

    def test_sends_to_sns_when_email_enabled(self):
        alert = make_alert()
        settings = make_settings(topic_arn="arn:aws:sns:us-east-1:123:alerts")

        with (
            patch("src.handlers.notifier.load_global_settings", return_value=settings),
            patch("src.handlers.notifier.AwsHandler") as MockAws,
        ):
            aws_instance = self._make_aws_mock()
            MockAws.return_value = aws_instance

            result = lambda_handler(make_sqs_event(alert), make_context())

        aws_instance._sns.publish.assert_called_once()
        call_kwargs = aws_instance._sns.publish.call_args[1]
        assert call_kwargs["TopicArn"] == "arn:aws:sns:us-east-1:123:alerts"
        assert "HIGH" in call_kwargs["Subject"]
        assert "rule-001" in call_kwargs["Subject"]
        assert result["sent"] == 1

    def test_uses_env_topic_arn_when_settings_topic_arn_empty(self):
        alert = make_alert()
        settings = make_settings(email_enabled=True, topic_arn="")

        with (
            patch("src.handlers.notifier.load_global_settings", return_value=settings),
            patch("src.handlers.notifier.AwsHandler") as MockAws,
            patch("src.handlers.notifier.ALERTS_SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:123:env-alerts"),
        ):
            aws_instance = self._make_aws_mock()
            MockAws.return_value = aws_instance

            result = lambda_handler(make_sqs_event(alert), make_context())

        aws_instance._sns.publish.assert_called_once()
        call_kwargs = aws_instance._sns.publish.call_args[1]
        assert call_kwargs["TopicArn"] == "arn:aws:sns:us-east-1:123:env-alerts"
        assert result["sent"] == 1

    def test_skips_when_email_disabled(self):
        alert = make_alert()
        settings = make_settings(email_enabled=False)
        settings["routing"] = {"HIGH": "email"}

        with (
            patch("src.handlers.notifier.load_global_settings", return_value=settings),
            patch("src.handlers.notifier.AwsHandler") as MockAws,
        ):
            aws_instance = self._make_aws_mock()
            MockAws.return_value = aws_instance

            result = lambda_handler(make_sqs_event(alert), make_context())

        aws_instance._sns.publish.assert_not_called()
        assert result["failed"] == 1  # selected but not enabled => RuntimeError => failed

    def test_failed_sns_publish_counted_as_failed(self):
        alert = make_alert()
        settings = make_settings()

        with (
            patch("src.handlers.notifier.load_global_settings", return_value=settings),
            patch("src.handlers.notifier.AwsHandler") as MockAws,
        ):
            aws_instance = self._make_aws_mock()
            aws_instance._sns.publish.side_effect = Exception("SNS unavailable")
            MockAws.return_value = aws_instance

            result = lambda_handler(make_sqs_event(alert), make_context())

        assert result["failed"] == 1
        assert result["sent"] == 0

    def test_global_disabled_skips_all_channels(self):
        alert = make_alert()
        settings = make_settings()
        settings["notifications_enabled"] = False

        with (
            patch("src.handlers.notifier.load_global_settings", return_value=settings),
            patch("src.handlers.notifier.AwsHandler") as MockAws,
        ):
            aws_instance = self._make_aws_mock()
            MockAws.return_value = aws_instance

            result = lambda_handler(make_sqs_event(alert), make_context())

        aws_instance._sns.publish.assert_not_called()
        assert result["skipped"] == 1

    def test_notify_false_skips_item(self):
        alert = make_alert(notify=False)
        settings = make_settings()

        with (
            patch("src.handlers.notifier.load_global_settings", return_value=settings),
            patch("src.handlers.notifier.AwsHandler") as MockAws,
        ):
            aws_instance = self._make_aws_mock()
            MockAws.return_value = aws_instance

            result = lambda_handler(make_sqs_event(alert), make_context())

        aws_instance._sns.publish.assert_not_called()
        assert result["skipped"] == 1

    def test_multiple_records_all_sent(self):
        settings = make_settings()
        event = {
            "Records": [
                {"body": json.dumps(make_alert(alert_id="a1"))},
                {"body": json.dumps(make_alert(alert_id="a2"))},
                {"body": json.dumps(make_alert(alert_id="a3"))},
            ]
        }

        with (
            patch("src.handlers.notifier.load_global_settings", return_value=settings),
            patch("src.handlers.notifier.AwsHandler") as MockAws,
        ):
            aws_instance = self._make_aws_mock()
            MockAws.return_value = aws_instance

            result = lambda_handler(event, make_context())

        assert aws_instance._sns.publish.call_count == 3
        assert result["sent"] == 3
        assert result["processed"] == 3

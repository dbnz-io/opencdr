"""Tests for the alarm_notifier Lambda handler (AlarmsSnsTopic -> Slack)."""
from __future__ import annotations

import json
import os
from unittest.mock import MagicMock, patch

import pytest

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

from src.handlers import alarm_notifier
from src.handlers.alarm_notifier import (
    _format_alarm_message,
    _get_webhook_url,
    _post_to_slack,
    lambda_handler,
)


@pytest.fixture(autouse=True)
def reset_webhook_cache(monkeypatch):
    monkeypatch.setattr(alarm_notifier, "_webhook_cache", None)
    monkeypatch.setattr(alarm_notifier, "_webhook_cache_loaded_at", 0.0)
    monkeypatch.setenv("STAGE", "dev")


def make_sns_event(alarm: dict) -> dict:
    return {"Records": [{"Sns": {"Message": json.dumps(alarm)}}]}


class TestFormatAlarmMessage:
    def test_alarm_state_gets_red_circle(self):
        text = _format_alarm_message(
            {
                "AlarmName": "opencdr-dev-processor-errors",
                "NewStateValue": "ALARM",
                "AlarmDescription": "processor Lambda error count > 0",
                "NewStateReason": "Threshold crossed",
            }
        )
        assert "\U0001f534" in text
        assert "opencdr-dev-processor-errors" in text
        assert "ALARM" in text

    def test_ok_state_gets_green_check(self):
        text = _format_alarm_message(
            {"AlarmName": "x", "NewStateValue": "OK", "AlarmDescription": "", "NewStateReason": ""}
        )
        assert "✅" in text


class TestGetWebhookUrl:
    def test_reads_from_ssm_at_expected_path(self):
        mock_ssm = MagicMock()
        mock_ssm.get_parameter.return_value = {"Parameter": {"Value": "https://hooks.example/abc"}}
        with patch("boto3.client", return_value=mock_ssm):
            url = _get_webhook_url()

        assert url == "https://hooks.example/abc"
        mock_ssm.get_parameter.assert_called_once_with(
            Name="/opencdr-dev/ops-alerts/slack-webhook", WithDecryption=True
        )

    def test_second_call_within_ttl_uses_cache(self):
        mock_ssm = MagicMock()
        mock_ssm.get_parameter.return_value = {"Parameter": {"Value": "https://hooks.example/abc"}}
        with patch("boto3.client", return_value=mock_ssm):
            _get_webhook_url()
            _get_webhook_url()

        assert mock_ssm.get_parameter.call_count == 1


class TestPostToSlack:
    def test_rejects_non_https_webhook(self):
        with pytest.raises(ValueError, match="HTTPS"):
            _post_to_slack("http://not-secure.example/hook", "hello")

    def test_posts_json_payload_over_https(self):
        mock_resp = MagicMock()
        mock_resp.__enter__.return_value.read.return_value = b"ok"
        with patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen:
            _post_to_slack("https://hooks.example/abc", "hello world")

        request = mock_urlopen.call_args.args[0]
        assert request.full_url == "https://hooks.example/abc"
        assert json.loads(request.data) == {"text": "hello world"}


class TestLambdaHandler:
    def test_forwards_alarm_and_returns_ok(self):
        mock_ssm = MagicMock()
        mock_ssm.get_parameter.return_value = {"Parameter": {"Value": "https://hooks.example/abc"}}
        mock_resp = MagicMock()
        mock_resp.__enter__.return_value.read.return_value = b"ok"

        event = make_sns_event(
            {
                "AlarmName": "opencdr-dev-processor-errors",
                "NewStateValue": "ALARM",
                "AlarmDescription": "processor Lambda error count > 0",
                "NewStateReason": "Threshold crossed",
            }
        )

        with patch("boto3.client", return_value=mock_ssm), \
             patch("urllib.request.urlopen", return_value=mock_resp):
            result = lambda_handler(event, context=MagicMock(aws_request_id="req-1"))

        assert result == {"status": "ok"}

    def test_malformed_sns_message_does_not_crash(self):
        mock_ssm = MagicMock()
        mock_ssm.get_parameter.return_value = {"Parameter": {"Value": "https://hooks.example/abc"}}
        mock_resp = MagicMock()
        mock_resp.__enter__.return_value.read.return_value = b"ok"

        event = {"Records": [{"Sns": {"Message": "not json"}}]}

        with patch("boto3.client", return_value=mock_ssm), \
             patch("urllib.request.urlopen", return_value=mock_resp):
            result = lambda_handler(event, context=MagicMock(aws_request_id="req-1"))

        assert result == {"status": "ok"}

    def test_slack_post_failure_reraises_for_sns_retry(self):
        mock_ssm = MagicMock()
        mock_ssm.get_parameter.return_value = {"Parameter": {"Value": "https://hooks.example/abc"}}

        event = make_sns_event({"AlarmName": "x", "NewStateValue": "ALARM"})

        with patch("boto3.client", return_value=mock_ssm), \
             patch("urllib.request.urlopen", side_effect=RuntimeError("network down")):
            with pytest.raises(RuntimeError, match="network down"):
                lambda_handler(event, context=MagicMock(aws_request_id="req-1"))

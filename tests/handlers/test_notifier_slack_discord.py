"""Tests for Slack and Discord notification channels in notifier handler."""
from __future__ import annotations

import json
import os
import urllib.error
from unittest.mock import MagicMock, patch

import pytest

os.environ.setdefault("LOGS_TABLE_NAME", "test-logs-table")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

from src.handlers.notifier import (
    _post_json,
    _route_channels,
    build_discord_payload,
    build_slack_payload,
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
        ],
    }
    base.update(overrides)
    return base


def make_settings_slack(webhook="https://hooks.slack.com/test", routing=None) -> dict:
    return {
        "notifications_enabled": True,
        "channels": {
            "slack": {"enabled": True, "webhook_url": webhook},
            "discord": {"enabled": False, "webhook_url": ""},
            "email": {"enabled": False, "topic_arn": ""},
        },
        "routing": routing or {},
    }


def make_settings_discord(webhook="https://discord.com/api/webhooks/test", routing=None) -> dict:
    return {
        "notifications_enabled": True,
        "channels": {
            "slack": {"enabled": False, "webhook_url": ""},
            "discord": {"enabled": True, "webhook_url": webhook},
            "email": {"enabled": False, "topic_arn": ""},
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
# build_slack_payload
# ---------------------------------------------------------------------------


class TestBuildSlackPayload:
    def test_returns_attachments_structure(self):
        payload = build_slack_payload(make_alert())
        assert "attachments" in payload
        assert isinstance(payload["attachments"], list)

    def test_blocks_contain_severity_and_rule(self):
        payload = build_slack_payload(make_alert(severity="CRITICAL", rule_id="rule-999"))
        text = json.dumps(payload)
        assert "CRITICAL" in text
        assert "rule-999" in text

    def test_blocks_contain_user_and_ip(self):
        payload = build_slack_payload(make_alert())
        text = json.dumps(payload)
        assert "alice" in text
        assert "1.2.3.4" in text

    def test_blocks_contain_playbook(self):
        payload = build_slack_payload(make_alert())
        assert "Revoke credentials immediately." in json.dumps(payload)

    def test_signal_refs_included_for_correlation_alerts(self):
        payload = build_slack_payload(make_alert())
        text = json.dumps(payload)
        assert "det-aabb" in text

    def test_no_signal_refs_section_when_empty(self):
        payload = build_slack_payload(make_alert(signal_refs=[]))
        text = json.dumps(payload)
        assert "Related Signals" not in text

    def test_alert_id_in_context(self):
        payload = build_slack_payload(make_alert(alert_id="my-alert"))
        assert "my-alert" in json.dumps(payload)

    def test_severity_color_critical(self):
        payload = build_slack_payload(make_alert(severity="CRITICAL"))
        color = payload["attachments"][0]["color"]
        assert color == "#d32f2f"

    def test_severity_color_high(self):
        payload = build_slack_payload(make_alert(severity="HIGH"))
        color = payload["attachments"][0]["color"]
        assert color == "#f57c00"

    def test_severity_color_medium(self):
        payload = build_slack_payload(make_alert(severity="MEDIUM"))
        color = payload["attachments"][0]["color"]
        assert color == "#fbc02d"

    def test_severity_color_low(self):
        payload = build_slack_payload(make_alert(severity="LOW"))
        color = payload["attachments"][0]["color"]
        assert color == "#1976d2"

    def test_unknown_severity_fallback_color(self):
        payload = build_slack_payload(make_alert(severity="UNKNOWN"))
        color = payload["attachments"][0]["color"]
        assert color == "#616161"

    def test_missing_primary_signal_falls_back_to_item(self):
        alert = make_alert()
        del alert["primary_signal"]
        payload = build_slack_payload(alert)
        assert "attachments" in payload

    def test_match_count_in_payload(self):
        payload = build_slack_payload(make_alert(match_count=9))
        assert "9" in json.dumps(payload)


# ---------------------------------------------------------------------------
# build_discord_payload
# ---------------------------------------------------------------------------


class TestBuildDiscordPayload:
    def test_returns_embeds_structure(self):
        payload = build_discord_payload(make_alert())
        assert "embeds" in payload
        assert len(payload["embeds"]) == 1

    def test_embed_title_contains_severity_and_rule(self):
        payload = build_discord_payload(make_alert(severity="HIGH", rule_id="rule-001"))
        title = payload["embeds"][0]["title"]
        assert "HIGH" in title
        assert "rule-001" in title

    def test_embed_contains_user_and_ip(self):
        text = json.dumps(build_discord_payload(make_alert()))
        assert "alice" in text
        assert "1.2.3.4" in text

    def test_embed_contains_playbook(self):
        text = json.dumps(build_discord_payload(make_alert()))
        assert "Revoke credentials immediately." in text

    def test_embed_color_critical(self):
        payload = build_discord_payload(make_alert(severity="CRITICAL"))
        assert payload["embeds"][0]["color"] == 15158332

    def test_embed_color_high(self):
        payload = build_discord_payload(make_alert(severity="HIGH"))
        assert payload["embeds"][0]["color"] == 15105570

    def test_embed_color_medium(self):
        payload = build_discord_payload(make_alert(severity="MEDIUM"))
        assert payload["embeds"][0]["color"] == 15844367

    def test_embed_color_low(self):
        payload = build_discord_payload(make_alert(severity="LOW"))
        assert payload["embeds"][0]["color"] == 3447003

    def test_footer_contains_alert_metadata(self):
        payload = build_discord_payload(make_alert(alert_id="a1", alert_key="k1"))
        footer = payload["embeds"][0]["footer"]["text"]
        assert "a1" in footer
        assert "k1" in footer

    def test_footer_defaults_to_opencdr_when_no_metadata(self):
        alert = make_alert()
        alert.pop("alert_id", None)
        alert.pop("alert_key", None)
        alert["alert_id"] = ""
        alert["alert_key"] = ""
        payload = build_discord_payload(alert)
        assert payload["embeds"][0]["footer"]["text"] == "OpenCDR"

    def test_missing_primary_signal_falls_back(self):
        alert = make_alert()
        del alert["primary_signal"]
        payload = build_discord_payload(alert)
        assert "embeds" in payload


# ---------------------------------------------------------------------------
# _post_json
# ---------------------------------------------------------------------------


class TestPostJson:
    def test_raises_on_non_https_url(self):
        with pytest.raises(ValueError, match="HTTPS"):
            _post_json("http://example.com/hook", {})

    def test_success_returns_status_and_body(self):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b"ok"
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            status, body = _post_json("https://example.com/hook", {"x": 1})

        assert status == 200
        assert body == "ok"

    def test_http_error_returns_status_and_body(self):
        http_err = urllib.error.HTTPError(
            url="https://x.com", code=400, msg="Bad Request", hdrs={}, fp=None
        )
        http_err.read = lambda: b"bad payload"

        with patch("urllib.request.urlopen", side_effect=http_err):
            status, body = _post_json("https://example.com/hook", {})

        assert status == 400
        assert "bad payload" in body


# ---------------------------------------------------------------------------
# lambda_handler — Slack dispatch
# ---------------------------------------------------------------------------


class TestLambdaHandlerSlack:
    def _post_ok(self, url, payload, **kwargs):
        return 200, "ok"

    def _post_fail(self, url, payload, **kwargs):
        return 400, "bad request"

    def test_sends_to_slack_when_enabled(self):
        settings = make_settings_slack()
        with (
            patch("src.handlers.notifier.load_global_settings", return_value=settings),
            patch("src.handlers.notifier.AwsHandler"),
            patch("src.handlers.notifier._post_json", side_effect=self._post_ok),
        ):
            result = lambda_handler(make_sqs_event(make_alert()), make_context())
        assert result["sent"] == 1

    def test_http_error_from_slack_counted_as_failed(self):
        settings = make_settings_slack()
        with (
            patch("src.handlers.notifier.load_global_settings", return_value=settings),
            patch("src.handlers.notifier.AwsHandler"),
            patch("src.handlers.notifier._post_json", side_effect=self._post_fail),
        ):
            result = lambda_handler(make_sqs_event(make_alert()), make_context())
        assert result["failed"] == 1
        assert result["sent"] == 0

    def test_skips_when_slack_not_enabled(self):
        settings = make_settings_slack(webhook="")
        settings["channels"]["slack"]["enabled"] = False
        settings["routing"] = {"HIGH": "slack"}
        with (
            patch("src.handlers.notifier.load_global_settings", return_value=settings),
            patch("src.handlers.notifier.AwsHandler"),
            patch("src.handlers.notifier._post_json", side_effect=self._post_ok) as mock_post,
        ):
            result = lambda_handler(make_sqs_event(make_alert()), make_context())
        mock_post.assert_not_called()
        assert result["failed"] == 1  # selected but not enabled => RuntimeError


# ---------------------------------------------------------------------------
# lambda_handler — Discord dispatch
# ---------------------------------------------------------------------------


class TestLambdaHandlerDiscord:
    def _post_ok(self, url, payload, **kwargs):
        return 200, "ok"

    def test_sends_to_discord_when_enabled(self):
        settings = make_settings_discord()
        with (
            patch("src.handlers.notifier.load_global_settings", return_value=settings),
            patch("src.handlers.notifier.AwsHandler"),
            patch("src.handlers.notifier._post_json", side_effect=self._post_ok),
        ):
            result = lambda_handler(make_sqs_event(make_alert()), make_context())
        assert result["sent"] == 1

    def test_http_error_from_discord_counted_as_failed(self):
        settings = make_settings_discord()
        with (
            patch("src.handlers.notifier.load_global_settings", return_value=settings),
            patch("src.handlers.notifier.AwsHandler"),
            patch("src.handlers.notifier._post_json", return_value=(429, "rate limited")),
        ):
            result = lambda_handler(make_sqs_event(make_alert()), make_context())
        assert result["failed"] == 1


# ---------------------------------------------------------------------------
# lambda_handler — unknown channel skipped
# ---------------------------------------------------------------------------


class TestLambdaHandlerUnknownChannel:
    def test_unknown_channel_in_routing_counted_as_skipped(self):
        settings = {
            "notifications_enabled": True,
            "channels": {
                "slack": {"enabled": False, "webhook_url": ""},
                "discord": {"enabled": False, "webhook_url": ""},
                "email": {"enabled": False, "topic_arn": ""},
            },
            "routing": {"HIGH": "carrier_pigeon"},
        }
        with (
            patch("src.handlers.notifier.load_global_settings", return_value=settings),
            patch("src.handlers.notifier.AwsHandler"),
        ):
            result = lambda_handler(make_sqs_event(make_alert()), make_context())
        assert result["skipped"] == 1
        assert result["sent"] == 0

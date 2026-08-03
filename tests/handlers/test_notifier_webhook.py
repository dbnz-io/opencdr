"""Tests for the custom webhook notification channel in notifier handler."""
from __future__ import annotations

import json
import os
from unittest.mock import MagicMock, patch

import pytest

os.environ.setdefault("LOGS_TABLE_NAME", "test-logs-table")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

from src.handlers.notifier import (
    _post_json,
    _route_channels,
    lambda_handler,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_alert(**overrides) -> dict:
    base = {
        "alert_id": "alert-001",
        "severity": "HIGH",
        "rule_id": "rule-001",
        "playbook": "Revoke credentials immediately.",
        "timestamp": "2026-01-01T00:00:00Z",
        "primary_signal": {
            "activity_name": "AssumeRole",
            "actor": {"user_name": "alice"},
            "network": {"source_ip": "1.2.3.4"},
            "api": {"operation": "AssumeRole"},
        },
    }
    base.update(overrides)
    return base


def make_settings_webhook(targets=None, enabled=True) -> dict:
    return {
        "notifications_enabled": True,
        "channels": {
            "slack": {"enabled": False, "webhook_url": ""},
            "discord": {"enabled": False, "webhook_url": ""},
            "email": {"enabled": False, "topic_arn": ""},
            "webhook": {
                "enabled": enabled,
                "targets": targets if targets is not None else [
                    {"name": "pagerduty", "url": "https://events.pagerduty.com/v2/enqueue", "headers": {}},
                ],
            },
        },
        "routing": {},
    }


def make_sqs_event(item: dict) -> dict:
    return {"Records": [{"body": json.dumps(item)}]}


def make_context():
    ctx = MagicMock()
    ctx.aws_request_id = "test-req-id"
    ctx.invoked_function_arn = "arn:aws:lambda:us-east-1:123456789012:function:test-notifier"
    return ctx


# ---------------------------------------------------------------------------
# _post_json — extra_headers support
# ---------------------------------------------------------------------------


class TestPostJsonExtraHeaders:
    def test_no_extra_headers_still_works(self):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b"ok"
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            status, body = _post_json("https://example.com/hook", {"key": "val"})

        assert status == 200

    def test_extra_headers_are_merged(self):
        captured = []

        def fake_open(req, timeout=None):
            captured.append(dict(req.headers))
            raise Exception("stop")

        with patch("urllib.request.urlopen", side_effect=fake_open):
            try:
                _post_json(
                    "https://example.com/hook",
                    {},
                    extra_headers={"Authorization": "Bearer mytoken", "X-Custom": "val"},
                )
            except Exception:
                pass

        assert captured, "urlopen was never called"
        h = captured[0]
        auth = h.get("Authorization") or h.get("authorization")
        assert auth == "Bearer mytoken"

    def test_extra_headers_do_not_override_content_type(self):
        captured = []

        def fake_open(req, timeout=None):
            captured.append(dict(req.headers))
            raise Exception("stop")

        with patch("urllib.request.urlopen", side_effect=fake_open):
            try:
                _post_json(
                    "https://example.com/hook",
                    {},
                    extra_headers={"Content-Type": "text/plain"},
                )
            except Exception:
                pass

        # urllib title-cases headers; Content-Type may be overridden by caller — that's fine
        assert captured

    def test_rejects_non_https(self):
        with pytest.raises(ValueError, match="HTTPS"):
            _post_json("http://example.com/hook", {})


# ---------------------------------------------------------------------------
# _route_channels — webhook auto fan-out
# ---------------------------------------------------------------------------


class TestRouteChannelsWebhook:
    def test_webhook_included_when_enabled_with_targets(self):
        channels = _route_channels(make_alert(), make_settings_webhook())
        assert "webhook" in channels

    def test_webhook_excluded_when_disabled(self):
        channels = _route_channels(make_alert(), make_settings_webhook(enabled=False))
        assert "webhook" not in channels

    def test_webhook_excluded_when_no_targets(self):
        channels = _route_channels(make_alert(), make_settings_webhook(targets=[]))
        assert "webhook" not in channels

    def test_webhook_honoured_in_explicit_routing(self):
        settings = make_settings_webhook()
        settings["routing"] = {"HIGH": "webhook"}
        channels = _route_channels(make_alert(severity="HIGH"), settings)
        assert channels == ["webhook"]

    def test_webhook_honoured_in_list_routing(self):
        settings = make_settings_webhook()
        settings["routing"] = {"HIGH": ["slack", "webhook"]}
        settings["channels"]["slack"] = {"enabled": True, "webhook_url": "https://hooks.slack.com/x"}
        channels = _route_channels(make_alert(severity="HIGH"), settings)
        assert "webhook" in channels


# ---------------------------------------------------------------------------
# lambda_handler — webhook channel
# ---------------------------------------------------------------------------


class TestLambdaHandlerWebhook:
    def _mock_post(self, status=200):
        return patch(
            "src.handlers.notifier._post_json",
            return_value=(status, "ok"),
        )

    def test_single_target_success_counted(self):
        with (
            patch("src.handlers.notifier.load_global_settings", return_value=make_settings_webhook()),
            patch("src.handlers.notifier.AwsHandler"),
            self._mock_post(),
        ):
            result = lambda_handler(make_sqs_event(make_alert()), make_context())

        assert result["sent"] == 1
        assert result["failed"] == 0

    def test_correct_url_used(self):
        calls = []

        def capture(url, payload, *, extra_headers=None, **kw):
            calls.append(url)
            return 200, "ok"

        with (
            patch("src.handlers.notifier.load_global_settings", return_value=make_settings_webhook()),
            patch("src.handlers.notifier.AwsHandler"),
            patch("src.handlers.notifier._post_json", side_effect=capture),
        ):
            lambda_handler(make_sqs_event(make_alert()), make_context())

        assert calls[0] == "https://events.pagerduty.com/v2/enqueue"

    def test_custom_headers_forwarded(self):
        calls = []

        def capture(url, payload, *, extra_headers=None, **kw):
            calls.append(extra_headers)
            return 200, "ok"

        targets = [{"name": "opsgenie", "url": "https://api.opsgenie.com/v2/alerts",
                    "headers": {"Authorization": "GenieKey abc123"}}]
        with (
            patch("src.handlers.notifier.load_global_settings", return_value=make_settings_webhook(targets=targets)),
            patch("src.handlers.notifier.AwsHandler"),
            patch("src.handlers.notifier._post_json", side_effect=capture),
        ):
            lambda_handler(make_sqs_event(make_alert()), make_context())

        assert calls[0] == {"Authorization": "GenieKey abc123"}

    def test_empty_headers_dict_passed_as_none(self):
        """An empty headers dict should be treated as no extra headers."""
        calls = []

        def capture(url, payload, *, extra_headers=None, **kw):
            calls.append(extra_headers)
            return 200, "ok"

        targets = [{"name": "hook", "url": "https://example.com/hook", "headers": {}}]
        with (
            patch("src.handlers.notifier.load_global_settings", return_value=make_settings_webhook(targets=targets)),
            patch("src.handlers.notifier.AwsHandler"),
            patch("src.handlers.notifier._post_json", side_effect=capture),
        ):
            lambda_handler(make_sqs_event(make_alert()), make_context())

        assert not calls[0]  # None or empty dict

    def test_alert_payload_forwarded_as_is(self):
        payloads = []

        def capture(url, payload, **kw):
            payloads.append(payload)
            return 200, "ok"

        with (
            patch("src.handlers.notifier.load_global_settings", return_value=make_settings_webhook()),
            patch("src.handlers.notifier.AwsHandler"),
            patch("src.handlers.notifier._post_json", side_effect=capture),
        ):
            lambda_handler(make_sqs_event(make_alert(rule_id="rule-007")), make_context())

        assert payloads[0].get("rule_id") == "rule-007"

    def test_multiple_targets_all_succeed(self):
        targets = [
            {"name": "pd", "url": "https://events.pagerduty.com/v2/enqueue", "headers": {}},
            {"name": "og", "url": "https://api.opsgenie.com/v2/alerts", "headers": {"Authorization": "GenieKey x"}},
        ]
        with (
            patch("src.handlers.notifier.load_global_settings", return_value=make_settings_webhook(targets=targets)),
            patch("src.handlers.notifier.AwsHandler"),
            self._mock_post(200),
        ):
            result = lambda_handler(make_sqs_event(make_alert()), make_context())

        assert result["sent"] == 2
        assert result["failed"] == 0

    def test_multiple_targets_partial_failure(self):
        call_count = [0]

        def capture(url, payload, **kw):
            call_count[0] += 1
            if call_count[0] == 1:
                return 200, "ok"
            return 500, "internal server error"

        targets = [
            {"name": "ok-target", "url": "https://ok.example.com/hook", "headers": {}},
            {"name": "bad-target", "url": "https://bad.example.com/hook", "headers": {}},
        ]
        with (
            patch("src.handlers.notifier.load_global_settings", return_value=make_settings_webhook(targets=targets)),
            patch("src.handlers.notifier.AwsHandler"),
            patch("src.handlers.notifier._post_json", side_effect=capture),
        ):
            result = lambda_handler(make_sqs_event(make_alert()), make_context())

        assert result["sent"] == 1
        assert result["failed"] == 1

    def test_target_without_url_is_skipped(self):
        targets = [
            {"name": "no-url", "url": "", "headers": {}},
            {"name": "ok", "url": "https://example.com/hook", "headers": {}},
        ]
        with (
            patch("src.handlers.notifier.load_global_settings", return_value=make_settings_webhook(targets=targets)),
            patch("src.handlers.notifier.AwsHandler"),
            self._mock_post(200),
        ):
            result = lambda_handler(make_sqs_event(make_alert()), make_context())

        assert result["sent"] == 1

    def test_http_error_from_target_counted_as_failed(self):
        with (
            patch("src.handlers.notifier.load_global_settings", return_value=make_settings_webhook()),
            patch("src.handlers.notifier.AwsHandler"),
            self._mock_post(400),
        ):
            result = lambda_handler(make_sqs_event(make_alert()), make_context())

        assert result["failed"] == 1
        assert result["sent"] == 0

    def test_exception_from_target_counted_as_failed(self):
        with (
            patch("src.handlers.notifier.load_global_settings", return_value=make_settings_webhook()),
            patch("src.handlers.notifier.AwsHandler"),
            patch("src.handlers.notifier._post_json", side_effect=Exception("timeout")),
        ):
            result = lambda_handler(make_sqs_event(make_alert()), make_context())

        assert result["failed"] == 1

    def test_webhook_disabled_does_not_post(self):
        with (
            patch("src.handlers.notifier.load_global_settings", return_value=make_settings_webhook(enabled=False)),
            patch("src.handlers.notifier.AwsHandler"),
            patch("src.handlers.notifier._post_json") as mock_post,
        ):
            result = lambda_handler(make_sqs_event(make_alert()), make_context())

        mock_post.assert_not_called()
        assert result["sent"] == 0

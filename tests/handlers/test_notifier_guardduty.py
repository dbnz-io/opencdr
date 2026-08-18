"""Tests for GuardDuty-specific notification gating in notifier handler.

GuardDuty items default to no notification; settings.guardduty_notify opts
specific severities/services back in. This is a separate decision from
_route_channels (which only picks channels once an item is eligible to send)
and from the item-level notify flag (which processor.py sets True for every
GuardDuty match so it's still visible in the alerts table/API).
"""
from __future__ import annotations

import json
import os
from unittest.mock import MagicMock, patch

os.environ.setdefault("LOGS_TABLE_NAME", "test-logs-table")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

from src.handlers.notifier import _guardduty_should_notify, lambda_handler


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_gd_item(**overrides) -> dict:
    base = {
        "alert_id": "alert-gd-001",
        "alert_key": "024_guardduty_iam_credential_compromise#suspicious-user",
        "source": "guardduty",
        "severity": "HIGH",
        "gd_resource_type": "IAMUser",
        "rule_id": "024_guardduty_iam_credential_compromise",
        "notify": True,
        "playbook": "Disable the compromised access key.",
        "match_count": 1,
        "primary_signal": {
            "actor": {"user_name": "suspicious-user"},
            "network": {"source_ip": "9.10.11.12"},
            "api": {"operation": "UnauthorizedAccess:IAMUser/TorIPCaller"},
        },
        "signal_refs": [
            {"timestamp": "2026-01-01T00:00:00Z", "rule_id": "024_guardduty_iam_credential_compromise", "detection_id": "det-gd-1"},
        ],
    }
    base.update(overrides)
    return base


def make_settings(guardduty_notify=None, routing=None, webhook="https://hooks.slack.com/test") -> dict:
    return {
        "notifications_enabled": True,
        "channels": {
            "slack": {"enabled": True, "webhook_url": webhook},
            "discord": {"enabled": False, "webhook_url": ""},
            "email": {"enabled": False, "topic_arn": ""},
        },
        "routing": routing or {},
        "guardduty_notify": guardduty_notify if guardduty_notify is not None else {},
    }


def make_sqs_event(item: dict) -> dict:
    return {"Records": [{"body": json.dumps(item)}]}


def make_context():
    ctx = MagicMock()
    ctx.aws_request_id = "test-req-id"
    return ctx


def _post_ok(url, payload, **kwargs):
    return 200, "ok"


# ---------------------------------------------------------------------------
# _guardduty_should_notify — precedence
# ---------------------------------------------------------------------------


class TestGuardDutyShouldNotifyPrecedence:
    def test_absent_guardduty_notify_defaults_to_false(self):
        # The critical case: no settings written at all -> every GuardDuty
        # item is skipped, including CRITICAL/Attack Sequence findings.
        item = make_gd_item(severity="CRITICAL", gd_resource_type="")
        assert _guardduty_should_notify(item, {}) is False

    def test_default_true_notifies_everything_not_overridden(self):
        settings = {"guardduty_notify": {"default": True}}
        item = make_gd_item(severity="LOW", gd_resource_type="EC2")
        assert _guardduty_should_notify(item, settings) is True

    def test_by_severity_overrides_default(self):
        settings = {"guardduty_notify": {"default": False, "by_severity": {"CRITICAL": True}}}
        assert _guardduty_should_notify(make_gd_item(severity="CRITICAL"), settings) is True
        assert _guardduty_should_notify(make_gd_item(severity="HIGH"), settings) is False

    def test_by_service_overrides_by_severity(self):
        # Deliberately conflicting settings to prove precedence, not just presence.
        settings = {
            "guardduty_notify": {
                "default": False,
                "by_severity": {"HIGH": False},
                "by_service": {"IAMUser": True},
            }
        }
        item = make_gd_item(severity="HIGH", gd_resource_type="IAMUser")
        assert _guardduty_should_notify(item, settings) is True

    def test_by_severity_and_service_overrides_everything(self):
        settings = {
            "guardduty_notify": {
                "default": True,
                "by_severity": {"HIGH": True},
                "by_service": {"IAMUser": True},
                "by_severity_and_service": {"HIGH:IAMUser": False},
            }
        }
        item = make_gd_item(severity="HIGH", gd_resource_type="IAMUser")
        assert _guardduty_should_notify(item, settings) is False

    def test_missing_gd_resource_type_skips_service_lookups(self):
        settings = {"guardduty_notify": {"default": False, "by_service": {"IAMUser": True}}}
        item = make_gd_item(gd_resource_type="")
        assert _guardduty_should_notify(item, settings) is False

    def test_malformed_guardduty_notify_does_not_crash(self):
        item = make_gd_item()
        assert _guardduty_should_notify(item, {"guardduty_notify": "not-a-dict"}) is False
        assert _guardduty_should_notify(item, {"guardduty_notify": None}) is False


# ---------------------------------------------------------------------------
# lambda_handler — GuardDuty gating integration
# ---------------------------------------------------------------------------


class TestLambdaHandlerGuardDutyGating:
    def test_skips_guardduty_item_when_settings_absent(self):
        settings = make_settings()
        with (
            patch("src.handlers.notifier.load_global_settings", return_value=settings),
            patch("src.handlers.notifier.AwsHandler"),
            patch("src.handlers.notifier._post_json", side_effect=_post_ok) as mock_post,
        ):
            result = lambda_handler(make_sqs_event(make_gd_item()), make_context())
        mock_post.assert_not_called()
        assert result["skipped"] == 1
        assert result["sent"] == 0

    def test_sends_guardduty_item_when_opted_in_by_severity(self):
        settings = make_settings(guardduty_notify={"default": False, "by_severity": {"HIGH": True}})
        with (
            patch("src.handlers.notifier.load_global_settings", return_value=settings),
            patch("src.handlers.notifier.AwsHandler"),
            patch("src.handlers.notifier._post_json", side_effect=_post_ok) as mock_post,
        ):
            result = lambda_handler(make_sqs_event(make_gd_item(severity="HIGH")), make_context())
        mock_post.assert_called_once()
        assert result["sent"] == 1

    def test_non_guardduty_item_unaffected_by_absent_guardduty_notify(self):
        # Regression guard: a CloudTrail-sourced item must not be touched by
        # this gate at all, even when guardduty_notify is empty/absent.
        settings = make_settings()
        item = {
            "alert_id": "alert-ct-001",
            "alert_key": "009_admin_policy_attached#alice",
            "severity": "HIGH",
            "rule_id": "009_admin_policy_attached",
            "playbook": "Detach the admin policy.",
            "match_count": 1,
            "primary_signal": {
                "actor": {"user_name": "alice"},
                "network": {"source_ip": "1.2.3.4"},
                "api": {"operation": "AttachUserPolicy"},
            },
            "signal_refs": [
                {"timestamp": "2026-01-01T00:00:00Z", "rule_id": "009_admin_policy_attached", "detection_id": "det-ct-1"},
            ],
        }
        with (
            patch("src.handlers.notifier.load_global_settings", return_value=settings),
            patch("src.handlers.notifier.AwsHandler"),
            patch("src.handlers.notifier._post_json", side_effect=_post_ok),
        ):
            result = lambda_handler(make_sqs_event(item), make_context())
        assert result["sent"] == 1
        assert result["skipped"] == 0

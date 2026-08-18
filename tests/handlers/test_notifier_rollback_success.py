"""Tests for the "rollback_success" notification type: purple-styled
Slack/Discord/email payloads for a rollbackHandler undo that succeeded, and
the lambda_handler dispatch that routes to them instead of the
remediation-success (green) or alert builders.
"""
from __future__ import annotations

import json
import os
from unittest.mock import MagicMock, patch

os.environ.setdefault("LOGS_TABLE_NAME", "test-logs-table")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

from src.handlers.notifier import (
    build_rollback_success_discord_payload,
    build_rollback_success_email_message,
    build_rollback_success_slack_payload,
    lambda_handler,
)


def make_rollback_item(**overrides) -> dict:
    base = {
        "type": "rollback_success",
        "notify": True,
        "detection_id": "d-1",
        "rule_id": "011_security_group_opened",
        "severity": "UNKNOWN",
        "response_module": "deauthorize_security_group_rules",
        "undo_module": "authorize_security_group_rules",
        "cloud_account_id": "123456789012",
        "operation": "authorize_security_group_rules",
        "target": "sg=sg-0abc123",
        "timestamp": "2026-08-15T00:00:00+00:00",
    }
    base.update(overrides)
    return base


def make_sqs_event(item: dict) -> dict:
    return {"Records": [{"body": json.dumps(item)}]}


def make_context():
    ctx = MagicMock()
    ctx.aws_request_id = "test-req-id"
    return ctx


def make_settings_all_channels() -> dict:
    return {
        "notifications_enabled": True,
        "channels": {
            "slack": {"enabled": True, "webhook_url": "https://hooks.slack.com/test"},
            "discord": {"enabled": True, "webhook_url": "https://discord.com/api/webhooks/test"},
            "email": {"enabled": False, "topic_arn": ""},
            "securityhub": {"enabled": True},
            "jira": {"enabled": False},
            "webhook": {"enabled": False, "targets": []},
        },
        "routing": {},
    }


class TestBuildRollbackSuccessSlackPayload:
    def test_returns_attachments_with_purple_color(self):
        payload = build_rollback_success_slack_payload(make_rollback_item())
        assert payload["attachments"][0]["color"] == "#7b1fa2"

    def test_color_differs_from_remediation_green_and_severity_colors(self):
        payload = build_rollback_success_slack_payload(make_rollback_item())
        color = payload["attachments"][0]["color"]
        assert color not in {"#2e7d32", "#d32f2f", "#f57c00", "#fbc02d", "#1976d2", "#616161"}

    def test_blocks_contain_rule_original_action_and_undo(self):
        payload = build_rollback_success_slack_payload(make_rollback_item())
        text = json.dumps(payload)
        assert "011_security_group_opened" in text
        assert "deauthorize_security_group_rules" in text
        assert "authorize_security_group_rules" in text
        assert "sg=sg-0abc123" in text

    def test_detection_id_in_context_when_present(self):
        payload = build_rollback_success_slack_payload(make_rollback_item())
        assert any(b.get("type") == "context" for b in payload["attachments"][0]["blocks"])

    def test_no_context_block_when_detection_id_missing(self):
        payload = build_rollback_success_slack_payload(make_rollback_item(detection_id=""))
        assert not any(b.get("type") == "context" for b in payload["attachments"][0]["blocks"])


class TestBuildRollbackSuccessDiscordPayload:
    def test_returns_embeds_with_purple_color(self):
        payload = build_rollback_success_discord_payload(make_rollback_item())
        assert payload["embeds"][0]["color"] == 8069026

    def test_color_differs_from_remediation_green_and_severity_colors(self):
        payload = build_rollback_success_discord_payload(make_rollback_item())
        color = payload["embeds"][0]["color"]
        assert color not in {3066993, 15158332, 15105570, 15844367, 3447003, 9807270}

    def test_title_contains_rule_id_and_status(self):
        payload = build_rollback_success_discord_payload(make_rollback_item())
        assert "011_security_group_opened" in payload["embeds"][0]["title"]
        assert "ROLLED BACK" in payload["embeds"][0]["title"]


class TestBuildRollbackSuccessEmailMessage:
    def test_subject_and_body(self):
        subject, body = build_rollback_success_email_message(make_rollback_item())
        assert "Rolled back" in subject
        assert "011_security_group_opened" in subject
        assert "ROLLED BACK" in body
        assert "deauthorize_security_group_rules" in body
        assert "authorize_security_group_rules" in body


class TestLambdaHandlerRollbackDispatch:
    def _post_ok(self, url, payload, **kwargs):
        return 200, "ok"

    def test_sends_purple_payload_to_slack_and_discord(self):
        settings = make_settings_all_channels()
        with (
            patch("src.handlers.notifier.load_global_settings", return_value=settings),
            patch("src.handlers.notifier.AwsHandler"),
            patch("src.handlers.notifier._post_json", side_effect=self._post_ok) as mock_post,
        ):
            result = lambda_handler(make_sqs_event(make_rollback_item()), make_context())

        assert result["sent"] == 2  # slack + discord; securityhub is skipped
        sent_payloads = [call.args[1] for call in mock_post.call_args_list]
        assert any(p.get("attachments", [{}])[0].get("color") == "#7b1fa2" for p in sent_payloads)
        assert any(p.get("embeds", [{}])[0].get("color") == 8069026 for p in sent_payloads)

    def test_securityhub_skipped_for_rollback_items(self):
        settings = make_settings_all_channels()
        with (
            patch("src.handlers.notifier.load_global_settings", return_value=settings),
            patch("src.handlers.notifier.AwsHandler") as mock_aws_cls,
            patch("src.handlers.notifier._post_json", side_effect=self._post_ok),
        ):
            lambda_handler(make_sqs_event(make_rollback_item()), make_context())
        mock_aws_cls.return_value._securityhub.batch_import_findings.assert_not_called()

    def test_rollback_and_remediation_use_different_colors(self):
        """The whole point: a rollback must not look like the thing it undid."""
        from src.handlers.notifier import build_remediation_success_slack_payload

        remediation_color = build_remediation_success_slack_payload(
            {"type": "remediation_success", "rule_id": "r", "response_module": "x", "target": "t"}
        )["attachments"][0]["color"]
        rollback_color = build_rollback_success_slack_payload(make_rollback_item())["attachments"][0]["color"]
        assert remediation_color != rollback_color

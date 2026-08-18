"""Tests for the "remediation_success" notification type: green-styled
Slack/Discord/email payloads for a responder action that succeeded, and the
lambda_handler dispatch that routes to them instead of the alert builders.
"""
from __future__ import annotations

import json
import os
from unittest.mock import MagicMock, patch

os.environ.setdefault("LOGS_TABLE_NAME", "test-logs-table")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

from src.handlers.notifier import (
    build_remediation_success_discord_payload,
    build_remediation_success_email_message,
    build_remediation_success_slack_payload,
    lambda_handler,
)


def make_remediation_item(**overrides) -> dict:
    base = {
        "type": "remediation_success",
        "notify": True,
        "detection_id": "d-1",
        "rule_id": "006_access_key_created",
        "severity": "MEDIUM",
        "response_module": "disable_access_key",
        "cloud_account_id": "123456789012",
        "operation": "disable_access_key",
        "target": "user=alice,access_key_id=AKIA123",
        "timestamp": "2026-08-02T00:00:00+00:00",
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


class TestBuildRemediationSuccessSlackPayload:
    def test_returns_attachments_with_green_color(self):
        payload = build_remediation_success_slack_payload(make_remediation_item())
        assert payload["attachments"][0]["color"] == "#2e7d32"

    def test_blocks_contain_rule_and_action(self):
        payload = build_remediation_success_slack_payload(make_remediation_item())
        text = json.dumps(payload)
        assert "006_access_key_created" in text
        assert "disable_access_key" in text
        assert "user=alice,access_key_id=AKIA123" in text

    def test_detection_id_in_context_when_present(self):
        payload = build_remediation_success_slack_payload(make_remediation_item())
        assert any(
            b.get("type") == "context" for b in payload["attachments"][0]["blocks"]
        )

    def test_no_context_block_when_detection_id_missing(self):
        payload = build_remediation_success_slack_payload(make_remediation_item(detection_id=""))
        assert not any(
            b.get("type") == "context" for b in payload["attachments"][0]["blocks"]
        )


class TestBuildRemediationSuccessDiscordPayload:
    def test_returns_embeds_with_green_color(self):
        payload = build_remediation_success_discord_payload(make_remediation_item())
        assert payload["embeds"][0]["color"] == 3066993

    def test_title_contains_rule_id(self):
        payload = build_remediation_success_discord_payload(make_remediation_item())
        assert "006_access_key_created" in payload["embeds"][0]["title"]
        assert "REMEDIATED" in payload["embeds"][0]["title"]


class TestBuildRemediationSuccessEmailMessage:
    def test_subject_and_body(self):
        subject, body = build_remediation_success_email_message(make_remediation_item())
        assert "Remediated" in subject
        assert "006_access_key_created" in subject
        assert "REMEDIATED" in body
        assert "disable_access_key" in body


class TestBuildRemediationSuccessSlackPayloadDryRun:
    def test_uses_dry_run_color_not_green(self):
        payload = build_remediation_success_slack_payload(make_remediation_item(dry_run=True))
        assert payload["attachments"][0]["color"] == "#607d8b"

    def test_header_says_dry_run_simulated(self):
        payload = build_remediation_success_slack_payload(make_remediation_item(dry_run=True))
        text = json.dumps(payload)
        assert "DRY RUN" in text
        assert "SIMULATED" in text

    def test_includes_explanatory_note_block(self):
        payload = build_remediation_success_slack_payload(make_remediation_item(dry_run=True))
        text = json.dumps(payload)
        assert "DREDGE_DRY_RUN" in text
        assert "no AWS API call was made" in text

    def test_real_run_has_no_dry_run_language(self):
        payload = build_remediation_success_slack_payload(make_remediation_item(dry_run=False))
        text = json.dumps(payload)
        assert "DRY RUN" not in text
        assert "SIMULATED" not in text


class TestBuildRemediationSuccessDiscordPayloadDryRun:
    def test_uses_dry_run_color_not_green(self):
        payload = build_remediation_success_discord_payload(make_remediation_item(dry_run=True))
        assert payload["embeds"][0]["color"] == 6323595

    def test_title_says_dry_run_simulated(self):
        payload = build_remediation_success_discord_payload(make_remediation_item(dry_run=True))
        assert "DRY RUN" in payload["embeds"][0]["title"]
        assert "SIMULATED" in payload["embeds"][0]["title"]

    def test_real_run_title_unaffected(self):
        payload = build_remediation_success_discord_payload(make_remediation_item(dry_run=False))
        assert payload["embeds"][0]["title"] == "REMEDIATED — 006_access_key_created"


class TestBuildRemediationSuccessEmailMessageDryRun:
    def test_subject_and_body_flag_dry_run(self):
        subject, body = build_remediation_success_email_message(make_remediation_item(dry_run=True))
        assert "Dry run" in subject
        assert "DRY RUN (SIMULATED)" in body
        assert "DREDGE_DRY_RUN" in body

    def test_real_run_unaffected(self):
        subject, body = build_remediation_success_email_message(make_remediation_item(dry_run=False))
        assert "Dry run" not in subject
        assert "DRY RUN" not in body


class TestLambdaHandlerRemediationDispatch:
    def _post_ok(self, url, payload, **kwargs):
        return 200, "ok"

    def test_sends_green_payload_to_slack_and_discord(self):
        settings = make_settings_all_channels()
        with (
            patch("src.handlers.notifier.load_global_settings", return_value=settings),
            patch("src.handlers.notifier.AwsHandler"),
            patch("src.handlers.notifier._post_json", side_effect=self._post_ok) as mock_post,
        ):
            result = lambda_handler(make_sqs_event(make_remediation_item()), make_context())

        assert result["sent"] == 2  # slack + discord; securityhub is skipped
        sent_payloads = [call.args[1] for call in mock_post.call_args_list]
        assert any(p.get("attachments", [{}])[0].get("color") == "#2e7d32" for p in sent_payloads)
        assert any(p.get("embeds", [{}])[0].get("color") == 3066993 for p in sent_payloads)

    def test_securityhub_skipped_for_remediation_items(self):
        settings = make_settings_all_channels()
        with (
            patch("src.handlers.notifier.load_global_settings", return_value=settings),
            patch("src.handlers.notifier.AwsHandler") as mock_aws_cls,
            patch("src.handlers.notifier._post_json", side_effect=self._post_ok),
        ):
            lambda_handler(make_sqs_event(make_remediation_item()), make_context())
        mock_aws_cls.return_value._securityhub.batch_import_findings.assert_not_called()

    def test_ordinary_alert_still_uses_alert_builders(self):
        settings = make_settings_all_channels()
        settings["channels"]["securityhub"]["enabled"] = False
        alert = {
            "alert_id": "a-1",
            "severity": "HIGH",
            "rule_id": "rule-001",
            "playbook": "do the thing",
            "primary_signal": {"actor": {"user_name": "alice"}},
        }
        with (
            patch("src.handlers.notifier.load_global_settings", return_value=settings),
            patch("src.handlers.notifier.AwsHandler"),
            patch("src.handlers.notifier._post_json", side_effect=self._post_ok) as mock_post,
        ):
            lambda_handler(make_sqs_event(alert), make_context())
        sent_payloads = [call.args[1] for call in mock_post.call_args_list]
        # HIGH severity color (#f57c00), not the remediation green.
        assert any(p.get("attachments", [{}])[0].get("color") == "#f57c00" for p in sent_payloads)

    def test_dry_run_remediation_dispatches_the_simulated_payload(self):
        settings = make_settings_all_channels()
        with (
            patch("src.handlers.notifier.load_global_settings", return_value=settings),
            patch("src.handlers.notifier.AwsHandler"),
            patch("src.handlers.notifier._post_json", side_effect=self._post_ok) as mock_post,
        ):
            result = lambda_handler(make_sqs_event(make_remediation_item(dry_run=True)), make_context())

        assert result["sent"] == 2
        sent_payloads = [call.args[1] for call in mock_post.call_args_list]
        assert any(p.get("attachments", [{}])[0].get("color") == "#607d8b" for p in sent_payloads)
        assert any(p.get("embeds", [{}])[0].get("color") == 6323595 for p in sent_payloads)

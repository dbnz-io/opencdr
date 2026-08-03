"""Tests for the Security Hub notification channel in notifier handler."""
from __future__ import annotations

import json
import os
from unittest.mock import MagicMock, patch

import pytest

os.environ.setdefault("LOGS_TABLE_NAME", "test-logs-table")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_REGION", "us-east-1")

from src.handlers.notifier import (
    _iso8601_z,
    _route_channels,
    build_securityhub_finding,
    lambda_handler,
)

_PRODUCT_ARN = "arn:aws:securityhub:us-east-1:123456789012:product/123456789012/default"
_ACCOUNT_ID = "123456789012"
_FUNCTION_ARN = f"arn:aws:lambda:us-east-1:{_ACCOUNT_ID}:function:test-notifier"


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
        "timestamp": "2026-01-01T00:00:00",
        "match_count": 3,
        "primary_signal": {
            "activity_name": "AssumeRole",
            "actor": {
                "user_name": "alice",
                "arn": "arn:aws:iam::123456789012:user/alice",
                "account_id": "123456789012",
            },
            "network": {"source_ip": "1.2.3.4"},
            "api": {"operation": "AssumeRole"},
        },
    }
    base.update(overrides)
    return base


def make_settings_securityhub(routing=None) -> dict:
    return {
        "notifications_enabled": True,
        "channels": {
            "slack": {"enabled": False, "webhook_url": ""},
            "discord": {"enabled": False, "webhook_url": ""},
            "email": {"enabled": False, "topic_arn": ""},
            "securityhub": {"enabled": True},
        },
        "routing": routing or {},
    }


def make_sqs_event(item: dict) -> dict:
    return {"Records": [{"body": json.dumps(item)}]}


def make_context():
    ctx = MagicMock()
    ctx.aws_request_id = "test-req-id"
    ctx.invoked_function_arn = _FUNCTION_ARN
    return ctx


# ---------------------------------------------------------------------------
# _iso8601_z
# ---------------------------------------------------------------------------


class TestIso8601Z:
    def test_adds_z_when_missing(self):
        assert _iso8601_z("2026-01-01T00:00:00") == "2026-01-01T00:00:00Z"

    def test_leaves_existing_z_untouched(self):
        assert _iso8601_z("2026-01-01T00:00:00Z") == "2026-01-01T00:00:00Z"

    def test_leaves_offset_aware_timestamp_untouched(self):
        assert _iso8601_z("2026-01-01T00:00:00+00:00") == "2026-01-01T00:00:00+00:00"

    def test_empty_string_passthrough(self):
        assert _iso8601_z("") == ""


# ---------------------------------------------------------------------------
# build_securityhub_finding
# ---------------------------------------------------------------------------


class TestBuildSecurityhubFinding:
    def test_required_asff_fields_present(self):
        finding = build_securityhub_finding(make_alert(), product_arn=_PRODUCT_ARN, account_id=_ACCOUNT_ID)
        for field in ("SchemaVersion", "Id", "ProductArn", "GeneratorId", "AwsAccountId",
                      "Types", "CreatedAt", "UpdatedAt", "Severity", "Title",
                      "Description", "Resources", "FindingProviderFields",
                      "Workflow", "RecordState"):
            assert field in finding, f"Missing required ASFF field: {field}"

    def test_schema_version(self):
        finding = build_securityhub_finding(make_alert(), product_arn=_PRODUCT_ARN, account_id=_ACCOUNT_ID)
        assert finding["SchemaVersion"] == "2018-10-08"

    def test_id_includes_alert_id(self):
        finding = build_securityhub_finding(make_alert(alert_id="abc-123"), product_arn=_PRODUCT_ARN, account_id=_ACCOUNT_ID)
        assert "abc-123" in finding["Id"]

    def test_generator_id_includes_rule_id(self):
        finding = build_securityhub_finding(make_alert(rule_id="rule-042"), product_arn=_PRODUCT_ARN, account_id=_ACCOUNT_ID)
        assert "rule-042" in finding["GeneratorId"]

    def test_product_arn_propagated(self):
        finding = build_securityhub_finding(make_alert(), product_arn=_PRODUCT_ARN, account_id=_ACCOUNT_ID)
        assert finding["ProductArn"] == _PRODUCT_ARN

    def test_timestamp_gets_z_suffix(self):
        finding = build_securityhub_finding(make_alert(timestamp="2026-01-01T00:00:00"), product_arn=_PRODUCT_ARN, account_id=_ACCOUNT_ID)
        assert finding["CreatedAt"].endswith("Z")
        assert finding["UpdatedAt"].endswith("Z")

    @pytest.mark.parametrize("severity,expected_label,expected_min_normalized", [
        ("CRITICAL", "CRITICAL", 80),
        ("HIGH", "HIGH", 60),
        ("MEDIUM", "MEDIUM", 30),
        ("LOW", "LOW", 10),
        ("UNKNOWN", "INFORMATIONAL", 0),
    ])
    def test_severity_mapping(self, severity, expected_label, expected_min_normalized):
        finding = build_securityhub_finding(make_alert(severity=severity), product_arn=_PRODUCT_ARN, account_id=_ACCOUNT_ID)
        assert finding["Severity"]["Label"] == expected_label
        assert finding["Severity"]["Normalized"] >= expected_min_normalized

    def test_title_contains_rule_id_and_activity(self):
        finding = build_securityhub_finding(make_alert(rule_id="rule-001"), product_arn=_PRODUCT_ARN, account_id=_ACCOUNT_ID)
        assert "rule-001" in finding["Title"]
        assert "AssumeRole" in finding["Title"]

    def test_title_truncated_to_256(self):
        long_rule = "r" * 300
        finding = build_securityhub_finding(make_alert(rule_id=long_rule), product_arn=_PRODUCT_ARN, account_id=_ACCOUNT_ID)
        assert len(finding["Title"]) <= 256

    def test_description_is_playbook(self):
        finding = build_securityhub_finding(make_alert(playbook="Do the thing."), product_arn=_PRODUCT_ARN, account_id=_ACCOUNT_ID)
        assert "Do the thing." in finding["Description"]

    def test_resource_uses_user_arn_when_present(self):
        finding = build_securityhub_finding(make_alert(), product_arn=_PRODUCT_ARN, account_id=_ACCOUNT_ID)
        resource = finding["Resources"][0]
        assert resource["Type"] == "AwsIamUser"
        assert resource["Id"] == "arn:aws:iam::123456789012:user/alice"

    def test_resource_falls_back_to_constructed_arn_when_no_arn(self):
        alert = make_alert()
        alert["primary_signal"]["actor"].pop("arn")
        finding = build_securityhub_finding(alert, product_arn=_PRODUCT_ARN, account_id=_ACCOUNT_ID)
        resource = finding["Resources"][0]
        assert resource["Type"] == "AwsIamUser"
        assert "alice" in resource["Id"]

    def test_resource_falls_back_to_account_when_no_user(self):
        alert = make_alert()
        alert["primary_signal"]["actor"] = {"account_id": "123456789012"}
        finding = build_securityhub_finding(alert, product_arn=_PRODUCT_ARN, account_id=_ACCOUNT_ID)
        resource = finding["Resources"][0]
        assert resource["Type"] == "AwsAccount"

    def test_account_id_from_actor_takes_precedence(self):
        alert = make_alert()
        alert["primary_signal"]["actor"]["account_id"] = "999999999999"
        finding = build_securityhub_finding(alert, product_arn=_PRODUCT_ARN, account_id=_ACCOUNT_ID)
        assert finding["AwsAccountId"] == "999999999999"

    def test_workflow_status_is_new(self):
        finding = build_securityhub_finding(make_alert(), product_arn=_PRODUCT_ARN, account_id=_ACCOUNT_ID)
        assert finding["Workflow"]["Status"] == "NEW"

    def test_record_state_is_active(self):
        finding = build_securityhub_finding(make_alert(), product_arn=_PRODUCT_ARN, account_id=_ACCOUNT_ID)
        assert finding["RecordState"] == "ACTIVE"

    def test_finding_provider_fields_severity_matches(self):
        finding = build_securityhub_finding(make_alert(severity="CRITICAL"), product_arn=_PRODUCT_ARN, account_id=_ACCOUNT_ID)
        assert finding["FindingProviderFields"]["Severity"]["Label"] == "CRITICAL"

    def test_at_least_one_resource(self):
        finding = build_securityhub_finding(make_alert(), product_arn=_PRODUCT_ARN, account_id=_ACCOUNT_ID)
        assert len(finding["Resources"]) >= 1


# ---------------------------------------------------------------------------
# _route_channels — securityhub auto fan-out
# ---------------------------------------------------------------------------


class TestRouteChannelsSecurityHub:
    def test_securityhub_included_when_enabled(self):
        settings = make_settings_securityhub()
        channels = _route_channels(make_alert(), settings)
        assert "securityhub" in channels

    def test_securityhub_excluded_when_disabled(self):
        settings = make_settings_securityhub()
        settings["channels"]["securityhub"]["enabled"] = False
        channels = _route_channels(make_alert(), settings)
        assert "securityhub" not in channels

    def test_securityhub_excluded_when_channel_absent(self):
        settings = {
            "notifications_enabled": True,
            "channels": {"slack": {"enabled": False, "webhook_url": ""}},
            "routing": {},
        }
        channels = _route_channels(make_alert(), settings)
        assert "securityhub" not in channels

    def test_securityhub_honoured_in_explicit_routing(self):
        settings = make_settings_securityhub(routing={"HIGH": "securityhub"})
        channels = _route_channels(make_alert(severity="HIGH"), settings)
        assert channels == ["securityhub"]

    def test_securityhub_honoured_in_list_routing(self):
        settings = make_settings_securityhub(routing={"HIGH": ["slack", "securityhub"]})
        settings["channels"]["slack"] = {"enabled": True, "webhook_url": "https://hooks.slack.com/x"}
        channels = _route_channels(make_alert(severity="HIGH"), settings)
        assert "securityhub" in channels


# ---------------------------------------------------------------------------
# lambda_handler — Security Hub channel
# ---------------------------------------------------------------------------


class TestLambdaHandlerSecurityHub:
    def _mock_sh(self, fail_count=0):
        mock = MagicMock()
        mock.batch_import_findings.return_value = {
            "SuccessCount": 1 - fail_count,
            "FailedCount": fail_count,
            "FailedFindings": (
                [{"ErrorCode": "InvalidInput", "ErrorMessage": "bad finding", "Id": "x"}]
                if fail_count
                else []
            ),
        }
        return mock

    def test_successful_send_counted(self):
        sh_mock = self._mock_sh()
        aws_mock = MagicMock()
        aws_mock._securityhub = sh_mock
        settings = make_settings_securityhub()

        with (
            patch("src.handlers.notifier.load_global_settings", return_value=settings),
            patch("src.handlers.notifier.AwsHandler", return_value=aws_mock),
        ):
            result = lambda_handler(make_sqs_event(make_alert()), make_context())

        assert result["sent"] == 1
        assert result["failed"] == 0
        sh_mock.batch_import_findings.assert_called_once()

    def test_finding_passed_to_batch_import(self):
        sh_mock = self._mock_sh()
        aws_mock = MagicMock()
        aws_mock._securityhub = sh_mock
        settings = make_settings_securityhub()

        with (
            patch("src.handlers.notifier.load_global_settings", return_value=settings),
            patch("src.handlers.notifier.AwsHandler", return_value=aws_mock),
        ):
            lambda_handler(make_sqs_event(make_alert(rule_id="rule-007")), make_context())

        call_kwargs = sh_mock.batch_import_findings.call_args
        findings = call_kwargs[1]["Findings"]
        assert len(findings) == 1
        assert "rule-007" in findings[0]["GeneratorId"]

    def test_rejected_finding_counted_as_failed(self):
        sh_mock = self._mock_sh(fail_count=1)
        aws_mock = MagicMock()
        aws_mock._securityhub = sh_mock
        settings = make_settings_securityhub()

        with (
            patch("src.handlers.notifier.load_global_settings", return_value=settings),
            patch("src.handlers.notifier.AwsHandler", return_value=aws_mock),
        ):
            result = lambda_handler(make_sqs_event(make_alert()), make_context())

        assert result["failed"] == 1
        assert result["sent"] == 0

    def test_securityhub_exception_counted_as_failed(self):
        sh_mock = MagicMock()
        sh_mock.batch_import_findings.side_effect = Exception("Connection error")
        aws_mock = MagicMock()
        aws_mock._securityhub = sh_mock
        settings = make_settings_securityhub()

        with (
            patch("src.handlers.notifier.load_global_settings", return_value=settings),
            patch("src.handlers.notifier.AwsHandler", return_value=aws_mock),
        ):
            result = lambda_handler(make_sqs_event(make_alert()), make_context())

        assert result["failed"] == 1

    def test_product_arn_derived_from_context_arn(self):
        sh_mock = self._mock_sh()
        aws_mock = MagicMock()
        aws_mock._securityhub = sh_mock
        settings = make_settings_securityhub()

        with (
            patch("src.handlers.notifier.load_global_settings", return_value=settings),
            patch("src.handlers.notifier.AwsHandler", return_value=aws_mock),
        ):
            lambda_handler(make_sqs_event(make_alert()), make_context())

        findings = sh_mock.batch_import_findings.call_args[1]["Findings"]
        assert _ACCOUNT_ID in findings[0]["ProductArn"]

    def test_securityhub_disabled_does_not_send(self):
        sh_mock = self._mock_sh()
        aws_mock = MagicMock()
        aws_mock._securityhub = sh_mock
        settings = make_settings_securityhub()
        settings["channels"]["securityhub"]["enabled"] = False

        with (
            patch("src.handlers.notifier.load_global_settings", return_value=settings),
            patch("src.handlers.notifier.AwsHandler", return_value=aws_mock),
        ):
            result = lambda_handler(make_sqs_event(make_alert()), make_context())

        sh_mock.batch_import_findings.assert_not_called()
        assert result["sent"] == 0

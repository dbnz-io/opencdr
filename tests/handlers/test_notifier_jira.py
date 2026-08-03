"""Tests for the Jira notification channel in notifier handler."""
from __future__ import annotations

import base64
import json
import os
from unittest.mock import MagicMock, patch

import pytest

os.environ.setdefault("LOGS_TABLE_NAME", "test-logs-table")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

from src.handlers.notifier import (
    _post_json_basic_auth,
    _route_channels,
    build_jira_issue,
    lambda_handler,
)

_JIRA_BASE = "https://yourco.atlassian.net"
_PROJECT = "SEC"
_EMAIL = "soc@yourco.com"
_TOKEN = "api-token-abc"


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
        "match_count": 3,
        "primary_signal": {
            "activity_name": "AssumeRole",
            "actor": {"user_name": "alice", "account_id": "123456789012"},
            "network": {"source_ip": "1.2.3.4"},
            "api": {"operation": "AssumeRole"},
        },
    }
    base.update(overrides)
    return base


def make_settings_jira(**overrides) -> dict:
    jira_cfg = {
        "enabled": True,
        "base_url": _JIRA_BASE,
        "project_key": _PROJECT,
        "user_email": _EMAIL,
        "api_token": _TOKEN,
    }
    jira_cfg.update(overrides)
    return {
        "notifications_enabled": True,
        "channels": {
            "slack": {"enabled": False, "webhook_url": ""},
            "discord": {"enabled": False, "webhook_url": ""},
            "email": {"enabled": False, "topic_arn": ""},
            "jira": jira_cfg,
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


def _created_response(key: str = "SEC-42") -> tuple[int, str]:
    return 201, json.dumps({"id": "10001", "key": key, "self": f"{_JIRA_BASE}/rest/api/3/issue/10001"})


# ---------------------------------------------------------------------------
# _post_json_basic_auth
# ---------------------------------------------------------------------------


class TestPostJsonBasicAuth:
    def test_rejects_non_https_url(self):
        with pytest.raises(ValueError, match="HTTPS"):
            _post_json_basic_auth("http://example.com", {}, email="u", token="t")

    def test_sends_basic_auth_header(self):
        expected = "Basic " + base64.b64encode(f"{_EMAIL}:{_TOKEN}".encode()).decode()
        captured_headers: list[dict] = []

        import urllib.request as _ur

        original_open = _ur.urlopen

        def fake_open(req, timeout=None):
            captured_headers.append(dict(req.headers))
            raise urllib.error.HTTPError(req.full_url, 200, "ok", {}, None)

        import urllib.error

        with patch("urllib.request.urlopen", side_effect=fake_open):
            try:
                _post_json_basic_auth(
                    f"{_JIRA_BASE}/rest/api/3/issue", {}, email=_EMAIL, token=_TOKEN
                )
            except Exception:
                pass

        assert captured_headers, "urlopen was never called"
        # Headers are title-cased by urllib
        auth = captured_headers[0].get("Authorization") or captured_headers[0].get("authorization")
        assert auth == expected

    def test_returns_status_and_body_on_success(self):
        mock_resp = MagicMock()
        mock_resp.status = 201
        mock_resp.read.return_value = b'{"key": "SEC-1"}'
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            status, body = _post_json_basic_auth(
                f"{_JIRA_BASE}/rest/api/3/issue", {}, email=_EMAIL, token=_TOKEN
            )

        assert status == 201
        assert "SEC-1" in body

    def test_returns_error_status_on_http_error(self):
        import urllib.error

        err = urllib.error.HTTPError(
            f"{_JIRA_BASE}/rest/api/3/issue", 400, "Bad Request", {}, None
        )
        err.read = lambda: b'{"errorMessages":["bad field"]}'

        with patch("urllib.request.urlopen", side_effect=err):
            status, body = _post_json_basic_auth(
                f"{_JIRA_BASE}/rest/api/3/issue", {}, email=_EMAIL, token=_TOKEN
            )

        assert status == 400
        assert "bad field" in body


# ---------------------------------------------------------------------------
# build_jira_issue
# ---------------------------------------------------------------------------


class TestBuildJiraIssue:
    def test_fields_key_present(self):
        issue = build_jira_issue(make_alert(), project_key=_PROJECT)
        assert "fields" in issue

    def test_project_key_set(self):
        issue = build_jira_issue(make_alert(), project_key="OPS")
        assert issue["fields"]["project"]["key"] == "OPS"

    def test_summary_contains_severity_and_rule(self):
        issue = build_jira_issue(make_alert(severity="CRITICAL", rule_id="rule-007"), project_key=_PROJECT)
        assert "CRITICAL" in issue["fields"]["summary"]
        assert "rule-007" in issue["fields"]["summary"]

    def test_summary_truncated_to_255(self):
        issue = build_jira_issue(make_alert(rule_id="r" * 300), project_key=_PROJECT)
        assert len(issue["fields"]["summary"]) <= 255

    @pytest.mark.parametrize("severity,expected_priority", [
        ("CRITICAL", "Highest"),
        ("HIGH", "High"),
        ("MEDIUM", "Medium"),
        ("LOW", "Low"),
        ("INFORMATIONAL", "Lowest"),
        ("UNKNOWN", "Medium"),
    ])
    def test_priority_mapping(self, severity, expected_priority):
        issue = build_jira_issue(make_alert(severity=severity), project_key=_PROJECT)
        assert issue["fields"]["priority"]["name"] == expected_priority

    def test_default_issue_type_is_bug(self):
        issue = build_jira_issue(make_alert(), project_key=_PROJECT)
        assert issue["fields"]["issuetype"]["name"] == "Bug"

    def test_custom_issue_type(self):
        issue = build_jira_issue(make_alert(), project_key=_PROJECT, issue_type="Task")
        assert issue["fields"]["issuetype"]["name"] == "Task"

    def test_opencdr_label_present(self):
        issue = build_jira_issue(make_alert(), project_key=_PROJECT)
        assert "opencdr" in issue["fields"]["labels"]

    def test_description_is_adf_doc(self):
        issue = build_jira_issue(make_alert(), project_key=_PROJECT)
        desc = issue["fields"]["description"]
        assert desc["type"] == "doc"
        assert desc["version"] == 1
        assert isinstance(desc["content"], list)

    def test_description_contains_playbook(self):
        issue = build_jira_issue(make_alert(playbook="Isolate the instance."), project_key=_PROJECT)
        desc_text = json.dumps(issue["fields"]["description"])
        assert "Isolate the instance." in desc_text

    def test_description_contains_user_and_ip(self):
        desc_text = json.dumps(build_jira_issue(make_alert(), project_key=_PROJECT)["fields"]["description"])
        assert "alice" in desc_text
        assert "1.2.3.4" in desc_text

    def test_alert_id_in_description_when_present(self):
        issue = build_jira_issue(make_alert(alert_id="alert-xyz"), project_key=_PROJECT)
        desc_text = json.dumps(issue["fields"]["description"])
        assert "alert-xyz" in desc_text

    def test_no_alert_id_paragraph_when_absent(self):
        alert = make_alert()
        alert.pop("alert_id", None)
        issue = build_jira_issue(alert, project_key=_PROJECT)
        desc_text = json.dumps(issue["fields"]["description"])
        assert "Alert ID" not in desc_text

    def test_falls_back_to_top_level_when_no_primary_signal(self):
        alert = {
            "severity": "HIGH",
            "rule_id": "rule-001",
            "playbook": "Do something.",
        }
        issue = build_jira_issue(alert, project_key=_PROJECT)
        assert issue["fields"]["summary"] != ""


# ---------------------------------------------------------------------------
# _route_channels — Jira auto fan-out
# ---------------------------------------------------------------------------


class TestRouteChannelsJira:
    def test_jira_included_when_all_fields_present(self):
        channels = _route_channels(make_alert(), make_settings_jira())
        assert "jira" in channels

    def test_jira_excluded_when_disabled(self):
        channels = _route_channels(make_alert(), make_settings_jira(enabled=False))
        assert "jira" not in channels

    def test_jira_excluded_when_base_url_missing(self):
        channels = _route_channels(make_alert(), make_settings_jira(base_url=""))
        assert "jira" not in channels

    def test_jira_excluded_when_project_key_missing(self):
        channels = _route_channels(make_alert(), make_settings_jira(project_key=""))
        assert "jira" not in channels

    def test_jira_excluded_when_user_email_missing(self):
        channels = _route_channels(make_alert(), make_settings_jira(user_email=""))
        assert "jira" not in channels

    def test_jira_excluded_when_api_token_missing(self):
        channels = _route_channels(make_alert(), make_settings_jira(api_token=""))
        assert "jira" not in channels

    def test_jira_honoured_in_explicit_routing(self):
        settings = make_settings_jira()
        settings["routing"] = {"HIGH": "jira"}
        channels = _route_channels(make_alert(severity="HIGH"), settings)
        assert channels == ["jira"]

    def test_jira_honoured_in_list_routing(self):
        settings = make_settings_jira()
        settings["routing"] = {"HIGH": ["jira", "securityhub"]}
        channels = _route_channels(make_alert(severity="HIGH"), settings)
        assert "jira" in channels


# ---------------------------------------------------------------------------
# lambda_handler — Jira channel
# ---------------------------------------------------------------------------


class TestLambdaHandlerJira:
    def _mock_post(self, status=201, key="SEC-42"):
        return patch(
            "src.handlers.notifier._post_json_basic_auth",
            return_value=(status, json.dumps({"key": key})),
        )

    def test_successful_create_counted(self):
        with (
            patch("src.handlers.notifier.load_global_settings", return_value=make_settings_jira()),
            patch("src.handlers.notifier.AwsHandler"),
            self._mock_post(),
        ):
            result = lambda_handler(make_sqs_event(make_alert()), make_context())

        assert result["sent"] == 1
        assert result["failed"] == 0

    def test_correct_jira_url_used(self):
        calls = []

        def capture(url, payload, *, email, token, **kw):
            calls.append(url)
            return 201, json.dumps({"key": "SEC-1"})

        with (
            patch("src.handlers.notifier.load_global_settings", return_value=make_settings_jira()),
            patch("src.handlers.notifier.AwsHandler"),
            patch("src.handlers.notifier._post_json_basic_auth", side_effect=capture),
        ):
            lambda_handler(make_sqs_event(make_alert()), make_context())

        assert calls[0] == f"{_JIRA_BASE}/rest/api/3/issue"

    def test_trailing_slash_stripped_from_base_url(self):
        calls = []

        def capture(url, payload, *, email, token, **kw):
            calls.append(url)
            return 201, json.dumps({"key": "SEC-1"})

        settings = make_settings_jira(base_url=f"{_JIRA_BASE}/")
        with (
            patch("src.handlers.notifier.load_global_settings", return_value=settings),
            patch("src.handlers.notifier.AwsHandler"),
            patch("src.handlers.notifier._post_json_basic_auth", side_effect=capture),
        ):
            lambda_handler(make_sqs_event(make_alert()), make_context())

        assert not calls[0].endswith("//rest/api/3/issue")

    def test_auth_credentials_passed(self):
        calls = []

        def capture(url, payload, *, email, token, **kw):
            calls.append({"email": email, "token": token})
            return 201, json.dumps({"key": "SEC-1"})

        with (
            patch("src.handlers.notifier.load_global_settings", return_value=make_settings_jira()),
            patch("src.handlers.notifier.AwsHandler"),
            patch("src.handlers.notifier._post_json_basic_auth", side_effect=capture),
        ):
            lambda_handler(make_sqs_event(make_alert()), make_context())

        assert calls[0]["email"] == _EMAIL
        assert calls[0]["token"] == _TOKEN

    def test_custom_issue_type_used(self):
        payloads = []

        def capture(url, payload, *, email, token, **kw):
            payloads.append(payload)
            return 201, json.dumps({"key": "SEC-1"})

        settings = make_settings_jira()
        settings["channels"]["jira"]["issue_type"] = "Task"

        with (
            patch("src.handlers.notifier.load_global_settings", return_value=settings),
            patch("src.handlers.notifier.AwsHandler"),
            patch("src.handlers.notifier._post_json_basic_auth", side_effect=capture),
        ):
            lambda_handler(make_sqs_event(make_alert()), make_context())

        assert payloads[0]["fields"]["issuetype"]["name"] == "Task"

    def test_http_error_counted_as_failed(self):
        with (
            patch("src.handlers.notifier.load_global_settings", return_value=make_settings_jira()),
            patch("src.handlers.notifier.AwsHandler"),
            self._mock_post(status=403),
        ):
            result = lambda_handler(make_sqs_event(make_alert()), make_context())

        assert result["failed"] == 1
        assert result["sent"] == 0

    def test_exception_counted_as_failed(self):
        with (
            patch("src.handlers.notifier.load_global_settings", return_value=make_settings_jira()),
            patch("src.handlers.notifier.AwsHandler"),
            patch("src.handlers.notifier._post_json_basic_auth", side_effect=Exception("timeout")),
        ):
            result = lambda_handler(make_sqs_event(make_alert()), make_context())

        assert result["failed"] == 1

    def test_missing_api_token_counted_as_failed(self):
        settings = make_settings_jira(api_token="")
        settings["routing"] = {"HIGH": "jira"}  # force the channel despite missing config
        with (
            patch("src.handlers.notifier.load_global_settings", return_value=settings),
            patch("src.handlers.notifier.AwsHandler"),
        ):
            result = lambda_handler(make_sqs_event(make_alert()), make_context())

        assert result["failed"] == 1

    def test_jira_disabled_does_not_post(self):
        with (
            patch("src.handlers.notifier.load_global_settings", return_value=make_settings_jira(enabled=False)),
            patch("src.handlers.notifier.AwsHandler"),
            patch("src.handlers.notifier._post_json_basic_auth") as mock_post,
        ):
            result = lambda_handler(make_sqs_event(make_alert()), make_context())

        mock_post.assert_not_called()
        assert result["sent"] == 0

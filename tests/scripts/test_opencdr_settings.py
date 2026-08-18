"""Tests for `opencdr.py settings set` — Security Hub and Jira integrations."""
from __future__ import annotations

import argparse
import sys
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pytest

# Make the scripts/ directory importable without installing the package.
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

import opencdr  # noqa: E402  (after sys.path manipulation)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_args(**kwargs) -> argparse.Namespace:
    """Build a Namespace that mirrors what argparse produces for `settings set`."""
    defaults = {
        "setting_id": "global",
        "file": None,
        "slack_webhook": None,
        "discord_webhook": None,
        "email_topic_arn": None,
        "enable_securityhub": False,
        "jira_url": None,
        "jira_project": None,
        "jira_email": None,
        "jira_token": None,
        "jira_issue_type": "",
        "webhook_url": None,
        "webhook_name": "",
        "webhook_headers": None,
        "guardduty_notify_default": None,
        "guardduty_notify_severity": None,
        "guardduty_notify_service": None,
        "guardduty_notify_severity_service": None,
    }
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


def _run_settings_set(
    args: argparse.Namespace,
    *,
    api_response: tuple = (200, {"ok": True}),
    existing_settings: dict | None = None,
):
    """
    Run cmd_settings_set with mocked API calls.

    GET /settings/... returns existing_settings (HTTP 200) when provided, otherwise 404.
    PUT /settings/... returns api_response.

    Returns (stdout, put_calls) where put_calls is a list of (method, path, payload)
    for every PUT call made — existing tests can keep using calls[0].
    """
    put_calls = []

    def fake_request(method, path, url, key, **kwargs):
        if method == "GET":
            if existing_settings is not None:
                return 200, existing_settings
            return 404, {}
        put_calls.append((method, path, kwargs.get("json")))
        return api_response

    with (
        patch.object(opencdr, "_load_config", return_value={}),
        patch.object(opencdr, "_require_api", return_value=("https://api.example.com", "test-key")),
        patch.object(opencdr, "_request", side_effect=fake_request),
        patch("sys.stdout", new_callable=StringIO) as mock_out,
    ):
        opencdr.cmd_settings_set(args)

    return mock_out.getvalue(), put_calls


# ---------------------------------------------------------------------------
# --enable-securityhub flag
# ---------------------------------------------------------------------------


class TestSettingsSetSecurityHub:
    def test_enable_securityhub_builds_correct_payload(self):
        _, calls = _run_settings_set(_make_args(enable_securityhub=True))
        assert len(calls) == 1
        payload = calls[0][2]
        assert payload["channels"] == {"securityhub": {"enabled": True}}

    def test_enable_securityhub_calls_put_on_correct_path(self):
        _, calls = _run_settings_set(_make_args(enable_securityhub=True))
        method, path, _ = calls[0]
        assert method == "PUT"
        assert path == "/settings/global"

    def test_enable_securityhub_uses_setting_id(self):
        _, calls = _run_settings_set(_make_args(enable_securityhub=True, setting_id="custom"))
        _, path, _ = calls[0]
        assert path == "/settings/custom"

    def test_enable_securityhub_prints_success(self, capsys):
        def fake_req(method, path, url, key, **kwargs):
            if method == "GET":
                return 404, {}
            return 200, {"ok": True}

        with (
            patch.object(opencdr, "_load_config", return_value={}),
            patch.object(opencdr, "_require_api", return_value=("https://api.example.com", "key")),
            patch.object(opencdr, "_request", side_effect=fake_req),
        ):
            opencdr.cmd_settings_set(_make_args(enable_securityhub=True))
        captured = capsys.readouterr()
        assert "saved" in captured.out.lower()

    def test_enable_securityhub_combined_with_slack(self):
        args = _make_args(enable_securityhub=True, slack_webhook="https://hooks.slack.com/x")
        _, calls = _run_settings_set(args)
        payload = calls[0][2]
        assert "securityhub" in payload["channels"]
        assert "slack" in payload["channels"]
        assert payload["channels"]["securityhub"] == {"enabled": True}
        assert payload["channels"]["slack"]["webhook_url"] == "https://hooks.slack.com/x"

    def test_enable_securityhub_combined_with_discord(self):
        args = _make_args(enable_securityhub=True, discord_webhook="https://discord.com/api/webhooks/x")
        _, calls = _run_settings_set(args)
        payload = calls[0][2]
        assert "securityhub" in payload["channels"]
        assert "discord" in payload["channels"]

    def test_enable_securityhub_combined_with_email(self):
        args = _make_args(enable_securityhub=True, email_topic_arn="arn:aws:sns:us-east-1:123:topic")
        _, calls = _run_settings_set(args)
        payload = calls[0][2]
        assert "securityhub" in payload["channels"]
        assert "email" in payload["channels"]

    def test_securityhub_disabled_by_default(self):
        # --slack-webhook only → securityhub should not appear
        _, calls = _run_settings_set(_make_args(slack_webhook="https://hooks.slack.com/x"))
        payload = calls[0][2]
        assert "securityhub" not in payload.get("channels", {})


# ---------------------------------------------------------------------------
# No-argument error path includes --enable-securityhub hint
# ---------------------------------------------------------------------------


class TestSettingsSetNoArgs:
    def test_exits_when_no_option_provided(self):
        with (
            patch.object(opencdr, "_load_config", return_value={}),
            patch.object(opencdr, "_require_api", return_value=("https://api.example.com", "key")),
            pytest.raises(SystemExit) as exc_info,
        ):
            opencdr.cmd_settings_set(_make_args())
        assert exc_info.value.code == 1

    def test_error_message_mentions_securityhub(self, capsys):
        with (
            patch.object(opencdr, "_load_config", return_value={}),
            patch.object(opencdr, "_require_api", return_value=("https://api.example.com", "key")),
            pytest.raises(SystemExit),
        ):
            opencdr.cmd_settings_set(_make_args())
        captured = capsys.readouterr()
        assert "securityhub" in captured.out.lower()


# ---------------------------------------------------------------------------
# Argparser registers --enable-securityhub
# ---------------------------------------------------------------------------


class TestArgparser:
    def _build_parser(self) -> argparse.ArgumentParser:
        # Reconstruct the parser by calling the module's main() argument setup.
        # We do this by parsing a known set of args and checking the resulting namespace.
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="command")
        sg_p = sub.add_parser("settings")
        sg_sub = sg_p.add_subparsers(dest="subcommand")
        sgs = sg_sub.add_parser("set")
        sgs.add_argument("setting_id", nargs="?", default="global")
        sgs.add_argument("--file")
        sgs.add_argument("--slack-webhook", dest="slack_webhook")
        sgs.add_argument("--discord-webhook", dest="discord_webhook")
        sgs.add_argument("--email-topic-arn", dest="email_topic_arn")
        sgs.add_argument("--enable-securityhub", dest="enable_securityhub", action="store_true", default=False)
        return parser

    def test_enable_securityhub_flag_defaults_to_false(self):
        parser = self._build_parser()
        args = parser.parse_args(["settings", "set"])
        assert args.enable_securityhub is False

    def test_enable_securityhub_flag_sets_true(self):
        parser = self._build_parser()
        args = parser.parse_args(["settings", "set", "--enable-securityhub"])
        assert args.enable_securityhub is True

    def test_real_parser_has_enable_securityhub(self):
        """Smoke-test against the real parser defined in main()."""
        # Capture the parser by running through main's setup without executing
        captured_parser: list[argparse.ArgumentParser] = []

        original_parse = argparse.ArgumentParser.parse_args

        def _capture(self, args=None, namespace=None):
            captured_parser.append(self)
            raise SystemExit(0)

        with (
            patch.object(argparse.ArgumentParser, "parse_args", _capture),
            pytest.raises(SystemExit),
        ):
            opencdr.main()

        parser = captured_parser[0]
        # Walk subparsers to find the "settings set" parser and check it has --enable-securityhub
        found = False
        for action in parser._subparsers._group_actions:
            for name, subparser in action.choices.items():
                if name != "settings":
                    continue
                for sub_action in subparser._subparsers._group_actions:
                    for sub_name, sub_sub in sub_action.choices.items():
                        if sub_name != "set":
                            continue
                        option_strings = [
                            s
                            for a in sub_sub._actions
                            for s in a.option_strings
                        ]
                        found = "--enable-securityhub" in option_strings
        assert found, "--enable-securityhub not registered in the real parser"


# ---------------------------------------------------------------------------
# settings set — Jira
# ---------------------------------------------------------------------------

_JIRA_URL = "https://yourco.atlassian.net"
_JIRA_PROJECT = "SEC"
_JIRA_EMAIL = "soc@yourco.com"
_JIRA_TOKEN = "api-token-abc"


def _jira_args(**overrides):
    defaults = dict(
        jira_url=_JIRA_URL,
        jira_project=_JIRA_PROJECT,
        jira_email=_JIRA_EMAIL,
        jira_token=_JIRA_TOKEN,
        jira_issue_type="",
    )
    defaults.update(overrides)
    return _make_args(**defaults)


class TestSettingsSetJira:
    def test_all_fields_build_correct_payload(self):
        _, calls = _run_settings_set(_jira_args())
        payload = calls[0][2]
        jira = payload["channels"]["jira"]
        assert jira["enabled"] is True
        assert jira["base_url"] == _JIRA_URL
        assert jira["project_key"] == _JIRA_PROJECT
        assert jira["user_email"] == _JIRA_EMAIL
        assert jira["api_token"] == _JIRA_TOKEN

    def test_calls_put_on_correct_path(self):
        _, calls = _run_settings_set(_jira_args())
        method, path, _ = calls[0]
        assert method == "PUT"
        assert path == "/settings/global"

    def test_custom_setting_id(self):
        _, calls = _run_settings_set(_jira_args(setting_id="staging"))
        _, path, _ = calls[0]
        assert path == "/settings/staging"

    def test_optional_issue_type_included_when_set(self):
        _, calls = _run_settings_set(_jira_args(jira_issue_type="Task"))
        jira = calls[0][2]["channels"]["jira"]
        assert jira.get("issue_type") == "Task"

    def test_issue_type_omitted_when_empty(self):
        _, calls = _run_settings_set(_jira_args(jira_issue_type=""))
        jira = calls[0][2]["channels"]["jira"]
        assert "issue_type" not in jira

    def test_jira_combined_with_slack(self):
        args = _jira_args(slack_webhook="https://hooks.slack.com/x")
        _, calls = _run_settings_set(args)
        payload = calls[0][2]
        assert "jira" in payload["channels"]
        assert "slack" in payload["channels"]

    def test_jira_combined_with_securityhub(self):
        args = _jira_args(enable_securityhub=True)
        _, calls = _run_settings_set(args)
        payload = calls[0][2]
        assert "jira" in payload["channels"]
        assert "securityhub" in payload["channels"]

    def test_no_jira_in_payload_when_no_jira_args(self):
        _, calls = _run_settings_set(_make_args(slack_webhook="https://hooks.slack.com/x"))
        payload = calls[0][2]
        assert "jira" not in payload.get("channels", {})

    def test_exits_when_only_partial_jira_args_provided(self):
        with (
            patch.object(opencdr, "_load_config", return_value={}),
            patch.object(opencdr, "_require_api", return_value=("https://api.example.com", "key")),
            pytest.raises(SystemExit) as exc_info,
        ):
            opencdr.cmd_settings_set(_make_args(jira_url=_JIRA_URL))  # missing project/email/token
        assert exc_info.value.code == 1

    def test_partial_jira_error_message(self, capsys):
        with (
            patch.object(opencdr, "_load_config", return_value={}),
            patch.object(opencdr, "_require_api", return_value=("https://api.example.com", "key")),
            patch.object(opencdr, "_request", return_value=(404, {})),
            pytest.raises(SystemExit),
        ):
            opencdr.cmd_settings_set(_make_args(jira_url=_JIRA_URL))
        captured = capsys.readouterr()
        assert "jira" in captured.out.lower()


class TestArgparserJira:
    def _get_settings_set_options(self) -> list[str]:
        captured_parser: list[argparse.ArgumentParser] = []

        def _capture(self, args=None, namespace=None):
            captured_parser.append(self)
            raise SystemExit(0)

        with (
            patch.object(argparse.ArgumentParser, "parse_args", _capture),
            pytest.raises(SystemExit),
        ):
            opencdr.main()

        parser = captured_parser[0]
        for action in parser._subparsers._group_actions:
            for name, subparser in action.choices.items():
                if name != "settings":
                    continue
                for sub_action in subparser._subparsers._group_actions:
                    for sub_name, sub_sub in sub_action.choices.items():
                        if sub_name == "set":
                            return [s for a in sub_sub._actions for s in a.option_strings]
        return []

    def test_jira_url_registered(self):
        assert "--jira-url" in self._get_settings_set_options()

    def test_jira_project_registered(self):
        assert "--jira-project" in self._get_settings_set_options()

    def test_jira_email_registered(self):
        assert "--jira-email" in self._get_settings_set_options()

    def test_jira_token_registered(self):
        assert "--jira-token" in self._get_settings_set_options()

    def test_jira_issue_type_registered(self):
        assert "--jira-issue-type" in self._get_settings_set_options()


# ---------------------------------------------------------------------------
# settings set — custom webhook
# ---------------------------------------------------------------------------


class TestSettingsSetWebhook:
    def test_webhook_url_builds_correct_payload(self):
        _, calls = _run_settings_set(_make_args(webhook_url="https://events.pagerduty.com/v2/enqueue"))
        webhook = calls[0][2]["channels"]["webhook"]
        assert webhook["enabled"] is True
        assert len(webhook["targets"]) == 1
        assert webhook["targets"][0]["url"] == "https://events.pagerduty.com/v2/enqueue"

    def test_default_webhook_name_is_default(self):
        _, calls = _run_settings_set(_make_args(webhook_url="https://example.com/hook"))
        target = calls[0][2]["channels"]["webhook"]["targets"][0]
        assert target["name"] == "default"

    def test_custom_webhook_name_used(self):
        _, calls = _run_settings_set(_make_args(
            webhook_url="https://example.com/hook",
            webhook_name="pagerduty",
        ))
        target = calls[0][2]["channels"]["webhook"]["targets"][0]
        assert target["name"] == "pagerduty"

    def test_webhook_header_parsed(self):
        _, calls = _run_settings_set(_make_args(
            webhook_url="https://example.com/hook",
            webhook_headers=["Authorization=GenieKey abc123"],
        ))
        target = calls[0][2]["channels"]["webhook"]["targets"][0]
        assert target["headers"]["Authorization"] == "GenieKey abc123"

    def test_multiple_webhook_headers_parsed(self):
        _, calls = _run_settings_set(_make_args(
            webhook_url="https://example.com/hook",
            webhook_headers=["Authorization=Bearer tok", "X-Custom=val"],
        ))
        headers = calls[0][2]["channels"]["webhook"]["targets"][0]["headers"]
        assert headers["Authorization"] == "Bearer tok"
        assert headers["X-Custom"] == "val"

    def test_header_value_with_equals_sign(self):
        _, calls = _run_settings_set(_make_args(
            webhook_url="https://example.com/hook",
            webhook_headers=["Authorization=Bearer tok=padded"],
        ))
        headers = calls[0][2]["channels"]["webhook"]["targets"][0]["headers"]
        assert headers["Authorization"] == "Bearer tok=padded"

    def test_no_webhook_in_payload_when_url_not_set(self):
        _, calls = _run_settings_set(_make_args(slack_webhook="https://hooks.slack.com/x"))
        assert "webhook" not in calls[0][2].get("channels", {})

    def test_webhook_combined_with_slack(self):
        _, calls = _run_settings_set(_make_args(
            webhook_url="https://example.com/hook",
            slack_webhook="https://hooks.slack.com/x",
        ))
        payload = calls[0][2]
        assert "webhook" in payload["channels"]
        assert "slack" in payload["channels"]

    def test_invalid_header_format_exits(self, capsys):
        with (
            patch.object(opencdr, "_load_config", return_value={}),
            patch.object(opencdr, "_require_api", return_value=("https://api.example.com", "key")),
            pytest.raises(SystemExit) as exc_info,
        ):
            opencdr.cmd_settings_set(_make_args(
                webhook_url="https://example.com/hook",
                webhook_headers=["INVALID_NO_EQUALS"],
            ))
        assert exc_info.value.code == 1

    def test_empty_headers_list_produces_empty_dict(self):
        _, calls = _run_settings_set(_make_args(
            webhook_url="https://example.com/hook",
            webhook_headers=[],
        ))
        target = calls[0][2]["channels"]["webhook"]["targets"][0]
        assert target["headers"] == {}


class TestArgparserWebhook:
    def _get_settings_set_options(self) -> list[str]:
        captured_parser: list[argparse.ArgumentParser] = []

        def _capture(self, args=None, namespace=None):
            captured_parser.append(self)
            raise SystemExit(0)

        with (
            patch.object(argparse.ArgumentParser, "parse_args", _capture),
            pytest.raises(SystemExit),
        ):
            opencdr.main()

        parser = captured_parser[0]
        for action in parser._subparsers._group_actions:
            for name, subparser in action.choices.items():
                if name != "settings":
                    continue
                for sub_action in subparser._subparsers._group_actions:
                    for sub_name, sub_sub in sub_action.choices.items():
                        if sub_name == "set":
                            return [s for a in sub_sub._actions for s in a.option_strings]
        return []

    def test_webhook_url_registered(self):
        assert "--webhook-url" in self._get_settings_set_options()

    def test_webhook_name_registered(self):
        assert "--webhook-name" in self._get_settings_set_options()

    def test_webhook_header_registered(self):
        assert "--webhook-header" in self._get_settings_set_options()


# ---------------------------------------------------------------------------
# settings set — guardduty_notify
# ---------------------------------------------------------------------------


class TestSettingsSetGuardDutyNotify:
    def test_default_builds_correct_payload(self):
        _, calls = _run_settings_set(_make_args(guardduty_notify_default="true"))
        assert calls[0][2]["guardduty_notify"] == {"default": True}

    def test_default_false_builds_correct_payload(self):
        _, calls = _run_settings_set(_make_args(guardduty_notify_default="false"))
        assert calls[0][2]["guardduty_notify"] == {"default": False}

    def test_invalid_default_value_exits(self, capsys):
        with (
            patch.object(opencdr, "_load_config", return_value={}),
            patch.object(opencdr, "_require_api", return_value=("https://api.example.com", "key")),
            pytest.raises(SystemExit) as exc_info,
        ):
            opencdr.cmd_settings_set(_make_args(guardduty_notify_default="maybe"))
        assert exc_info.value.code == 1
        assert "guardduty-notify-default" in capsys.readouterr().out

    def test_severity_flag_builds_by_severity(self):
        _, calls = _run_settings_set(_make_args(guardduty_notify_severity=["CRITICAL=true"]))
        assert calls[0][2]["guardduty_notify"] == {"by_severity": {"CRITICAL": True}}

    def test_multiple_severity_flags(self):
        _, calls = _run_settings_set(
            _make_args(guardduty_notify_severity=["CRITICAL=true", "LOW=false"])
        )
        assert calls[0][2]["guardduty_notify"]["by_severity"] == {"CRITICAL": True, "LOW": False}

    def test_service_flag_builds_by_service(self):
        _, calls = _run_settings_set(_make_args(guardduty_notify_service=["IAMUser=true"]))
        assert calls[0][2]["guardduty_notify"] == {"by_service": {"IAMUser": True}}

    def test_severity_service_flag_builds_by_severity_and_service(self):
        _, calls = _run_settings_set(
            _make_args(guardduty_notify_severity_service=["HIGH:EC2=true"])
        )
        assert calls[0][2]["guardduty_notify"] == {"by_severity_and_service": {"HIGH:EC2": True}}

    def test_all_four_combined(self):
        _, calls = _run_settings_set(_make_args(
            guardduty_notify_default="false",
            guardduty_notify_severity=["CRITICAL=true"],
            guardduty_notify_service=["IAMUser=true"],
            guardduty_notify_severity_service=["HIGH:EC2=true"],
        ))
        gd = calls[0][2]["guardduty_notify"]
        assert gd == {
            "default": False,
            "by_severity": {"CRITICAL": True},
            "by_service": {"IAMUser": True},
            "by_severity_and_service": {"HIGH:EC2": True},
        }

    def test_invalid_pair_format_exits(self, capsys):
        with (
            patch.object(opencdr, "_load_config", return_value={}),
            patch.object(opencdr, "_require_api", return_value=("https://api.example.com", "key")),
            pytest.raises(SystemExit) as exc_info,
        ):
            opencdr.cmd_settings_set(_make_args(guardduty_notify_severity=["CRITICAL_NO_EQUALS"]))
        assert exc_info.value.code == 1
        assert "guardduty-notify-severity" in capsys.readouterr().out

    def test_no_guardduty_notify_in_payload_when_not_set(self):
        _, calls = _run_settings_set(_make_args(slack_webhook="https://hooks.slack.com/x"))
        assert "guardduty_notify" not in calls[0][2]

    def test_guardduty_notify_combined_with_channel_flag(self):
        _, calls = _run_settings_set(_make_args(
            slack_webhook="https://hooks.slack.com/x",
            guardduty_notify_default="true",
        ))
        payload = calls[0][2]
        assert payload["channels"]["slack"]["enabled"] is True
        assert payload["guardduty_notify"] == {"default": True}

    def test_existing_guardduty_notify_merged_not_replaced(self):
        existing = {
            "notifications_enabled": True,
            "channels": {},
            "guardduty_notify": {"default": False, "by_severity": {"LOW": False}},
        }
        _, calls = _run_settings_set(
            _make_args(guardduty_notify_severity=["CRITICAL=true"]),
            existing_settings=existing,
        )
        gd = calls[0][2]["guardduty_notify"]
        assert gd["default"] is False
        assert gd["by_severity"] == {"LOW": False, "CRITICAL": True}

    def test_guardduty_notify_only_update_does_not_touch_channels(self):
        existing = {
            "notifications_enabled": True,
            "channels": {"slack": {"enabled": True, "webhook_url": "https://hooks.slack.com/x"}},
        }
        _, calls = _run_settings_set(
            _make_args(guardduty_notify_default="true"),
            existing_settings=existing,
        )
        assert calls[0][2]["channels"] == existing["channels"]


class TestArgparserGuardDutyNotify:
    def _get_settings_set_options(self) -> list[str]:
        captured_parser: list[argparse.ArgumentParser] = []

        def _capture(self, args=None, namespace=None):
            captured_parser.append(self)
            raise SystemExit(0)

        with (
            patch.object(argparse.ArgumentParser, "parse_args", _capture),
            pytest.raises(SystemExit),
        ):
            opencdr.main()

        parser = captured_parser[0]
        for action in parser._subparsers._group_actions:
            for name, subparser in action.choices.items():
                if name != "settings":
                    continue
                for sub_action in subparser._subparsers._group_actions:
                    for sub_name, sub_sub in sub_action.choices.items():
                        if sub_name == "set":
                            return [s for a in sub_sub._actions for s in a.option_strings]
        return []

    def test_guardduty_notify_default_registered(self):
        assert "--guardduty-notify-default" in self._get_settings_set_options()

    def test_guardduty_notify_severity_registered(self):
        assert "--guardduty-notify-severity" in self._get_settings_set_options()

    def test_guardduty_notify_service_registered(self):
        assert "--guardduty-notify-service" in self._get_settings_set_options()

    def test_guardduty_notify_severity_service_registered(self):
        assert "--guardduty-notify-severity-service" in self._get_settings_set_options()


# ---------------------------------------------------------------------------
# _merge_guardduty_notify — unit tests
# ---------------------------------------------------------------------------


class TestMergeGuardDutyNotify:
    def test_default_added_to_empty(self):
        merged = opencdr._merge_guardduty_notify({}, {"default": True})
        assert merged == {"default": True}

    def test_default_replaces_existing(self):
        merged = opencdr._merge_guardduty_notify({"default": False}, {"default": True})
        assert merged["default"] is True

    def test_by_severity_merges_key_by_key(self):
        existing = {"by_severity": {"LOW": False}}
        merged = opencdr._merge_guardduty_notify(existing, {"by_severity": {"CRITICAL": True}})
        assert merged["by_severity"] == {"LOW": False, "CRITICAL": True}

    def test_by_severity_key_overridden_not_duplicated(self):
        existing = {"by_severity": {"CRITICAL": False}}
        merged = opencdr._merge_guardduty_notify(existing, {"by_severity": {"CRITICAL": True}})
        assert merged["by_severity"] == {"CRITICAL": True}

    def test_untouched_sub_keys_preserved(self):
        existing = {
            "default": False,
            "by_severity": {"LOW": False},
            "by_service": {"IAMUser": True},
        }
        merged = opencdr._merge_guardduty_notify(existing, {"by_severity_and_service": {"HIGH:EC2": True}})
        assert merged["default"] is False
        assert merged["by_severity"] == {"LOW": False}
        assert merged["by_service"] == {"IAMUser": True}
        assert merged["by_severity_and_service"] == {"HIGH:EC2": True}


# ---------------------------------------------------------------------------
# _merge_channels — unit tests
# ---------------------------------------------------------------------------


class TestMergeChannels:
    def test_new_channel_added_to_empty(self):
        merged = opencdr._merge_channels({}, {"slack": {"enabled": True, "webhook_url": "https://x"}})
        assert merged["slack"]["enabled"] is True

    def test_existing_channel_not_touched(self):
        existing = {"slack": {"enabled": True, "webhook_url": "https://old"}}
        merged = opencdr._merge_channels(existing, {"discord": {"enabled": True, "webhook_url": "https://new"}})
        assert merged["slack"]["webhook_url"] == "https://old"
        assert "discord" in merged

    def test_channel_update_replaces_only_that_channel(self):
        existing = {
            "slack": {"enabled": True, "webhook_url": "https://old"},
            "email": {"enabled": True, "topic_arn": "arn:aws:sns:us-east-1:123:topic"},
        }
        merged = opencdr._merge_channels(existing, {"slack": {"enabled": True, "webhook_url": "https://new"}})
        assert merged["slack"]["webhook_url"] == "https://new"
        assert merged["email"]["topic_arn"] == "arn:aws:sns:us-east-1:123:topic"

    def test_webhook_target_appended(self):
        existing = {
            "webhook": {
                "enabled": True,
                "targets": [{"name": "pagerduty", "url": "https://pd.example.com", "headers": {}}],
            }
        }
        new = {
            "webhook": {
                "enabled": True,
                "targets": [{"name": "opsgenie", "url": "https://og.example.com", "headers": {}}],
            }
        }
        merged = opencdr._merge_channels(existing, new)
        names = {t["name"] for t in merged["webhook"]["targets"]}
        assert names == {"pagerduty", "opsgenie"}

    def test_webhook_target_same_name_replaces(self):
        existing = {
            "webhook": {
                "enabled": True,
                "targets": [{"name": "pd", "url": "https://old.example.com", "headers": {}}],
            }
        }
        new = {
            "webhook": {
                "enabled": True,
                "targets": [{"name": "pd", "url": "https://new.example.com", "headers": {}}],
            }
        }
        merged = opencdr._merge_channels(existing, new)
        assert len(merged["webhook"]["targets"]) == 1
        assert merged["webhook"]["targets"][0]["url"] == "https://new.example.com"

    def test_webhook_first_target_no_existing(self):
        merged = opencdr._merge_channels(
            {},
            {"webhook": {"enabled": True, "targets": [{"name": "pd", "url": "https://pd.example.com", "headers": {}}]}},
        )
        assert len(merged["webhook"]["targets"]) == 1


# ---------------------------------------------------------------------------
# cmd_settings_set — merge integration
# ---------------------------------------------------------------------------


class TestSettingsSetMerge:
    def test_does_not_overwrite_existing_channel(self):
        existing = {
            "channels": {"slack": {"enabled": True, "webhook_url": "https://hooks.slack.com/existing"}},
            "notifications_enabled": True,
        }
        _, calls = _run_settings_set(
            _make_args(discord_webhook="https://discord.com/api/webhooks/new"),
            existing_settings=existing,
        )
        channels = calls[0][2]["channels"]
        assert channels["slack"]["webhook_url"] == "https://hooks.slack.com/existing"
        assert channels["discord"]["webhook_url"] == "https://discord.com/api/webhooks/new"

    def test_updates_channel_without_touching_others(self):
        existing = {
            "channels": {
                "slack": {"enabled": True, "webhook_url": "https://hooks.slack.com/old"},
                "email": {"enabled": True, "topic_arn": "arn:aws:sns:us-east-1:123:topic"},
            },
            "notifications_enabled": True,
        }
        _, calls = _run_settings_set(
            _make_args(slack_webhook="https://hooks.slack.com/new"),
            existing_settings=existing,
        )
        channels = calls[0][2]["channels"]
        assert channels["slack"]["webhook_url"] == "https://hooks.slack.com/new"
        assert channels["email"]["topic_arn"] == "arn:aws:sns:us-east-1:123:topic"

    def test_webhook_target_appended_not_replaced(self):
        existing = {
            "channels": {
                "webhook": {
                    "enabled": True,
                    "targets": [{"name": "pagerduty", "url": "https://pd.example.com", "headers": {}}],
                }
            },
            "notifications_enabled": True,
        }
        _, calls = _run_settings_set(
            _make_args(webhook_url="https://og.example.com", webhook_name="opsgenie"),
            existing_settings=existing,
        )
        targets = calls[0][2]["channels"]["webhook"]["targets"]
        names = {t["name"] for t in targets}
        assert names == {"pagerduty", "opsgenie"}

    def test_webhook_target_same_name_replaced_not_duplicated(self):
        existing = {
            "channels": {
                "webhook": {
                    "enabled": True,
                    "targets": [{"name": "pd", "url": "https://old.example.com", "headers": {}}],
                }
            },
            "notifications_enabled": True,
        }
        _, calls = _run_settings_set(
            _make_args(webhook_url="https://new.example.com", webhook_name="pd"),
            existing_settings=existing,
        )
        targets = calls[0][2]["channels"]["webhook"]["targets"]
        assert len(targets) == 1
        assert targets[0]["url"] == "https://new.example.com"

    def test_preserves_top_level_fields_from_existing(self):
        existing = {
            "channels": {"slack": {"enabled": True, "webhook_url": "https://hooks.slack.com/x"}},
            "notifications_enabled": True,
            "routing": {"HIGH": "slack"},
        }
        _, calls = _run_settings_set(
            _make_args(enable_securityhub=True),
            existing_settings=existing,
        )
        payload = calls[0][2]
        assert payload.get("routing") == {"HIGH": "slack"}
        assert payload["notifications_enabled"] is True

    def test_no_existing_settings_creates_fresh(self):
        _, calls = _run_settings_set(_make_args(slack_webhook="https://hooks.slack.com/x"))
        channels = calls[0][2]["channels"]
        assert channels == {"slack": {"enabled": True, "webhook_url": "https://hooks.slack.com/x"}}

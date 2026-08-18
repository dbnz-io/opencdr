"""Tests for mcp_server/server.py -- the full OpenCDR management-plane
MCP tools (status, rules, lists, signals, logs, settings, ir-roles).

Doesn't re-test _merge_channels/_merge_guardduty_notify's own merge rules
(already covered exhaustively in tests/scripts/test_opencdr_settings.py) --
just that these tool wrappers call _resolve_api/_request/the merge helpers
correctly and turn HTTP status codes into the right tool-facing result or
error.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "mcp_server"))
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

import opencdr  # noqa: E402  (after sys.path manipulation)
import server  # noqa: E402


class TestResolveApi:
    def test_raises_when_url_and_key_missing(self, monkeypatch):
        monkeypatch.delenv("OPENCDR_API_URL", raising=False)
        monkeypatch.delenv("OPENCDR_API_KEY", raising=False)
        with patch.object(opencdr, "_load_config", return_value={}):
            with pytest.raises(server.OpenCDRConfigError) as exc_info:
                server._resolve_api()
        assert "OPENCDR_API_URL" in str(exc_info.value)
        assert "OPENCDR_API_KEY" in str(exc_info.value)

    def test_env_vars_take_precedence_over_config_file(self, monkeypatch):
        monkeypatch.setenv("OPENCDR_API_URL", "https://env.example.com")
        monkeypatch.setenv("OPENCDR_API_KEY", "env-key")
        with patch.object(
            opencdr, "_load_config", return_value={"url": "https://file.example.com", "key": "file-key"}
        ):
            url, key = server._resolve_api()
        assert url == "https://env.example.com"
        assert key == "env-key"

    def test_trailing_slash_stripped(self, monkeypatch):
        monkeypatch.setenv("OPENCDR_API_URL", "https://env.example.com/")
        monkeypatch.setenv("OPENCDR_API_KEY", "env-key")
        with patch.object(opencdr, "_load_config", return_value={}):
            url, _ = server._resolve_api()
        assert url == "https://env.example.com"


@pytest.fixture()
def api_env(monkeypatch):
    monkeypatch.setenv("OPENCDR_API_URL", "https://api.example.com")
    monkeypatch.setenv("OPENCDR_API_KEY", "test-key")
    with patch.object(opencdr, "_load_config", return_value={}):
        yield


class TestSettingsGet:
    def test_returns_body_on_success(self, api_env):
        with patch.object(
            opencdr, "_request", return_value=(200, {"setting_id": "global", "channels": {}})
        ) as mock_req:
            result = server.opencdr_settings_get("global")
        assert result == {"setting_id": "global", "channels": {}}
        mock_req.assert_called_once_with("GET", "/settings/global", "https://api.example.com", "test-key")

    def test_404_returns_found_false(self, api_env):
        with patch.object(opencdr, "_request", return_value=(404, {})):
            result = server.opencdr_settings_get("missing")
        assert result == {"found": False, "setting_id": "missing"}

    def test_error_status_raises(self, api_env):
        with patch.object(opencdr, "_request", return_value=(500, {"message": "boom"})):
            with pytest.raises(RuntimeError, match="boom"):
                server.opencdr_settings_get("global")

    def test_defaults_to_global(self, api_env):
        with patch.object(opencdr, "_request", return_value=(200, {})) as mock_req:
            server.opencdr_settings_get()
        assert mock_req.call_args.args[1] == "/settings/global"


class TestSettingsSet:
    def test_merges_new_channel_into_existing(self, api_env):
        def fake_request(method, path, url, key, **kwargs):
            if method == "GET":
                return 200, {
                    "setting_id": "global",
                    "notifications_enabled": True,
                    "channels": {"slack": {"enabled": True, "webhook_url": "https://old"}},
                }
            return 200, kwargs["json"]

        with patch.object(opencdr, "_request", side_effect=fake_request):
            result = server.opencdr_settings_set(
                channels={"discord": {"enabled": True, "webhook_url": "https://new"}}
            )

        assert result["channels"]["slack"]["webhook_url"] == "https://old"  # untouched
        assert result["channels"]["discord"]["webhook_url"] == "https://new"

    def test_no_channels_provided_leaves_existing_untouched(self, api_env):
        def fake_request(method, path, url, key, **kwargs):
            if method == "GET":
                return 200, {"channels": {"slack": {"enabled": True}}}
            return 200, kwargs["json"]

        with patch.object(opencdr, "_request", side_effect=fake_request):
            result = server.opencdr_settings_set(guardduty_notify={"default": True})

        assert result["channels"] == {"slack": {"enabled": True}}
        assert result["guardduty_notify"] == {"default": True}

    def test_guardduty_notify_merged_key_by_key(self, api_env):
        def fake_request(method, path, url, key, **kwargs):
            if method == "GET":
                return 200, {"channels": {}, "guardduty_notify": {"by_severity": {"HIGH": True}}}
            return 200, kwargs["json"]

        with patch.object(opencdr, "_request", side_effect=fake_request):
            result = server.opencdr_settings_set(guardduty_notify={"by_severity": {"CRITICAL": True}})

        assert result["guardduty_notify"]["by_severity"] == {"HIGH": True, "CRITICAL": True}

    def test_notifications_enabled_override(self, api_env):
        def fake_request(method, path, url, key, **kwargs):
            if method == "GET":
                return 200, {"channels": {}, "notifications_enabled": True}
            return 200, kwargs["json"]

        with patch.object(opencdr, "_request", side_effect=fake_request):
            result = server.opencdr_settings_set(notifications_enabled=False)

        assert result["notifications_enabled"] is False

    def test_error_status_raises(self, api_env):
        def fake_request(method, path, url, key, **kwargs):
            if method == "GET":
                return 200, {"channels": {}}
            return 500, {"message": "boom"}

        with patch.object(opencdr, "_request", side_effect=fake_request):
            with pytest.raises(RuntimeError, match="boom"):
                server.opencdr_settings_set(channels={"slack": {"enabled": True}})


class TestSettingsDelete:
    def test_success_returns_deleted_true(self, api_env):
        with patch.object(opencdr, "_request", return_value=(200, {"ok": True})) as mock_req:
            result = server.opencdr_settings_delete("global")
        assert result == {"deleted": True, "setting_id": "global"}
        mock_req.assert_called_once_with("DELETE", "/settings/global", "https://api.example.com", "test-key")

    def test_404_returns_found_false(self, api_env):
        with patch.object(opencdr, "_request", return_value=(404, {})):
            result = server.opencdr_settings_delete("missing")
        assert result == {"found": False, "setting_id": "missing"}

    def test_error_status_raises(self, api_env):
        with patch.object(opencdr, "_request", return_value=(500, {"message": "boom"})):
            with pytest.raises(RuntimeError, match="boom"):
                server.opencdr_settings_delete("global")


class TestStatus:
    def test_returns_body(self, api_env):
        with patch.object(opencdr, "_request", return_value=(200, {"status": "ok"})) as mock_req:
            result = server.opencdr_status()
        assert result == {"status": "ok"}
        mock_req.assert_called_once_with("GET", "/status", "https://api.example.com", "test-key")

    def test_error_status_raises(self, api_env):
        with patch.object(opencdr, "_request", return_value=(500, {"message": "boom"})):
            with pytest.raises(RuntimeError, match="boom"):
                server.opencdr_status()


class TestRulesList:
    def test_no_kind_omits_rule_kind_qs(self, api_env):
        with patch.object(opencdr, "_request", return_value=(200, {"items": []})) as mock_req:
            server.opencdr_rules_list()
        path = mock_req.call_args.args[1]
        assert "rule_kind" not in path
        assert "page_size=50" in path

    def test_kind_included_in_qs(self, api_env):
        with patch.object(opencdr, "_request", return_value=(200, {"items": []})) as mock_req:
            server.opencdr_rules_list(kind="correlation")
        assert "rule_kind=correlation" in mock_req.call_args.args[1]

    def test_next_token_included(self, api_env):
        with patch.object(opencdr, "_request", return_value=(200, {"items": []})) as mock_req:
            server.opencdr_rules_list(next_token="tok1")
        assert "next_token=tok1" in mock_req.call_args.args[1]

    def test_error_status_raises(self, api_env):
        with patch.object(opencdr, "_request", return_value=(500, {"message": "boom"})):
            with pytest.raises(RuntimeError, match="boom"):
                server.opencdr_rules_list()


class TestRulesGet:
    def test_returns_body_on_success(self, api_env):
        rule = {"rule_id": "001_console_login", "rule_kind": "signal"}
        with patch.object(opencdr, "_request", return_value=(200, rule)) as mock_req:
            result = server.opencdr_rules_get("001_console_login", "signal")
        assert result == rule
        mock_req.assert_called_once_with(
            "GET", "/rules/001_console_login?rule_kind=signal", "https://api.example.com", "test-key"
        )

    def test_404_returns_found_false(self, api_env):
        with patch.object(opencdr, "_request", return_value=(404, {})):
            result = server.opencdr_rules_get("missing", "signal")
        assert result == {"found": False, "rule_id": "missing"}

    def test_error_status_raises(self, api_env):
        with patch.object(opencdr, "_request", return_value=(500, {"message": "boom"})):
            with pytest.raises(RuntimeError, match="boom"):
                server.opencdr_rules_get("x", "signal")


class TestRulesUpsert:
    def test_puts_to_correct_path_with_body(self, api_env):
        rule = {"severity": "HIGH", "conditions": []}
        with patch.object(opencdr, "_request", return_value=(200, {**rule, "rule_id": "x"})) as mock_req:
            result = server.opencdr_rules_upsert("x", "signal", rule)
        mock_req.assert_called_once_with(
            "PUT", "/rules/x?rule_kind=signal", "https://api.example.com", "test-key", json=rule
        )
        assert result["rule_id"] == "x"

    def test_error_status_raises(self, api_env):
        with patch.object(opencdr, "_request", return_value=(400, {"message": "bad conditions"})):
            with pytest.raises(RuntimeError, match="bad conditions"):
                server.opencdr_rules_upsert("x", "signal", {})


class TestRulesDelete:
    def test_success_returns_deleted_true(self, api_env):
        with patch.object(opencdr, "_request", return_value=(200, {"ok": True})) as mock_req:
            result = server.opencdr_rules_delete("x", "correlation")
        assert result == {"deleted": True, "rule_id": "x"}
        mock_req.assert_called_once_with(
            "DELETE", "/rules/x?rule_kind=correlation", "https://api.example.com", "test-key"
        )

    def test_404_returns_found_false(self, api_env):
        with patch.object(opencdr, "_request", return_value=(404, {})):
            result = server.opencdr_rules_delete("missing", "signal")
        assert result == {"found": False, "rule_id": "missing"}


class TestListsList:
    def test_calls_correct_path(self, api_env):
        with patch.object(opencdr, "_request", return_value=(200, {"items": []})) as mock_req:
            server.opencdr_lists_list()
        mock_req.assert_called_once_with(
            "GET", "/rules?rule_kind=list&page_size=100", "https://api.example.com", "test-key"
        )


class TestListsShow:
    def test_returns_list_body(self, api_env):
        with patch.object(opencdr, "_request", return_value=(200, {"rule_id": "x", "values": ["a"]})):
            result = server.opencdr_lists_show("x")
        assert result == {"rule_id": "x", "values": ["a"]}

    def test_404_raises(self, api_env):
        with patch.object(opencdr, "_request", return_value=(404, {})):
            with pytest.raises(RuntimeError, match="not found"):
                server.opencdr_lists_show("missing")


class TestListsCreate:
    def test_builds_correct_payload(self, api_env):
        with patch.object(opencdr, "_request", return_value=(200, {"ok": True})) as mock_req:
            server.opencdr_lists_create("automation-identities", "CI identities", ["ci-deploy-role"])
        mock_req.assert_called_once_with(
            "PUT",
            "/rules/automation-identities?rule_kind=list",
            "https://api.example.com",
            "test-key",
            json={
                "rule_id": "automation-identities",
                "rule_kind": "list",
                "description": "CI identities",
                "values": ["ci-deploy-role"],
            },
        )

    def test_defaults_to_empty_description_and_values(self, api_env):
        with patch.object(opencdr, "_request", return_value=(200, {"ok": True})) as mock_req:
            server.opencdr_lists_create("x")
        assert mock_req.call_args.kwargs["json"]["description"] == ""
        assert mock_req.call_args.kwargs["json"]["values"] == []


class TestListsAdd:
    def test_new_value_appended_and_put(self, api_env):
        def fake_request(method, path, url, key, **kwargs):
            if method == "GET":
                return 200, {"rule_id": "x", "values": ["existing"]}
            return 200, kwargs["json"]

        with patch.object(opencdr, "_request", side_effect=fake_request):
            result = server.opencdr_lists_add("x", "new-value")
        assert result["values"] == ["existing", "new-value"]

    def test_duplicate_value_is_a_no_op(self, api_env):
        def fake_request(method, path, url, key, **kwargs):
            if method == "GET":
                return 200, {"rule_id": "x", "values": ["existing"]}
            pytest.fail("PUT should not be called for a duplicate value")

        with patch.object(opencdr, "_request", side_effect=fake_request):
            result = server.opencdr_lists_add("x", "existing")
        assert result == {"changed": False, "list_id": "x", "values": ["existing"]}

    def test_missing_list_raises(self, api_env):
        with patch.object(opencdr, "_request", return_value=(404, {})):
            with pytest.raises(RuntimeError, match="not found"):
                server.opencdr_lists_add("missing", "v")


class TestListsRemove:
    def test_existing_value_removed_and_put(self, api_env):
        def fake_request(method, path, url, key, **kwargs):
            if method == "GET":
                return 200, {"rule_id": "x", "values": ["keep", "to-remove"]}
            return 200, kwargs["json"]

        with patch.object(opencdr, "_request", side_effect=fake_request):
            result = server.opencdr_lists_remove("x", "to-remove")
        assert result["values"] == ["keep"]

    def test_value_not_present_is_a_no_op(self, api_env):
        def fake_request(method, path, url, key, **kwargs):
            if method == "GET":
                return 200, {"rule_id": "x", "values": ["keep"]}
            pytest.fail("PUT should not be called when the value isn't in the list")

        with patch.object(opencdr, "_request", side_effect=fake_request):
            result = server.opencdr_lists_remove("x", "not-there")
        assert result == {"changed": False, "list_id": "x", "values": ["keep"]}


class TestListsDelete:
    def test_success_returns_deleted_true(self, api_env):
        with patch.object(opencdr, "_request", return_value=(200, {"ok": True})) as mock_req:
            result = server.opencdr_lists_delete("x")
        assert result == {"deleted": True, "list_id": "x"}
        mock_req.assert_called_once_with(
            "DELETE", "/rules/x?rule_kind=list", "https://api.example.com", "test-key"
        )

    def test_404_returns_found_false(self, api_env):
        with patch.object(opencdr, "_request", return_value=(404, {})):
            result = server.opencdr_lists_delete("missing")
        assert result == {"found": False, "list_id": "missing"}


class TestSignalsList:
    def test_no_filter_raises(self, api_env):
        with pytest.raises(ValueError, match="exactly one"):
            server.opencdr_signals_list()

    def test_two_filters_raises(self, api_env):
        with pytest.raises(ValueError, match="exactly one"):
            server.opencdr_signals_list(severity="HIGH", event_id="e1")

    def test_severity_uppercased_in_qs(self, api_env):
        with patch.object(opencdr, "_request", return_value=(200, {"items": []})) as mock_req:
            server.opencdr_signals_list(severity="high")
        assert "severity=HIGH" in mock_req.call_args.args[1]

    def test_event_id_only_is_valid(self, api_env):
        with patch.object(opencdr, "_request", return_value=(200, {"items": []})) as mock_req:
            server.opencdr_signals_list(event_id="e1")
        assert "event_id=e1" in mock_req.call_args.args[1]

    def test_category_only_is_valid(self, api_env):
        with patch.object(opencdr, "_request", return_value=(200, {"items": []})) as mock_req:
            server.opencdr_signals_list(category="iam")
        assert "category=iam" in mock_req.call_args.args[1]

    def test_error_status_raises(self, api_env):
        with patch.object(opencdr, "_request", return_value=(500, {"message": "boom"})):
            with pytest.raises(RuntimeError, match="boom"):
                server.opencdr_signals_list(severity="HIGH")


class TestSignalsStats:
    def test_no_dates_omits_query_string(self, api_env):
        with patch.object(opencdr, "_request", return_value=(200, {"counts": {}, "total": 0})) as mock_req:
            server.opencdr_signals_stats()
        assert mock_req.call_args.args[1] == "/signals/stats"

    def test_both_dates_included_in_qs(self, api_env):
        with patch.object(opencdr, "_request", return_value=(200, {"counts": {}, "total": 0})) as mock_req:
            server.opencdr_signals_stats(date_from="2026-08-01", date_to="2026-08-12")
        path = mock_req.call_args.args[1]
        assert "date_from=2026-08-01" in path
        assert "date_to=2026-08-12" in path

    def test_returns_body_on_success(self, api_env):
        body = {"date_from": "2026-08-06", "date_to": "2026-08-12", "counts": {"HIGH": 2}, "total": 2}
        with patch.object(opencdr, "_request", return_value=(200, body)):
            result = server.opencdr_signals_stats()
        assert result == body

    def test_error_status_raises(self, api_env):
        with patch.object(opencdr, "_request", return_value=(500, {"message": "boom"})):
            with pytest.raises(RuntimeError, match="boom"):
                server.opencdr_signals_stats()


class TestLogsList:
    def test_no_filter_raises(self, api_env):
        with pytest.raises(ValueError, match="exactly one"):
            server.opencdr_logs_list()

    def test_two_filters_raises(self, api_env):
        with pytest.raises(ValueError, match="exactly one"):
            server.opencdr_logs_list(service="x", event_id="e1")

    def test_service_only_is_valid(self, api_env):
        with patch.object(opencdr, "_request", return_value=(200, {"items": []})) as mock_req:
            server.opencdr_logs_list(service="OPENCDR-SIGNAL-WRITER")
        assert "service=OPENCDR-SIGNAL-WRITER" in mock_req.call_args.args[1]

    def test_event_name_only_is_valid(self, api_env):
        with patch.object(opencdr, "_request", return_value=(200, {"items": []})) as mock_req:
            server.opencdr_logs_list(event_name="SIGNAL_INSERTED")
        assert "event_name=SIGNAL_INSERTED" in mock_req.call_args.args[1]

    def test_error_status_raises(self, api_env):
        with patch.object(opencdr, "_request", return_value=(500, {"message": "boom"})):
            with pytest.raises(RuntimeError, match="boom"):
                server.opencdr_logs_list(service="x")


class TestIrRolesList:
    def test_calls_correct_path(self, api_env):
        with patch.object(opencdr, "_request", return_value=(200, {"items": []})) as mock_req:
            server.opencdr_ir_roles_list()
        path = mock_req.call_args.args[1]
        assert path.startswith("/ir-roles?")
        assert "page_size=20" in path

    def test_next_token_included(self, api_env):
        with patch.object(opencdr, "_request", return_value=(200, {"items": []})) as mock_req:
            server.opencdr_ir_roles_list(next_token="tok1")
        assert "next_token=tok1" in mock_req.call_args.args[1]


class TestIrRolesGet:
    def test_returns_body_on_success(self, api_env):
        role = {"aws_account_id": "123456789012", "role_arn": "arn:aws:iam::123456789012:role/IR"}
        with patch.object(opencdr, "_request", return_value=(200, role)) as mock_req:
            result = server.opencdr_ir_roles_get("123456789012")
        assert result == role
        mock_req.assert_called_once_with(
            "GET", "/ir-roles/123456789012", "https://api.example.com", "test-key"
        )

    def test_404_returns_found_false(self, api_env):
        with patch.object(opencdr, "_request", return_value=(404, {})):
            result = server.opencdr_ir_roles_get("999999999999")
        assert result == {"found": False, "aws_account_id": "999999999999"}


class TestIrRolesUpsert:
    def test_builds_correct_payload(self, api_env):
        with patch.object(opencdr, "_request", return_value=(200, {"ok": True})) as mock_req:
            server.opencdr_ir_roles_upsert("123456789012", "arn:aws:iam::123456789012:role/IR")
        mock_req.assert_called_once_with(
            "PUT",
            "/ir-roles/123456789012",
            "https://api.example.com",
            "test-key",
            json={
                "aws_account_id": "123456789012",
                "role_arn": "arn:aws:iam::123456789012:role/IR",
                "enabled": True,
            },
        )

    def test_enabled_false_passed_through(self, api_env):
        with patch.object(opencdr, "_request", return_value=(200, {"ok": True})) as mock_req:
            server.opencdr_ir_roles_upsert("123456789012", "arn:aws:iam::123456789012:role/IR", enabled=False)
        assert mock_req.call_args.kwargs["json"]["enabled"] is False

    def test_error_status_raises(self, api_env):
        with patch.object(opencdr, "_request", return_value=(400, {"message": "bad role_arn"})):
            with pytest.raises(RuntimeError, match="bad role_arn"):
                server.opencdr_ir_roles_upsert("123456789012", "not-an-arn")


class TestIrRolesDelete:
    def test_success_returns_deleted_true(self, api_env):
        with patch.object(opencdr, "_request", return_value=(200, {"ok": True})) as mock_req:
            result = server.opencdr_ir_roles_delete("123456789012")
        assert result == {"deleted": True, "aws_account_id": "123456789012"}
        mock_req.assert_called_once_with(
            "DELETE", "/ir-roles/123456789012", "https://api.example.com", "test-key"
        )

    def test_404_returns_found_false(self, api_env):
        with patch.object(opencdr, "_request", return_value=(404, {})):
            result = server.opencdr_ir_roles_delete("999999999999")
        assert result == {"found": False, "aws_account_id": "999999999999"}


class TestIrActionsList:
    def test_calls_correct_path(self, api_env):
        with patch.object(opencdr, "_request", return_value=(200, {"items": []})) as mock_req:
            server.opencdr_ir_actions_list()
        path = mock_req.call_args.args[1]
        assert path.startswith("/ir-actions?")
        assert "page_size=20" in path

    def test_next_token_included(self, api_env):
        with patch.object(opencdr, "_request", return_value=(200, {"items": []})) as mock_req:
            server.opencdr_ir_actions_list(next_token="tok1")
        assert "next_token=tok1" in mock_req.call_args.args[1]


class TestIrActionsGet:
    def test_returns_body_on_success(self, api_env):
        action = {"detection_id": "d-1", "response_module": "disable_access_key"}
        with patch.object(opencdr, "_request", return_value=(200, action)) as mock_req:
            result = server.opencdr_ir_actions_get("d-1")
        assert result == action
        mock_req.assert_called_once_with("GET", "/ir-actions/d-1", "https://api.example.com", "test-key")

    def test_404_returns_found_false(self, api_env):
        with patch.object(opencdr, "_request", return_value=(404, {})):
            result = server.opencdr_ir_actions_get("d-404")
        assert result == {"found": False, "detection_id": "d-404"}


class TestIrActionsRollback:
    def test_calls_correct_path(self, api_env):
        with patch.object(opencdr, "_request", return_value=(202, {"detection_id": "d-1"})) as mock_req:
            server.opencdr_ir_actions_rollback("d-1")
        mock_req.assert_called_once_with(
            "POST", "/ir-actions/d-1/rollback", "https://api.example.com", "test-key"
        )

    def test_success_returns_body(self, api_env):
        with patch.object(opencdr, "_request", return_value=(202, {"message": "Rollback enqueued", "detection_id": "d-1"})):
            result = server.opencdr_ir_actions_rollback("d-1")
        assert result == {"message": "Rollback enqueued", "detection_id": "d-1"}

    def test_404_returns_found_false(self, api_env):
        with patch.object(opencdr, "_request", return_value=(404, {})):
            result = server.opencdr_ir_actions_rollback("d-404")
        assert result == {"found": False, "detection_id": "d-404"}

    def test_unsupported_rollback_raises(self, api_env):
        with patch.object(opencdr, "_request", return_value=(400, {"message": "Rollback is not supported"})):
            with pytest.raises(RuntimeError, match="not supported"):
                server.opencdr_ir_actions_rollback("d-1")

    def test_already_rolled_back_raises(self, api_env):
        with patch.object(opencdr, "_request", return_value=(409, {"message": "already been rolled back"})):
            with pytest.raises(RuntimeError, match="already been rolled back"):
                server.opencdr_ir_actions_rollback("d-1")

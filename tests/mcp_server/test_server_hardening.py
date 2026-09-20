"""
Hardening tests for the OpenCDR MCP server: tool safety annotations,
capability profiles, URL/path encoding, pagination-token safety, AWS account
validation, IR-role ARN/account matching, and audit metadata.

These complement test_server.py (which locks in per-tool request behavior).
External HTTP is mocked at opencdr._request throughout -- no live infra.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "mcp_server"))

import opencdr  # noqa: E402
import server  # noqa: E402


@pytest.fixture
def api_env(monkeypatch):
    monkeypatch.setenv("OPENCDR_API_URL", "https://api.example.com")
    monkeypatch.setenv("OPENCDR_API_KEY", "test-key")


# ---------------------------------------------------------------------------
# 1. Tool safety annotations
# ---------------------------------------------------------------------------

# (tool function, expected readOnly, expected destructive, expected idempotent)
_ANNOTATION_MATRIX = [
    ("opencdr_integrations_get", True, False, True),
    ("opencdr_integrations_put", False, False, True),
    ("opencdr_integrations_preview", False, False, True),
    ("opencdr_status", True, False, True),
    ("opencdr_rules_list", True, False, True),
    ("opencdr_rules_get", True, False, True),
    ("opencdr_lists_list", True, False, True),
    ("opencdr_lists_show", True, False, True),
    ("opencdr_signals_search", True, False, True),
    ("opencdr_signals_stats", True, False, True),
    ("opencdr_logs_search", True, False, True),
    ("opencdr_settings_get", True, False, True),
    ("opencdr_ir_roles_list", True, False, True),
    ("opencdr_ir_roles_get", True, False, True),
    ("opencdr_ir_actions_list", True, False, True),
    ("opencdr_ir_actions_get", True, False, True),
    # mutating, non-destructive, idempotent
    ("opencdr_rules_upsert", False, False, True),
    ("opencdr_lists_add", False, False, True),
    ("opencdr_lists_remove", False, False, True),
    ("opencdr_settings_set", False, False, True),
    # destructive
    ("opencdr_rules_delete", False, True, True),
    ("opencdr_lists_replace", False, True, True),
    ("opencdr_lists_delete", False, True, True),
    ("opencdr_settings_delete", False, True, True),
    ("opencdr_ir_roles_upsert", False, True, True),
    ("opencdr_ir_roles_delete", False, True, True),
    # rollback: destructive AND non-idempotent
    ("opencdr_ir_actions_rollback", False, True, False),
]


@pytest.mark.parametrize("name,read_only,destructive,idempotent", _ANNOTATION_MATRIX)
def test_tool_annotations(name, read_only, destructive, idempotent):
    fn = getattr(server, name)
    ann = fn._mcp_annotations
    assert ann.readOnlyHint is read_only, name
    assert ann.destructiveHint is destructive, name
    assert ann.idempotentHint is idempotent, name
    # every tool touches the external OpenCDR API
    assert ann.openWorldHint is True, name


def test_every_tool_is_classified():
    # No tool may ship without an annotation classification.
    assert set(server._TOOL_CAPS) == {n for (n, *_rest) in _ANNOTATION_MATRIX}


def test_registered_tools_carry_annotations():
    # The tools actually registered with FastMCP expose the annotations.
    for tool in server.mcp._tool_manager.list_tools():
        assert tool.annotations is not None, tool.name


# ---------------------------------------------------------------------------
# 9. Capability profiles (policy is pure; no reimport needed)
# ---------------------------------------------------------------------------

_READ_TOOLS = {
    "opencdr_integrations_get",
    "opencdr_status",
    "opencdr_rules_list",
    "opencdr_rules_get",
    "opencdr_lists_list",
    "opencdr_lists_show",
    "opencdr_signals_search",
    "opencdr_signals_stats",
    "opencdr_logs_search",
    "opencdr_settings_get",
    "opencdr_ir_roles_list",
    "opencdr_ir_roles_get",
    "opencdr_ir_actions_list",
    "opencdr_ir_actions_get",
}
_RULES_SETTINGS_WRITE = {
    "opencdr_integrations_put", "opencdr_integrations_preview",
    "opencdr_rules_upsert",
    "opencdr_rules_delete",
    "opencdr_lists_replace",
    "opencdr_lists_add",
    "opencdr_lists_remove",
    "opencdr_lists_delete",
    "opencdr_settings_set",
    "opencdr_settings_delete",
}
_RESPONDER_ONLY = {
    "opencdr_ir_roles_upsert",
    "opencdr_ir_roles_delete",
    "opencdr_ir_actions_rollback",
}


def test_observer_is_read_only():
    assert server.allowed_tools("observer") == _READ_TOOLS


def test_observer_cannot_reach_any_mutation():
    observer = server.allowed_tools("observer")
    for name in _RULES_SETTINGS_WRITE | _RESPONDER_ONLY:
        assert name not in observer, name


def test_operator_adds_rules_and_settings_but_not_responder():
    operator = server.allowed_tools("operator")
    assert _READ_TOOLS <= operator
    assert _RULES_SETTINGS_WRITE <= operator
    for name in _RESPONDER_ONLY:
        assert name not in operator, name


def test_responder_has_everything():
    responder = server.allowed_tools("responder")
    assert responder == _READ_TOOLS | _RULES_SETTINGS_WRITE | _RESPONDER_ONLY


def test_unknown_profile_falls_back_to_observer():
    assert server.allowed_tools("wat") == _READ_TOOLS


def test_default_process_profile_is_observer():
    # With no OPENCDR_MCP_PROFILE set (the test process), only read tools are
    # actually registered with FastMCP -- destructive tools are undiscoverable.
    registered = {t.name for t in server.mcp._tool_manager.list_tools()}
    assert registered == _READ_TOOLS
    for name in _RESPONDER_ONLY:
        assert name not in registered, name


# ---------------------------------------------------------------------------
# 4. URL / query / path encoding
# ---------------------------------------------------------------------------


def test_qs_url_encodes_and_drops_none():
    qs = server._qs(a="x y", b=None, c="a+b/c=d")
    assert "b=" not in qs
    assert "a=x+y" in qs
    assert "c=a%2Bb%2Fc%3Dd" in qs


def test_pagination_token_with_special_chars_is_encoded(api_env):
    # base64-urlsafe cursors can contain '=' padding; it must be percent-encoded
    # so it stays inside the next_token value instead of splitting the query.
    token = "eyJrIjoidiJ9=="
    with patch.object(opencdr, "_request", return_value=(200, {"items": []})) as mock_req:
        server.opencdr_rules_list(next_token=token)
    path = mock_req.call_args.args[1]
    assert "next_token=eyJrIjoidiJ9%3D%3D" in path
    assert "==" not in path.split("next_token=")[1]


def test_signals_search_encodes_principal_like_event_id(api_env):
    with patch.object(opencdr, "_request", return_value=(200, {"items": []})) as mock_req:
        server.opencdr_signals_search(event_id="AROA:sess/user@corp")
    path = mock_req.call_args.args[1]
    assert "AROA%3Asess%2Fuser%40corp" in path


def test_path_segment_rejects_empty():
    with pytest.raises(ValueError, match="rule_id is required"):
        server._seg("", "rule_id")
    with pytest.raises(ValueError, match="rule_id is required"):
        server._seg("   ", "rule_id")


def test_path_segment_cannot_break_out(api_env):
    # A slash in an id is encoded, so it can't forge a different route.
    with patch.object(opencdr, "_request", return_value=(200, {})) as mock_req:
        server.opencdr_rules_get("../../settings/global", "signal")
    path = mock_req.call_args.args[1]
    assert path.startswith("/rules/..%2F..%2Fsettings%2Fglobal?")


# ---------------------------------------------------------------------------
# 6. Investigation search date filters (backend-supported subset)
# ---------------------------------------------------------------------------


def test_signals_search_severity_accepts_date_range(api_env):
    with patch.object(opencdr, "_request", return_value=(200, {"items": []})) as mock_req:
        server.opencdr_signals_search(severity="HIGH", date_from="2026-08-01", date_to="2026-08-10")
    path = mock_req.call_args.args[1]
    assert "date_from=2026-08-01" in path
    assert "date_to=2026-08-10" in path


def test_signals_search_dates_ignored_without_severity(api_env):
    # date_from/date_to only apply to the day-bucketed severity selector.
    with patch.object(opencdr, "_request", return_value=(200, {"items": []})) as mock_req:
        server.opencdr_signals_search(event_id="e1", date_from="2026-08-01")
    path = mock_req.call_args.args[1]
    assert "date_from" not in path


def test_logs_search_service_accepts_date_range(api_env):
    with patch.object(opencdr, "_request", return_value=(200, {"items": []})) as mock_req:
        server.opencdr_logs_search(
            service="OPENCDR-API", date_from="2026-08-01", date_to="2026-08-10"
        )
    path = mock_req.call_args.args[1]
    assert "date_from=2026-08-01" in path and "date_to=2026-08-10" in path


# ---------------------------------------------------------------------------
# 10. AWS account / IR-role ARN validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad", ["12345", "12345678901a", "1234567890123", "", "12345678901"])
def test_invalid_account_id_rejected(api_env, bad):
    with pytest.raises(ValueError, match="12-digit"):
        server.opencdr_ir_roles_get(bad)


def test_ir_role_upsert_rejects_non_arn(api_env):
    with pytest.raises(ValueError, match="IAM role ARN"):
        server.opencdr_ir_roles_upsert("123456789012", "not-an-arn")


def test_ir_role_upsert_rejects_cross_account_arn(api_env):
    # ARN points at a different account than aws_account_id.
    with patch.object(opencdr, "_request") as mock_req:
        with pytest.raises(ValueError, match="cross-account role mapping refused"):
            server.opencdr_ir_roles_upsert("123456789012", "arn:aws:iam::999999999999:role/IR")
    mock_req.assert_not_called()  # never hit the API


def test_ir_role_upsert_accepts_matching_arn(api_env):
    with patch.object(opencdr, "_request", return_value=(200, {"ok": True})) as mock_req:
        server.opencdr_ir_roles_upsert("123456789012", "arn:aws:iam::123456789012:role/IR")
    mock_req.assert_called_once()


def test_ir_role_get_invalid_account_never_calls_api(api_env):
    with patch.object(opencdr, "_request") as mock_req:
        with pytest.raises(ValueError):
            server.opencdr_ir_roles_get("bad")
    mock_req.assert_not_called()


# ---------------------------------------------------------------------------
# 11. Rollback audit metadata (actor identity is server-side, not from LLM)
# ---------------------------------------------------------------------------


def test_rollback_sends_interface_without_reason(api_env):
    with patch.object(opencdr, "_request", return_value=(202, {})) as mock_req:
        server.opencdr_ir_actions_rollback("d-1")
    assert mock_req.call_args.kwargs["json"] == {"interface": "mcp"}


def test_rollback_includes_reason_when_given(api_env):
    with patch.object(opencdr, "_request", return_value=(202, {})) as mock_req:
        server.opencdr_ir_actions_rollback("d-1", reason="false positive")
    body = mock_req.call_args.kwargs["json"]
    assert body["interface"] == "mcp"
    assert body["reason"] == "false positive"
    # The tool exposes no actor/identity parameter -- identity is server-side.
    assert "actor" not in body


# ---------------------------------------------------------------------------
# 3. List replacement semantics
# ---------------------------------------------------------------------------


def test_lists_replace_is_whole_object_put(api_env):
    with patch.object(opencdr, "_request", return_value=(200, {"ok": True})) as mock_req:
        server.opencdr_lists_replace("ioc", "desc", ["a", "b"])
    method, path = mock_req.call_args.args[0], mock_req.call_args.args[1]
    assert method == "PUT"
    assert path == "/rules/ioc?rule_kind=list"
    assert mock_req.call_args.kwargs["json"]["values"] == ["a", "b"]


def test_lists_replace_docstring_warns_of_replacement():
    doc = server.opencdr_lists_replace.__doc__ or ""
    assert "REPLACE" in doc.upper()


def test_old_create_tool_name_is_gone():
    assert not hasattr(server, "opencdr_lists_create")

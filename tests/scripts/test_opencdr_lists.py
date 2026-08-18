"""Tests for `opencdr.py lists create/list/show/add/remove/delete`."""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

import opencdr  # noqa: E402  (after sys.path manipulation)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(func, args, *, api_response=None, request_side_effect=None):
    """
    Either pass a single api_response (every _request call gets the same
    response) or request_side_effect (a callable(method, path, url, key,
    **kwargs) for multi-call flows like _get_list then PUT).
    """
    kwargs = {}
    if request_side_effect is not None:
        kwargs["side_effect"] = request_side_effect
    else:
        kwargs["return_value"] = api_response
    with (
        patch.object(opencdr, "_load_config", return_value={}),
        patch.object(opencdr, "_require_api", return_value=("https://api.example.com", "test-key")),
        patch.object(opencdr, "_request", **kwargs) as mock_request,
    ):
        func(args)
    return mock_request


# ---------------------------------------------------------------------------
# cmd_lists_create
# ---------------------------------------------------------------------------


class TestListsCreate:
    def test_builds_correct_payload(self):
        args = SimpleNamespace(list_id="automation-identities", description="CI identities", values=["ci-deploy-role", "cdk-toolkit"])
        mock_request = _run(opencdr.cmd_lists_create, args, api_response=(200, {"ok": True}))
        method, path, kwargs = mock_request.call_args.args[0], mock_request.call_args.args[1], mock_request.call_args.kwargs
        assert method == "PUT"
        assert path == "/rules/automation-identities?rule_kind=list"
        assert kwargs["json"] == {
            "rule_id": "automation-identities",
            "rule_kind": "list",
            "description": "CI identities",
            "values": ["ci-deploy-role", "cdk-toolkit"],
        }

    def test_no_description_defaults_to_empty_string(self):
        args = SimpleNamespace(list_id="x", description=None, values=["a"])
        mock_request = _run(opencdr.cmd_lists_create, args, api_response=(200, {"ok": True}))
        assert mock_request.call_args.kwargs["json"]["description"] == ""

    def test_no_values_defaults_to_empty_list(self):
        args = SimpleNamespace(list_id="x", description="d", values=None)
        mock_request = _run(opencdr.cmd_lists_create, args, api_response=(200, {"ok": True}))
        assert mock_request.call_args.kwargs["json"]["values"] == []

    def test_success_prints_created_with_value_count(self, capsys):
        args = SimpleNamespace(list_id="x", description="d", values=["a", "b"])
        _run(opencdr.cmd_lists_create, args, api_response=(200, {"ok": True}))
        out = capsys.readouterr().out
        assert "created" in out.lower()
        assert "x" in out
        assert "2 values" in out

    def test_singular_value_count(self, capsys):
        args = SimpleNamespace(list_id="x", description="d", values=["a"])
        _run(opencdr.cmd_lists_create, args, api_response=(200, {"ok": True}))
        assert "1 value" in capsys.readouterr().out
        assert "1 values" not in capsys.readouterr().out

    def test_error_status_exits(self):
        args = SimpleNamespace(list_id="x", description="d", values=[])
        with pytest.raises(SystemExit):
            _run(opencdr.cmd_lists_create, args, api_response=(500, {"message": "boom"}))


# ---------------------------------------------------------------------------
# cmd_lists_list
# ---------------------------------------------------------------------------


class TestListsList:
    def test_calls_correct_path(self):
        mock_request = _run(opencdr.cmd_lists_list, SimpleNamespace(), api_response=(200, {"items": []}))
        method, path = mock_request.call_args.args[:2]
        assert method == "GET"
        assert path == "/rules?rule_kind=list&page_size=100"

    def test_empty_items_prints_no_lists_found(self, capsys):
        _run(opencdr.cmd_lists_list, SimpleNamespace(), api_response=(200, {"items": []}))
        assert "no lists found" in capsys.readouterr().out.lower()

    def test_items_printed_with_value_count(self, capsys):
        _run(
            opencdr.cmd_lists_list,
            SimpleNamespace(),
            api_response=(200, {"items": [{"rule_id": "automation-identities", "values": ["a", "b", "c"], "description": "CI"}]}),
        )
        out = capsys.readouterr().out
        assert "automation-identities" in out
        assert "3" in out

    def test_error_status_exits(self):
        with pytest.raises(SystemExit):
            _run(opencdr.cmd_lists_list, SimpleNamespace(), api_response=(500, {"message": "boom"}))


# ---------------------------------------------------------------------------
# cmd_lists_show
# ---------------------------------------------------------------------------


class TestListsShow:
    def test_calls_correct_path(self):
        args = SimpleNamespace(list_id="automation-identities")
        mock_request = _run(opencdr.cmd_lists_show, args, api_response=(200, {"values": []}))
        method, path = mock_request.call_args.args[:2]
        assert method == "GET"
        assert path == "/rules/automation-identities?rule_kind=list"

    def test_values_printed_sorted(self, capsys):
        args = SimpleNamespace(list_id="x")
        _run(opencdr.cmd_lists_show, args, api_response=(200, {"values": ["zebra", "apple", "mango"]}))
        out = capsys.readouterr().out
        assert out.index("apple") < out.index("mango") < out.index("zebra")

    def test_empty_values_no_crash(self, capsys):
        args = SimpleNamespace(list_id="x")
        _run(opencdr.cmd_lists_show, args, api_response=(200, {"values": []}))
        assert "0 values" in capsys.readouterr().out

    def test_404_exits_1_with_not_found_message(self, capsys):
        args = SimpleNamespace(list_id="missing-list")
        with pytest.raises(SystemExit) as exc_info:
            _run(opencdr.cmd_lists_show, args, api_response=(404, {}))
        assert exc_info.value.code == 1
        assert "not found" in capsys.readouterr().out.lower()


# ---------------------------------------------------------------------------
# cmd_lists_add
# ---------------------------------------------------------------------------


class TestListsAdd:
    def test_new_value_appended_and_put(self):
        args = SimpleNamespace(list_id="x", value="new-value")
        calls = []

        def fake_request(method, path, url, key, **kwargs):
            calls.append((method, path, kwargs.get("json")))
            if method == "GET":
                return 200, {"rule_id": "x", "values": ["existing"]}
            return 200, {"ok": True}

        _run(opencdr.cmd_lists_add, args, request_side_effect=fake_request)
        put_call = next(c for c in calls if c[0] == "PUT")
        assert put_call[2]["values"] == ["existing", "new-value"]

    def test_duplicate_value_skips_put(self, capsys):
        args = SimpleNamespace(list_id="x", value="existing")

        def fake_request(method, path, url, key, **kwargs):
            if method == "GET":
                return 200, {"rule_id": "x", "values": ["existing"]}
            pytest.fail("PUT should not be called for a duplicate value")

        _run(opencdr.cmd_lists_add, args, request_side_effect=fake_request)
        assert "already in" in capsys.readouterr().out.lower()

    def test_get_list_404_exits_before_put(self):
        args = SimpleNamespace(list_id="missing", value="v")

        def fake_request(method, path, url, key, **kwargs):
            if method == "GET":
                return 404, {}
            pytest.fail("PUT should not be called when the list doesn't exist")

        with pytest.raises(SystemExit) as exc_info:
            _run(opencdr.cmd_lists_add, args, request_side_effect=fake_request)
        assert exc_info.value.code == 1

    def test_success_prints_updated_count(self, capsys):
        args = SimpleNamespace(list_id="x", value="new-value")

        def fake_request(method, path, url, key, **kwargs):
            if method == "GET":
                return 200, {"rule_id": "x", "values": []}
            return 200, {"ok": True}

        _run(opencdr.cmd_lists_add, args, request_side_effect=fake_request)
        out = capsys.readouterr().out
        assert "updated" in out.lower()
        assert "1 value" in out


# ---------------------------------------------------------------------------
# cmd_lists_remove
# ---------------------------------------------------------------------------


class TestListsRemove:
    def test_existing_value_removed_and_put(self):
        args = SimpleNamespace(list_id="x", value="to-remove")
        calls = []

        def fake_request(method, path, url, key, **kwargs):
            calls.append((method, path, kwargs.get("json")))
            if method == "GET":
                return 200, {"rule_id": "x", "values": ["keep", "to-remove"]}
            return 200, {"ok": True}

        _run(opencdr.cmd_lists_remove, args, request_side_effect=fake_request)
        put_call = next(c for c in calls if c[0] == "PUT")
        assert put_call[2]["values"] == ["keep"]

    def test_value_not_present_skips_put(self, capsys):
        args = SimpleNamespace(list_id="x", value="not-there")

        def fake_request(method, path, url, key, **kwargs):
            if method == "GET":
                return 200, {"rule_id": "x", "values": ["keep"]}
            pytest.fail("PUT should not be called when the value isn't in the list")

        _run(opencdr.cmd_lists_remove, args, request_side_effect=fake_request)
        assert "not found" in capsys.readouterr().out.lower()

    def test_get_list_404_exits_before_put(self):
        args = SimpleNamespace(list_id="missing", value="v")

        def fake_request(method, path, url, key, **kwargs):
            if method == "GET":
                return 404, {}
            pytest.fail("PUT should not be called when the list doesn't exist")

        with pytest.raises(SystemExit):
            _run(opencdr.cmd_lists_remove, args, request_side_effect=fake_request)


# ---------------------------------------------------------------------------
# cmd_lists_delete
# ---------------------------------------------------------------------------


class TestListsDelete:
    def test_calls_correct_path(self):
        args = SimpleNamespace(list_id="x")
        mock_request = _run(opencdr.cmd_lists_delete, args, api_response=(200, {"ok": True}))
        method, path = mock_request.call_args.args[:2]
        assert method == "DELETE"
        assert path == "/rules/x?rule_kind=list"

    def test_success_prints_deleted_message(self, capsys):
        args = SimpleNamespace(list_id="x")
        _run(opencdr.cmd_lists_delete, args, api_response=(200, {"ok": True}))
        assert "deleted" in capsys.readouterr().out.lower()

    def test_404_exits_1(self, capsys):
        args = SimpleNamespace(list_id="missing")
        with pytest.raises(SystemExit) as exc_info:
            _run(opencdr.cmd_lists_delete, args, api_response=(404, {}))
        assert exc_info.value.code == 1
        assert "not found" in capsys.readouterr().out.lower()

    def test_other_error_status_exits(self):
        args = SimpleNamespace(list_id="x")
        with pytest.raises(SystemExit):
            _run(opencdr.cmd_lists_delete, args, api_response=(500, {"message": "boom"}))

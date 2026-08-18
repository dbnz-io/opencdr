"""Tests for `opencdr.py rules load/list/get/delete`."""
from __future__ import annotations

import json
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


@pytest.fixture()
def rules_dir(tmp_path, monkeypatch):
    d = tmp_path / "detection_rules"
    d.mkdir()
    monkeypatch.setattr(opencdr, "RULES_DIR", d)
    # cmd_rules_load's empty-directory message does RULES_DIR.relative_to(ROOT)
    # -- ROOT must be patched to an ancestor of the fake RULES_DIR too, or
    # that call raises ValueError ("not in the subpath of").
    monkeypatch.setattr(opencdr, "ROOT", tmp_path)
    return d


def _write_rule(directory: Path, filename: str, data: dict) -> None:
    (directory / filename).write_text(json.dumps(data))


def _make_load_args(dry_run=False) -> SimpleNamespace:
    return SimpleNamespace(dry_run=dry_run)


def _run_rules_load(args, *, api_response=(200, {"ok": True})):
    put_calls = []

    def fake_request(method, path, url, key, **kwargs):
        put_calls.append((method, path, kwargs.get("json")))
        return api_response

    with (
        patch.object(opencdr, "_load_config", return_value={}),
        patch.object(opencdr, "_require_api", return_value=("https://api.example.com", "test-key")),
        patch.object(opencdr, "_request", side_effect=fake_request),
    ):
        opencdr.cmd_rules_load(args)
    return put_calls


# ---------------------------------------------------------------------------
# cmd_rules_load
# ---------------------------------------------------------------------------


class TestRulesLoad:
    def test_empty_directory_prints_warning_no_api_calls(self, rules_dir, capsys):
        calls = _run_rules_load(_make_load_args())
        assert calls == []
        assert "no rule files found" in capsys.readouterr().out.lower()

    def test_skip_list_files_are_skipped_not_loaded(self, rules_dir):
        _write_rule(rules_dir, "test_atomic_rule.json", {"rule_id": "x", "rule_kind": "signal"})
        _write_rule(rules_dir, "test_correlation_rule.json", {"rule_id": "y", "rule_kind": "correlation"})
        _write_rule(rules_dir, "test_detection_rule.json", {"rule_id": "z", "rule_kind": "signal"})
        calls = _run_rules_load(_make_load_args())
        assert calls == []

    def test_real_rule_is_loaded_via_put_upsert(self, rules_dir):
        _write_rule(rules_dir, "024_guardduty.json", {"rule_id": "024_guardduty", "rule_kind": "signal"})
        calls = _run_rules_load(_make_load_args())
        assert len(calls) == 1
        method, path, payload = calls[0]
        assert method == "PUT"
        assert path == "/rules/024_guardduty?rule_kind=signal"
        assert payload == {"rule_id": "024_guardduty", "rule_kind": "signal"}

    def test_invalid_json_counts_as_failed_and_exits_1(self, rules_dir, capsys):
        (rules_dir / "broken.json").write_text("not valid json {{{")
        with pytest.raises(SystemExit) as exc_info:
            _run_rules_load(_make_load_args())
        assert exc_info.value.code == 1
        assert "invalid JSON" in capsys.readouterr().out

    def test_missing_rule_id_counts_as_failed(self, rules_dir):
        _write_rule(rules_dir, "bad.json", {"rule_kind": "signal"})
        with pytest.raises(SystemExit):
            _run_rules_load(_make_load_args())

    def test_missing_rule_kind_counts_as_failed(self, rules_dir):
        _write_rule(rules_dir, "bad.json", {"rule_id": "x"})
        with pytest.raises(SystemExit):
            _run_rules_load(_make_load_args())

    def test_dry_run_makes_no_api_calls(self, rules_dir, capsys):
        _write_rule(rules_dir, "024_guardduty.json", {"rule_id": "024_guardduty", "rule_kind": "signal"})
        calls = _run_rules_load(_make_load_args(dry_run=True))
        assert calls == []
        assert "[DRY]" in capsys.readouterr().out

    def test_api_error_status_counts_as_failed(self, rules_dir):
        _write_rule(rules_dir, "024_guardduty.json", {"rule_id": "024_guardduty", "rule_kind": "signal"})
        with pytest.raises(SystemExit) as exc_info:
            _run_rules_load(_make_load_args(), api_response=(400, {"message": "bad rule"}))
        assert exc_info.value.code == 1

    def test_201_status_counts_as_loaded_not_failed(self, rules_dir):
        _write_rule(rules_dir, "024_guardduty.json", {"rule_id": "024_guardduty", "rule_kind": "signal"})
        # Should not raise -- 201 is a success status, no sys.exit(1).
        _run_rules_load(_make_load_args(), api_response=(201, {"ok": True}))

    def test_summary_counts_all_three_buckets(self, rules_dir, capsys):
        _write_rule(rules_dir, "024_guardduty.json", {"rule_id": "024_guardduty", "rule_kind": "signal"})
        _write_rule(rules_dir, "test_atomic_rule.json", {"rule_id": "x", "rule_kind": "signal"})
        _write_rule(rules_dir, "bad.json", {"rule_kind": "signal"})
        with pytest.raises(SystemExit):
            _run_rules_load(_make_load_args())
        out = capsys.readouterr().out
        assert "Loaded  : 1" in out
        assert "Skipped : 1" in out
        assert "Failed  : 1" in out


# ---------------------------------------------------------------------------
# cmd_rules_list
# ---------------------------------------------------------------------------


def _run_rules_list(args, *, api_response):
    with (
        patch.object(opencdr, "_load_config", return_value={}),
        patch.object(opencdr, "_require_api", return_value=("https://api.example.com", "test-key")),
        patch.object(opencdr, "_request", return_value=api_response) as mock_request,
    ):
        opencdr.cmd_rules_list(args)
    return mock_request


class TestRulesList:
    def test_builds_query_with_kind_and_page_size(self):
        args = SimpleNamespace(kind="signal", page_size=25, next_token=None)
        mock_request = _run_rules_list(args, api_response=(200, {"items": []}))
        path = mock_request.call_args.args[1]
        assert "rule_kind=signal" in path
        assert "page_size=25" in path

    def test_includes_next_token_when_provided(self):
        args = SimpleNamespace(kind=None, page_size=25, next_token="abc123")
        mock_request = _run_rules_list(args, api_response=(200, {"items": []}))
        path = mock_request.call_args.args[1]
        assert "next_token=abc123" in path

    def test_omits_kind_when_not_provided(self):
        args = SimpleNamespace(kind=None, page_size=25, next_token=None)
        mock_request = _run_rules_list(args, api_response=(200, {"items": []}))
        path = mock_request.call_args.args[1]
        assert "rule_kind" not in path

    def test_empty_items_prints_no_rules_found(self, capsys):
        args = SimpleNamespace(kind=None, page_size=25, next_token=None)
        _run_rules_list(args, api_response=(200, {"items": []}))
        assert "no rules found" in capsys.readouterr().out.lower()

    def test_items_printed_with_rule_id(self, capsys):
        args = SimpleNamespace(kind=None, page_size=25, next_token=None)
        _run_rules_list(
            args,
            api_response=(200, {"items": [{"rule_id": "024_guardduty", "rule_kind": "signal", "severity": "HIGH", "enabled": True}]}),
        )
        assert "024_guardduty" in capsys.readouterr().out

    def test_has_next_prints_pagination_hint(self, capsys):
        args = SimpleNamespace(kind=None, page_size=25, next_token=None)
        _run_rules_list(
            args,
            api_response=(200, {"items": [{"rule_id": "x", "rule_kind": "signal"}], "has_next": True, "next_token": "tok2"}),
        )
        out = capsys.readouterr().out
        assert "tok2" in out

    def test_error_status_exits(self):
        args = SimpleNamespace(kind=None, page_size=25, next_token=None)
        with pytest.raises(SystemExit):
            _run_rules_list(args, api_response=(500, {"message": "boom"}))


# ---------------------------------------------------------------------------
# cmd_rules_get
# ---------------------------------------------------------------------------


def _run_rules_get(rule_id="024_guardduty", kind="signal", *, api_response):
    args = SimpleNamespace(rule_id=rule_id, kind=kind)
    with (
        patch.object(opencdr, "_load_config", return_value={}),
        patch.object(opencdr, "_require_api", return_value=("https://api.example.com", "test-key")),
        patch.object(opencdr, "_request", return_value=api_response) as mock_request,
    ):
        opencdr.cmd_rules_get(args)
    return mock_request


class TestRulesGet:
    def test_calls_correct_path(self):
        mock_request = _run_rules_get(api_response=(200, {"rule_id": "024_guardduty"}))
        method, path = mock_request.call_args.args[:2]
        assert method == "GET"
        assert path == "/rules/024_guardduty?rule_kind=signal"

    def test_prints_rule_json(self, capsys):
        _run_rules_get(api_response=(200, {"rule_id": "024_guardduty", "severity": "HIGH"}))
        out = capsys.readouterr().out
        assert "024_guardduty" in out
        assert "HIGH" in out

    def test_404_exits_1_with_not_found_message(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            _run_rules_get(api_response=(404, {}))
        assert exc_info.value.code == 1
        assert "not found" in capsys.readouterr().out.lower()

    def test_other_error_status_exits(self):
        with pytest.raises(SystemExit):
            _run_rules_get(api_response=(500, {"message": "boom"}))


# ---------------------------------------------------------------------------
# cmd_rules_delete
# ---------------------------------------------------------------------------


def _run_rules_delete(rule_id="024_guardduty", kind="signal", *, api_response):
    args = SimpleNamespace(rule_id=rule_id, kind=kind)
    with (
        patch.object(opencdr, "_load_config", return_value={}),
        patch.object(opencdr, "_require_api", return_value=("https://api.example.com", "test-key")),
        patch.object(opencdr, "_request", return_value=api_response) as mock_request,
    ):
        opencdr.cmd_rules_delete(args)
    return mock_request


class TestRulesDelete:
    def test_calls_correct_path(self):
        mock_request = _run_rules_delete(api_response=(200, {"ok": True}))
        method, path = mock_request.call_args.args[:2]
        assert method == "DELETE"
        assert path == "/rules/024_guardduty?rule_kind=signal"

    def test_success_prints_deleted_message(self, capsys):
        _run_rules_delete(api_response=(200, {"ok": True}))
        out = capsys.readouterr().out
        assert "deleted" in out.lower()
        assert "024_guardduty" in out

    def test_404_exits_1_with_not_found_message(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            _run_rules_delete(api_response=(404, {}))
        assert exc_info.value.code == 1
        assert "not found" in capsys.readouterr().out.lower()

    def test_other_error_status_exits(self):
        with pytest.raises(SystemExit):
            _run_rules_delete(api_response=(500, {"message": "boom"}))

"""Tests for `opencdr.py signals list` / `logs list` (cmd_signals_list, cmd_logs_list)."""
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


def _make_signals_args(severity=None, event_id=None, category=None, page_size=25, order="desc", next_token=None):
    return SimpleNamespace(
        severity=severity, event_id=event_id, category=category,
        page_size=page_size, order=order, next_token=next_token,
    )


def _make_logs_args(service=None, event_id=None, event_name=None, page_size=25, order="desc", next_token=None):
    return SimpleNamespace(
        service=service, event_id=event_id, event_name=event_name,
        page_size=page_size, order=order, next_token=next_token,
    )


def _run(func, args, *, api_response=(200, {"items": []})):
    with (
        patch.object(opencdr, "_load_config", return_value={}),
        patch.object(opencdr, "_require_api", return_value=("https://api.example.com", "test-key")),
        patch.object(opencdr, "_request", return_value=api_response) as mock_request,
    ):
        func(args)
    return mock_request


# ---------------------------------------------------------------------------
# cmd_signals_list
# ---------------------------------------------------------------------------


class TestSignalsListFilterValidation:
    def test_no_filter_provided_exits_1(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            _run(opencdr.cmd_signals_list, _make_signals_args())
        assert exc_info.value.code == 1
        assert "exactly one" in capsys.readouterr().out.lower()

    def test_two_filters_provided_exits_1(self):
        with pytest.raises(SystemExit) as exc_info:
            _run(opencdr.cmd_signals_list, _make_signals_args(severity="HIGH", event_id="e1"))
        assert exc_info.value.code == 1

    def test_all_three_filters_provided_exits_1(self):
        with pytest.raises(SystemExit):
            _run(opencdr.cmd_signals_list, _make_signals_args(severity="HIGH", event_id="e1", category="iam"))

    def test_severity_only_is_valid(self):
        mock_request = _run(opencdr.cmd_signals_list, _make_signals_args(severity="high"))
        path = mock_request.call_args.args[1]
        assert "severity=HIGH" in path  # uppercased

    def test_event_id_only_is_valid(self):
        mock_request = _run(opencdr.cmd_signals_list, _make_signals_args(event_id="e1"))
        path = mock_request.call_args.args[1]
        assert "event_id=e1" in path

    def test_category_only_is_valid(self):
        mock_request = _run(opencdr.cmd_signals_list, _make_signals_args(category="iam"))
        path = mock_request.call_args.args[1]
        assert "category=iam" in path


class TestSignalsListQueryString:
    def test_includes_page_size_and_order(self):
        mock_request = _run(opencdr.cmd_signals_list, _make_signals_args(severity="HIGH", page_size=10, order="asc"))
        path = mock_request.call_args.args[1]
        assert "page_size=10" in path
        assert "order=asc" in path

    def test_includes_next_token_when_provided(self):
        mock_request = _run(opencdr.cmd_signals_list, _make_signals_args(severity="HIGH", next_token="tok1"))
        path = mock_request.call_args.args[1]
        assert "next_token=tok1" in path

    def test_calls_signals_endpoint(self):
        mock_request = _run(opencdr.cmd_signals_list, _make_signals_args(severity="HIGH"))
        method, path = mock_request.call_args.args[:2]
        assert method == "GET"
        assert path.startswith("/signals?")


class TestSignalsListOutput:
    def test_empty_items_prints_no_signals_found(self, capsys):
        _run(opencdr.cmd_signals_list, _make_signals_args(severity="HIGH"), api_response=(200, {"items": []}))
        assert "no signals found" in capsys.readouterr().out.lower()

    def test_items_printed_with_rule_id(self, capsys):
        _run(
            opencdr.cmd_signals_list,
            _make_signals_args(severity="HIGH"),
            api_response=(200, {"items": [{"timestamp": "2026-08-14T00:00:00Z", "rule_id": "024_guardduty", "severity": "HIGH"}]}),
        )
        assert "024_guardduty" in capsys.readouterr().out

    def test_has_next_prints_pagination_hint(self, capsys):
        _run(
            opencdr.cmd_signals_list,
            _make_signals_args(severity="HIGH"),
            api_response=(200, {"items": [{"rule_id": "x"}], "has_next": True, "next_token": "tok2"}),
        )
        assert "tok2" in capsys.readouterr().out

    def test_error_status_exits(self):
        with pytest.raises(SystemExit):
            _run(opencdr.cmd_signals_list, _make_signals_args(severity="HIGH"), api_response=(500, {"message": "boom"}))


# ---------------------------------------------------------------------------
# cmd_logs_list
# ---------------------------------------------------------------------------


class TestLogsListFilterValidation:
    def test_no_filter_provided_exits_1(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            _run(opencdr.cmd_logs_list, _make_logs_args())
        assert exc_info.value.code == 1
        assert "exactly one" in capsys.readouterr().out.lower()

    def test_two_filters_provided_exits_1(self):
        with pytest.raises(SystemExit):
            _run(opencdr.cmd_logs_list, _make_logs_args(service="signal-writer", event_id="e1"))

    def test_service_only_is_valid(self):
        mock_request = _run(opencdr.cmd_logs_list, _make_logs_args(service="OPENCDR-SIGNAL-WRITER"))
        path = mock_request.call_args.args[1]
        assert "service=OPENCDR-SIGNAL-WRITER" in path

    def test_event_id_only_is_valid(self):
        mock_request = _run(opencdr.cmd_logs_list, _make_logs_args(event_id="e1"))
        path = mock_request.call_args.args[1]
        assert "event_id=e1" in path

    def test_event_name_only_is_valid(self):
        mock_request = _run(opencdr.cmd_logs_list, _make_logs_args(event_name="SIGNAL_INSERTED"))
        path = mock_request.call_args.args[1]
        assert "event_name=SIGNAL_INSERTED" in path


class TestLogsListOutput:
    def test_empty_items_prints_no_logs_found(self, capsys):
        _run(opencdr.cmd_logs_list, _make_logs_args(service="x"), api_response=(200, {"items": []}))
        assert "no logs found" in capsys.readouterr().out.lower()

    def test_items_printed_with_event_name_and_level(self, capsys):
        _run(
            opencdr.cmd_logs_list,
            _make_logs_args(service="x"),
            api_response=(200, {"items": [{"timestamp": "2026-08-14T00:00:00Z", "event_name": "SIGNAL_INSERTED", "details": {"level": "INFO"}}]}),
        )
        out = capsys.readouterr().out
        assert "SIGNAL_INSERTED" in out
        assert "INFO" in out

    def test_missing_details_does_not_crash(self, capsys):
        _run(
            opencdr.cmd_logs_list,
            _make_logs_args(service="x"),
            api_response=(200, {"items": [{"timestamp": "2026-08-14T00:00:00Z", "event_name": "SOME_EVENT"}]}),
        )
        assert "SOME_EVENT" in capsys.readouterr().out

    def test_has_next_prints_pagination_hint(self, capsys):
        _run(
            opencdr.cmd_logs_list,
            _make_logs_args(service="x"),
            api_response=(200, {"items": [{"event_name": "x"}], "has_next": True, "next_token": "tok3"}),
        )
        assert "tok3" in capsys.readouterr().out

    def test_error_status_exits(self):
        with pytest.raises(SystemExit):
            _run(opencdr.cmd_logs_list, _make_logs_args(service="x"), api_response=(500, {"message": "boom"}))

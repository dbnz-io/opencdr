"""Tests for `opencdr.py ir-actions list/get/rollback`."""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

import opencdr  # noqa: E402  (after sys.path manipulation)


# ---------------------------------------------------------------------------
# cmd_ir_actions_list
# ---------------------------------------------------------------------------


def _run_ir_actions_list(page_size=20, next_token=None, *, api_response):
    args = SimpleNamespace(page_size=page_size, next_token=next_token)
    with (
        patch.object(opencdr, "_load_config", return_value={}),
        patch.object(opencdr, "_require_api", return_value=("https://api.example.com", "test-key")),
        patch.object(opencdr, "_request", return_value=api_response) as mock_request,
    ):
        opencdr.cmd_ir_actions_list(args)
    return mock_request


class TestIrActionsList:
    def test_calls_correct_path(self):
        mock_request = _run_ir_actions_list(api_response=(200, {"items": []}))
        method, path = mock_request.call_args.args[:2]
        assert method == "GET"
        assert path == "/ir-actions?page_size=20"

    def test_next_token_included_in_query(self):
        mock_request = _run_ir_actions_list(next_token="abc", api_response=(200, {"items": []}))
        _, path = mock_request.call_args.args[:2]
        assert "next_token=abc" in path

    def test_empty_list_prints_warning(self, capsys):
        _run_ir_actions_list(api_response=(200, {"items": []}))
        assert "no ir actions recorded" in capsys.readouterr().out.lower()

    def test_prints_items(self, capsys):
        _run_ir_actions_list(
            api_response=(
                200,
                {
                    "items": [
                        {
                            "detection_id": "d-1",
                            "response_module": "disable_access_key",
                            "rollback_supported": True,
                            "rolled_back": False,
                        }
                    ]
                },
            )
        )
        out = capsys.readouterr().out
        assert "d-1" in out
        assert "disable_access_key" in out

    def test_has_next_shows_next_token_hint(self, capsys):
        _run_ir_actions_list(api_response=(200, {"items": [{"detection_id": "d-1"}], "has_next": True, "next_token": "xyz"}))
        out = capsys.readouterr().out
        assert "--next-token" in out
        assert "xyz" in out

    def test_error_status_exits(self):
        with pytest.raises(SystemExit):
            _run_ir_actions_list(api_response=(500, {"message": "boom"}))


# ---------------------------------------------------------------------------
# cmd_ir_actions_get
# ---------------------------------------------------------------------------


def _run_ir_actions_get(detection_id="d-1", *, api_response):
    args = SimpleNamespace(detection_id=detection_id)
    with (
        patch.object(opencdr, "_load_config", return_value={}),
        patch.object(opencdr, "_require_api", return_value=("https://api.example.com", "test-key")),
        patch.object(opencdr, "_request", return_value=api_response) as mock_request,
    ):
        opencdr.cmd_ir_actions_get(args)
    return mock_request


class TestIrActionsGet:
    def test_calls_correct_path(self):
        mock_request = _run_ir_actions_get(api_response=(200, {"detection_id": "d-1"}))
        method, path = mock_request.call_args.args[:2]
        assert method == "GET"
        assert path == "/ir-actions/d-1"

    def test_prints_action_json(self, capsys):
        _run_ir_actions_get(api_response=(200, {"detection_id": "d-1", "response_module": "disable_access_key"}))
        out = capsys.readouterr().out
        assert "d-1" in out
        assert "disable_access_key" in out

    def test_404_exits_1_with_not_found_message(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            _run_ir_actions_get(api_response=(404, {}))
        assert exc_info.value.code == 1
        assert "no ir action recorded" in capsys.readouterr().out.lower()

    def test_other_error_status_exits(self):
        with pytest.raises(SystemExit):
            _run_ir_actions_get(api_response=(500, {"message": "boom"}))


# ---------------------------------------------------------------------------
# cmd_ir_actions_rollback
# ---------------------------------------------------------------------------


def _run_ir_actions_rollback(detection_id="d-1", *, api_response):
    args = SimpleNamespace(detection_id=detection_id)
    with (
        patch.object(opencdr, "_load_config", return_value={}),
        patch.object(opencdr, "_require_api", return_value=("https://api.example.com", "test-key")),
        patch.object(opencdr, "_request", return_value=api_response) as mock_request,
    ):
        opencdr.cmd_ir_actions_rollback(args)
    return mock_request


class TestIrActionsRollback:
    def test_calls_correct_path(self):
        mock_request = _run_ir_actions_rollback(api_response=(202, {"detection_id": "d-1"}))
        method, path = mock_request.call_args.args[:2]
        assert method == "POST"
        assert path == "/ir-actions/d-1/rollback"

    def test_success_prints_enqueued_message(self, capsys):
        _run_ir_actions_rollback(api_response=(202, {"detection_id": "d-1"}))
        out = capsys.readouterr().out
        assert "enqueued" in out.lower()
        assert "d-1" in out

    def test_404_exits_1_with_not_found_message(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            _run_ir_actions_rollback(api_response=(404, {}))
        assert exc_info.value.code == 1
        assert "no ir action recorded" in capsys.readouterr().out.lower()

    def test_400_unsupported_exits_1(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            _run_ir_actions_rollback(api_response=(400, {"message": "Rollback is not supported for this action"}))
        assert exc_info.value.code == 1
        assert "not supported" in capsys.readouterr().out.lower()

    def test_409_already_rolled_back_exits_1(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            _run_ir_actions_rollback(api_response=(409, {"message": "This action has already been rolled back"}))
        assert exc_info.value.code == 1
        assert "already been rolled back" in capsys.readouterr().out.lower()

    def test_other_error_status_exits(self):
        with pytest.raises(SystemExit):
            _run_ir_actions_rollback(api_response=(500, {"message": "boom"}))

"""Tests for `opencdr.py settings get` / `settings delete` (cmd_settings_get, cmd_settings_delete)."""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

import opencdr  # noqa: E402  (after sys.path manipulation)


def _run(func, setting_id="global", *, api_response):
    args = SimpleNamespace(setting_id=setting_id)
    with (
        patch.object(opencdr, "_load_config", return_value={}),
        patch.object(opencdr, "_require_api", return_value=("https://api.example.com", "test-key")),
        patch.object(opencdr, "_request", return_value=api_response) as mock_request,
    ):
        func(args)
    return mock_request


class TestSettingsGet:
    def test_calls_correct_path(self):
        mock_request = _run(opencdr.cmd_settings_get, api_response=(200, {"channels": {}}))
        method, path = mock_request.call_args.args[:2]
        assert method == "GET"
        assert path == "/settings/global"

    def test_uses_custom_setting_id(self):
        mock_request = _run(opencdr.cmd_settings_get, setting_id="custom", api_response=(200, {}))
        path = mock_request.call_args.args[1]
        assert path == "/settings/custom"

    def test_prints_settings_json(self, capsys):
        _run(opencdr.cmd_settings_get, api_response=(200, {"channels": {"slack": {"enabled": True}}}))
        out = capsys.readouterr().out
        assert "slack" in out
        assert "enabled" in out

    def test_404_prints_not_found_does_not_exit(self, capsys):
        # cmd_settings_get returns (not sys.exit) on 404 -- distinct from
        # cmd_rules_get/cmd_lists_show which do exit 1 for the same status.
        _run(opencdr.cmd_settings_get, api_response=(404, {}))
        assert "not found" in capsys.readouterr().out.lower()

    def test_other_error_status_exits(self):
        with pytest.raises(SystemExit):
            _run(opencdr.cmd_settings_get, api_response=(500, {"message": "boom"}))


class TestSettingsDelete:
    def test_calls_correct_path(self):
        mock_request = _run(opencdr.cmd_settings_delete, api_response=(200, {"ok": True}))
        method, path = mock_request.call_args.args[:2]
        assert method == "DELETE"
        assert path == "/settings/global"

    def test_uses_custom_setting_id(self):
        mock_request = _run(opencdr.cmd_settings_delete, setting_id="custom", api_response=(200, {"ok": True}))
        path = mock_request.call_args.args[1]
        assert path == "/settings/custom"

    def test_success_prints_deleted_message(self, capsys):
        _run(opencdr.cmd_settings_delete, setting_id="global", api_response=(200, {"ok": True}))
        out = capsys.readouterr().out
        assert "deleted" in out.lower()
        assert "global" in out

    def test_404_prints_not_found_does_not_exit(self, capsys):
        _run(opencdr.cmd_settings_delete, api_response=(404, {}))
        assert "not found" in capsys.readouterr().out.lower()

    def test_other_error_status_exits(self):
        with pytest.raises(SystemExit):
            _run(opencdr.cmd_settings_delete, api_response=(500, {"message": "boom"}))

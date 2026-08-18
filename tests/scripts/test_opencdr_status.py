"""Tests for `opencdr.py status` (cmd_status)."""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

import opencdr  # noqa: E402  (after sys.path manipulation)


def _run_status(*, api_response=(200, {"service": "OPENCDR-API", "time": "2026-08-14T00:00:00Z", "request_id": "r-1"})):
    with (
        patch.object(opencdr, "_load_config", return_value={}),
        patch.object(opencdr, "_require_api", return_value=("https://api.example.com", "test-key")),
        patch.object(opencdr, "_request", return_value=api_response) as mock_request,
    ):
        opencdr.cmd_status(None)
    return mock_request


class TestStatus:
    def test_calls_status_endpoint(self):
        mock_request = _run_status()
        method, path = mock_request.call_args.args[:2]
        assert method == "GET"
        assert path == "/status"

    def test_prints_service_and_time(self, capsys):
        _run_status()
        out = capsys.readouterr().out
        assert "OPENCDR-API" in out
        assert "2026-08-14T00:00:00Z" in out
        assert "r-1" in out

    def test_missing_fields_default_to_empty(self, capsys):
        _run_status(api_response=(200, {}))
        out = capsys.readouterr().out
        assert "Service" in out
        assert "Time" in out

    def test_error_status_exits(self):
        with pytest.raises(SystemExit) as exc_info:
            _run_status(api_response=(500, {"message": "internal error"}))
        assert exc_info.value.code == 1

    def test_error_status_prints_message(self, capsys):
        with pytest.raises(SystemExit):
            _run_status(api_response=(403, {"message": "forbidden"}))
        out = capsys.readouterr().out
        assert "forbidden" in out.lower()

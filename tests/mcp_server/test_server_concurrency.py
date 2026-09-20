"""
MCP-layer optimistic-concurrency tests: lists add/remove and settings set
round-trip `expected_rev` and compare-and-set retry on a 409; rules upsert
forwards an explicit expected_rev. External HTTP is mocked at
opencdr._request -- no live infra.
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


def _puts(mock_req):
    return [c for c in mock_req.call_args_list if c.args[0] == "PUT"]


def test_lists_add_sends_expected_rev_from_read(api_env):
    def fake(method, path, url, key, **kwargs):
        if method == "GET":
            return 200, {"rule_id": "x", "values": ["a"], "rev": 7}
        return 200, kwargs["json"]

    with patch.object(opencdr, "_request", side_effect=fake) as mock_req:
        server.opencdr_lists_add("x", "b")
    put = _puts(mock_req)[0]
    assert put.kwargs["json"]["expected_rev"] == 7
    assert put.kwargs["json"]["values"] == ["a", "b"]


def test_lists_add_missing_rev_defaults_to_zero(api_env):
    def fake(method, path, url, key, **kwargs):
        if method == "GET":
            return 200, {"rule_id": "x", "values": []}
        return 200, kwargs["json"]

    with patch.object(opencdr, "_request", side_effect=fake) as mock_req:
        server.opencdr_lists_add("x", "b")
    assert _puts(mock_req)[0].kwargs["json"]["expected_rev"] == 0


def test_lists_add_retries_on_409_then_succeeds(api_env):
    calls = {"put": 0, "get": 0}

    def fake(method, path, url, key, **kwargs):
        if method == "GET":
            calls["get"] += 1
            return 200, {"rule_id": "x", "values": ["a"], "rev": calls["get"]}
        calls["put"] += 1
        if calls["put"] == 1:
            return 409, {"message": "rev mismatch"}
        return 200, kwargs["json"]

    with patch.object(opencdr, "_request", side_effect=fake):
        result = server.opencdr_lists_add("x", "b")
    assert calls["put"] == 2  # first PUT 409'd, second succeeded
    assert calls["get"] == 2  # re-read before retry
    assert result["values"] == ["a", "b"]


def test_lists_add_gives_up_after_max_attempts(api_env):
    def fake(method, path, url, key, **kwargs):
        if method == "GET":
            return 200, {"rule_id": "x", "values": ["a"], "rev": 1}
        return 409, {"message": "rev mismatch"}

    with patch.object(opencdr, "_request", side_effect=fake):
        with pytest.raises(RuntimeError, match="modified concurrently"):
            server.opencdr_lists_add("x", "b")


def test_lists_remove_sends_expected_rev(api_env):
    def fake(method, path, url, key, **kwargs):
        if method == "GET":
            return 200, {"rule_id": "x", "values": ["a", "b"], "rev": 3}
        return 200, kwargs["json"]

    with patch.object(opencdr, "_request", side_effect=fake) as mock_req:
        server.opencdr_lists_remove("x", "b")
    put = _puts(mock_req)[0]
    assert put.kwargs["json"]["expected_rev"] == 3
    assert put.kwargs["json"]["values"] == ["a"]


def test_lists_add_noop_does_not_write(api_env):
    def fake(method, path, url, key, **kwargs):
        if method == "GET":
            return 200, {"rule_id": "x", "values": ["a"], "rev": 5}
        pytest.fail("no-op add must not PUT")

    with patch.object(opencdr, "_request", side_effect=fake):
        result = server.opencdr_lists_add("x", "a")
    assert result == {"changed": False, "list_id": "x", "values": ["a"]}


def test_settings_set_sends_expected_rev(api_env):
    def fake(method, path, url, key, **kwargs):
        return 200, kwargs["json"]

    with (
        patch.object(opencdr, "_fetch_existing_settings", return_value=({"rev": 4}, {})),
        patch.object(opencdr, "_request", side_effect=fake) as mock_req,
    ):
        server.opencdr_settings_set(notifications_enabled=False)
    assert mock_req.call_args.kwargs["json"]["expected_rev"] == 4


def test_settings_set_retries_on_409(api_env):
    puts = {"n": 0}

    def fake(method, path, url, key, **kwargs):
        puts["n"] += 1
        if puts["n"] == 1:
            return 409, {"message": "rev mismatch"}
        return 200, kwargs["json"]

    with (
        patch.object(opencdr, "_fetch_existing_settings", return_value=({"rev": 1}, {})),
        patch.object(opencdr, "_request", side_effect=fake),
    ):
        server.opencdr_settings_set(notifications_enabled=True)
    assert puts["n"] == 2


def test_settings_set_gives_up_after_max_attempts(api_env):
    with (
        patch.object(opencdr, "_fetch_existing_settings", return_value=({"rev": 1}, {})),
        patch.object(opencdr, "_request", return_value=(409, {"message": "rev mismatch"})),
    ):
        with pytest.raises(RuntimeError, match="modified concurrently"):
            server.opencdr_settings_set(notifications_enabled=True)


def test_rules_upsert_forwards_expected_rev(api_env):
    with patch.object(opencdr, "_request", return_value=(200, {})) as mock_req:
        server.opencdr_rules_upsert("r1", "signal", {"severity": "LOW"}, expected_rev=9)
    assert mock_req.call_args.kwargs["json"]["expected_rev"] == 9


def test_rules_upsert_omits_expected_rev_by_default(api_env):
    with patch.object(opencdr, "_request", return_value=(200, {})) as mock_req:
        server.opencdr_rules_upsert("r1", "signal", {"severity": "LOW"})
    assert "expected_rev" not in mock_req.call_args.kwargs["json"]

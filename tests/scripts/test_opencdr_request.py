from __future__ import annotations

import json

import pytest

from scripts import opencdr


def _args(*values):
    return opencdr._build_parser().parse_args(["request", *values])


def test_request_calls_arbitrary_relative_route_with_encoded_query(monkeypatch, capsys):
    captured = {}
    monkeypatch.setattr(opencdr, "_load_config", lambda: {})
    monkeypatch.setattr(opencdr, "_require_api", lambda _cfg: ("https://api.example", "secret"))

    def request(method, path, url, key, **kwargs):
        captured.update(method=method, path=path, url=url, key=key, kwargs=kwargs)
        return 200, {"ok": True}

    monkeypatch.setattr(opencdr, "_request", request)
    opencdr.cmd_request(_args("GET", "/rules?rule_kind=signal", "--query", "next_token=a value"))

    assert captured == {
        "method": "GET",
        "path": "/rules?rule_kind=signal&next_token=a+value",
        "url": "https://api.example",
        "key": "secret",
        "kwargs": {},
    }
    assert json.loads(capsys.readouterr().out) == {"ok": True}


def test_request_loads_json_body_from_file(tmp_path, monkeypatch):
    body = tmp_path / "candidate.json"
    body.write_text('{"rule": {"rule_id": "custom"}}')
    captured = {}
    monkeypatch.setattr(opencdr, "_load_config", lambda: {})
    monkeypatch.setattr(opencdr, "_require_api", lambda _cfg: ("https://api.example", "secret"))

    def request(method, path, url, key, **kwargs):
        captured.update(method=method, path=path, kwargs=kwargs)
        return 200, {"valid": True}

    monkeypatch.setattr(opencdr, "_request", request)
    opencdr.cmd_request(_args("POST", "/rules/validate", "--file", str(body)))

    assert captured == {
        "method": "POST",
        "path": "/rules/validate",
        "kwargs": {"json": {"rule": {"rule_id": "custom"}}},
    }


@pytest.mark.parametrize(
    "path",
    ["rules", "https://attacker.example/rules", "//attacker.example/rules", "/rules#fragment"],
)
def test_request_rejects_paths_outside_selected_api(path, monkeypatch):
    monkeypatch.setattr(opencdr, "_require_api", lambda _cfg: pytest.fail("must not fetch key"))
    with pytest.raises(SystemExit) as exc:
        opencdr.cmd_request(_args("GET", path))
    assert exc.value.code == 2


def test_request_rejects_body_for_read_and_delete_methods(monkeypatch):
    monkeypatch.setattr(opencdr, "_require_api", lambda _cfg: pytest.fail("must not fetch key"))
    with pytest.raises(SystemExit) as exc:
        opencdr.cmd_request(_args("GET", "/status", "--data", "{}"))
    assert exc.value.code == 2


def test_request_propagates_api_errors_as_nonzero_exit(monkeypatch):
    monkeypatch.setattr(opencdr, "_load_config", lambda: {})
    monkeypatch.setattr(opencdr, "_require_api", lambda _cfg: ("https://api.example", "secret"))
    monkeypatch.setattr(
        opencdr, "_request", lambda *_args, **_kwargs: (409, {"message": "revision conflict"})
    )
    with pytest.raises(SystemExit) as exc:
        opencdr.cmd_request(_args("PUT", "/rules/custom", "--data", "{}"))
    assert exc.value.code == 1

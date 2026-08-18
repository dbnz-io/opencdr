"""Tests for `opencdr.py config set` / `config show` (cmd_config_set, cmd_config_show)."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

import opencdr  # noqa: E402  (after sys.path manipulation)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_set_args(url=None, key=None) -> SimpleNamespace:
    return SimpleNamespace(url=url, key=key)


@pytest.fixture()
def config_file(tmp_path, monkeypatch):
    """Point CONFIG_FILE at an isolated scratch path -- doesn't exist until _save_config writes it."""
    path = tmp_path / ".opencdr.json"
    monkeypatch.setattr(opencdr, "CONFIG_FILE", path)
    return path


# ---------------------------------------------------------------------------
# cmd_config_set
# ---------------------------------------------------------------------------


class TestConfigSet:
    def test_url_only_writes_url(self, config_file):
        opencdr.cmd_config_set(_make_set_args(url="https://api.example.com"))
        saved = json.loads(config_file.read_text())
        assert saved == {"url": "https://api.example.com"}

    def test_key_only_writes_key(self, config_file):
        opencdr.cmd_config_set(_make_set_args(key="secret-key-123"))
        saved = json.loads(config_file.read_text())
        assert saved == {"key": "secret-key-123"}

    def test_both_writes_both(self, config_file):
        opencdr.cmd_config_set(_make_set_args(url="https://api.example.com", key="secret-key-123"))
        saved = json.loads(config_file.read_text())
        assert saved == {"url": "https://api.example.com", "key": "secret-key-123"}

    def test_neither_exits_1(self, config_file, capsys):
        with pytest.raises(SystemExit) as exc_info:
            opencdr.cmd_config_set(_make_set_args())
        assert exc_info.value.code == 1
        assert "url" in capsys.readouterr().out.lower()
        assert not config_file.exists()

    def test_partial_update_preserves_existing_field(self, config_file):
        config_file.write_text(json.dumps({"url": "https://old.example.com", "key": "old-key"}))
        opencdr.cmd_config_set(_make_set_args(key="new-key"))
        saved = json.loads(config_file.read_text())
        assert saved == {"url": "https://old.example.com", "key": "new-key"}

    def test_success_message_shows_key_preview_not_full_key(self, config_file, capsys):
        opencdr.cmd_config_set(_make_set_args(key="abcdefghijklmnop"))
        out = capsys.readouterr().out
        assert "abcdefgh" in out
        assert "abcdefghijklmnop" not in out

    def test_success_prints_saved_confirmation(self, config_file, capsys):
        opencdr.cmd_config_set(_make_set_args(url="https://api.example.com"))
        assert "saved" in capsys.readouterr().out.lower()


# ---------------------------------------------------------------------------
# cmd_config_show
# ---------------------------------------------------------------------------


class TestConfigShow:
    def test_no_config_file_prints_not_found(self, config_file, capsys):
        opencdr.cmd_config_show(SimpleNamespace())
        out = capsys.readouterr().out
        assert "no config found" in out.lower()

    def test_shows_url_and_key_preview(self, config_file, capsys):
        config_file.write_text(json.dumps({"url": "https://api.example.com", "key": "abcdefghijklmnop"}))
        opencdr.cmd_config_show(SimpleNamespace())
        out = capsys.readouterr().out
        assert "https://api.example.com" in out
        assert "abcdefgh" in out
        assert "abcdefghijklmnop" not in out

    def test_missing_key_shows_not_set(self, config_file, capsys):
        config_file.write_text(json.dumps({"url": "https://api.example.com"}))
        opencdr.cmd_config_show(SimpleNamespace())
        out = capsys.readouterr().out
        assert "not set" in out.lower()

    def test_missing_url_shows_not_set(self, config_file, capsys):
        config_file.write_text(json.dumps({"key": "abcdefghijklmnop"}))
        opencdr.cmd_config_show(SimpleNamespace())
        out = capsys.readouterr().out
        assert "not set" in out.lower()


# ---------------------------------------------------------------------------
# _load_config / _save_config round trip
# ---------------------------------------------------------------------------


class TestLoadSaveConfigRoundTrip:
    def test_load_returns_empty_dict_when_file_absent(self, config_file):
        assert opencdr._load_config() == {}

    def test_save_then_load_round_trips(self, config_file):
        opencdr._save_config({"url": "https://api.example.com", "key": "k"})
        assert opencdr._load_config() == {"url": "https://api.example.com", "key": "k"}


# ---------------------------------------------------------------------------
# _require_api -- env vars take precedence over config file
# ---------------------------------------------------------------------------


class TestRequireApi:
    def test_env_vars_override_config_file(self, monkeypatch):
        monkeypatch.setenv("OPENCDR_API_URL", "https://from-env.example.com")
        monkeypatch.setenv("OPENCDR_API_KEY", "env-key")
        url, key = opencdr._require_api({"url": "https://from-file.example.com", "key": "file-key"})
        assert url == "https://from-env.example.com"
        assert key == "env-key"

    def test_falls_back_to_config_file_when_no_env_vars(self, monkeypatch):
        monkeypatch.delenv("OPENCDR_API_URL", raising=False)
        monkeypatch.delenv("OPENCDR_API_KEY", raising=False)
        url, key = opencdr._require_api({"url": "https://from-file.example.com/", "key": "file-key"})
        assert url == "https://from-file.example.com"  # trailing slash stripped
        assert key == "file-key"

    def test_missing_both_exits_1(self, monkeypatch, capsys):
        monkeypatch.delenv("OPENCDR_API_URL", raising=False)
        monkeypatch.delenv("OPENCDR_API_KEY", raising=False)
        with pytest.raises(SystemExit) as exc_info:
            opencdr._require_api({})
        assert exc_info.value.code == 1
        out = capsys.readouterr().out
        assert "url" in out.lower()
        assert "key" in out.lower()

    def test_missing_only_key_reports_key(self, monkeypatch, capsys):
        monkeypatch.delenv("OPENCDR_API_URL", raising=False)
        monkeypatch.delenv("OPENCDR_API_KEY", raising=False)
        with pytest.raises(SystemExit):
            opencdr._require_api({"url": "https://api.example.com"})
        out = capsys.readouterr().out
        assert "key" in out.lower()

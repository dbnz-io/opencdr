"""Tests for `opencdr.py setup` -- the interactive wizard.

Not exhaustive over every one of the 6 notification-channel prompts (they
all follow the identical confirm-then-prompt-then-validate pattern) --
covers the pure helpers directly, one full happy-path run (fresh install,
Slack only), the "decline everything" path, and the one channel with
genuinely different validation logic (Jira's all-four-fields-required rule).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

import opencdr  # noqa: E402  (after sys.path manipulation)


# ---------------------------------------------------------------------------
# _prompt / _confirm / _step -- pure(ish) helpers
# ---------------------------------------------------------------------------


class TestPrompt:
    def test_returns_typed_value(self):
        with patch("builtins.input", return_value="typed-value"):
            assert opencdr._prompt("Enter something") == "typed-value"

    def test_empty_input_returns_default(self):
        with patch("builtins.input", return_value=""):
            assert opencdr._prompt("Enter something", default="fallback") == "fallback"

    def test_secret_uses_getpass_not_input(self):
        with (
            patch("getpass.getpass", return_value="hidden-value") as mock_getpass,
            patch("builtins.input", side_effect=AssertionError("should not call input() for a secret prompt")),
        ):
            assert opencdr._prompt("API key", secret=True) == "hidden-value"
            mock_getpass.assert_called_once()

    def test_keyboard_interrupt_propagates(self):
        with patch("builtins.input", side_effect=KeyboardInterrupt):
            with pytest.raises(KeyboardInterrupt):
                opencdr._prompt("Enter something")


class TestConfirm:
    def test_yes_returns_true(self):
        with patch("builtins.input", return_value="y"):
            assert opencdr._confirm("Proceed?") is True

    def test_no_returns_false(self):
        with patch("builtins.input", return_value="n"):
            assert opencdr._confirm("Proceed?") is False

    def test_empty_input_returns_default_true(self):
        with patch("builtins.input", return_value=""):
            assert opencdr._confirm("Proceed?", default=True) is True

    def test_empty_input_returns_default_false(self):
        with patch("builtins.input", return_value=""):
            assert opencdr._confirm("Proceed?", default=False) is False

    def test_full_word_yes_accepted(self):
        with patch("builtins.input", return_value="yes"):
            assert opencdr._confirm("Proceed?", default=False) is True

    def test_garbage_input_treated_as_no(self):
        with patch("builtins.input", return_value="whatever"):
            assert opencdr._confirm("Proceed?", default=True) is False


# ---------------------------------------------------------------------------
# _prompt_api_credentials
# ---------------------------------------------------------------------------


@pytest.fixture()
def config_file(tmp_path, monkeypatch):
    path = tmp_path / ".opencdr.json"
    monkeypatch.setattr(opencdr, "CONFIG_FILE", path)
    return path


class TestPromptApiCredentials:
    def test_saves_url_and_key_to_config(self, config_file):
        with (
            patch("builtins.input", return_value="https://api.example.com"),
            patch("getpass.getpass", return_value="test-key"),
        ):
            url, key = opencdr._prompt_api_credentials({})
        assert url == "https://api.example.com"
        assert key == "test-key"
        assert json.loads(config_file.read_text()) == {"url": "https://api.example.com", "key": "test-key"}

    def test_trailing_slash_stripped(self, config_file):
        with (
            patch("builtins.input", return_value="https://api.example.com/"),
            patch("getpass.getpass", return_value="test-key"),
        ):
            url, _ = opencdr._prompt_api_credentials({})
        assert url == "https://api.example.com"

    def test_missing_url_exits_1(self, config_file, capsys):
        with patch("builtins.input", return_value=""):
            with pytest.raises(SystemExit) as exc_info:
                opencdr._prompt_api_credentials({})
        assert exc_info.value.code == 1
        assert "url" in capsys.readouterr().out.lower()

    def test_missing_key_exits_1(self, config_file, capsys):
        with (
            patch("builtins.input", return_value="https://api.example.com"),
            patch("getpass.getpass", return_value=""),
        ):
            with pytest.raises(SystemExit) as exc_info:
                opencdr._prompt_api_credentials({})
        assert exc_info.value.code == 1
        assert "key" in capsys.readouterr().out.lower()

    def test_non_http_url_warns_but_still_saves(self, config_file, capsys):
        with (
            patch("builtins.input", return_value="not-a-url"),
            patch("getpass.getpass", return_value="test-key"),
        ):
            url, key = opencdr._prompt_api_credentials({})
        assert url == "not-a-url"
        assert "warning" in capsys.readouterr().out.lower()


# ---------------------------------------------------------------------------
# _run_setup_wizard -- representative end-to-end paths
# ---------------------------------------------------------------------------


@pytest.fixture()
def wizard_dirs(tmp_path, monkeypatch):
    """Empty RULES_DIR so the rule-loading confirm short-circuits (rule_files
    is empty, `if rule_files and _confirm(...)` never calls _confirm at all)
    -- keeps the scripted input()/getpass() sequence for the tests below
    independent of how many real rule files happen to exist in the repo."""
    rules_dir = tmp_path / "detection_rules"
    rules_dir.mkdir()
    monkeypatch.setattr(opencdr, "RULES_DIR", rules_dir)
    monkeypatch.setattr(opencdr, "ROOT", tmp_path)
    path = tmp_path / ".opencdr.json"
    monkeypatch.setattr(opencdr, "CONFIG_FILE", path)
    return path


def _run_wizard(*, inputs: list[str], secrets: list[str], status_response=(200, {"service": "OPENCDR-API"}), settings_response=(200, {"ok": True})):
    request_calls = []

    def fake_request(method, path, url, key, **kwargs):
        request_calls.append((method, path, kwargs.get("json")))
        if path == "/status":
            return status_response
        return settings_response

    with (
        patch("builtins.input", side_effect=inputs),
        patch("getpass.getpass", side_effect=secrets),
        patch.object(opencdr, "_request", side_effect=fake_request),
    ):
        opencdr._run_setup_wizard()
    return request_calls


class TestRunSetupWizardFreshInstall:
    def test_slack_only_saves_correct_payload(self, wizard_dirs, capsys):
        calls = _run_wizard(
            inputs=[
                "https://api.example.com",  # API base URL
                "y",   # Configure Slack?
                "n",   # Configure Discord?
                "n",   # Configure email?
                "n",   # Configure Jira?
                "n",   # Configure Security Hub?
                "n",   # Configure custom webhook?
            ],
            secrets=["test-api-key", "https://hooks.slack.com/test"],
        )

        put_calls = [c for c in calls if c[0] == "PUT" and c[1] == "/settings/global"]
        assert len(put_calls) == 1
        payload = put_calls[0][2]
        assert payload["channels"]["slack"] == {"enabled": True, "webhook_url": "https://hooks.slack.com/test"}
        assert payload["notifications_enabled"] is True
        assert "setup complete" in capsys.readouterr().out.lower()

    def test_declining_every_channel_makes_no_settings_put(self, wizard_dirs, capsys):
        calls = _run_wizard(
            inputs=[
                "https://api.example.com",
                "n", "n", "n", "n", "n", "n",  # decline all 6 channels
            ],
            secrets=["test-api-key"],
        )
        put_calls = [c for c in calls if c[0] == "PUT" and c[1] == "/settings/global"]
        assert put_calls == []
        assert "skipped" in capsys.readouterr().out.lower()

    def test_connection_failure_exits_1(self, wizard_dirs):
        with pytest.raises(SystemExit) as exc_info:
            _run_wizard(
                inputs=["https://api.example.com"],
                secrets=["test-api-key"],
                status_response=(500, {"message": "internal error"}),
            )
        assert exc_info.value.code == 1

    def test_jira_partial_fields_skipped_with_warning(self, wizard_dirs, capsys):
        # Jira's 4 fields: base_url/project/email are plain _prompt() calls
        # (input()), only the API token is secret (getpass()) -- leaving
        # the token blank exercises the "all four required" validation.
        calls = _run_wizard(
            inputs=[
                "https://api.example.com",   # API base URL
                "n",                         # Slack
                "n",                         # Discord
                "n",                         # Email
                "y",                         # Jira -- yes
                "https://yourco.atlassian.net",  # jira base URL
                "SEC",                        # jira project key
                "soc@yourco.com",             # jira user email
                "n",                          # Security Hub
                "n",                          # Custom webhook
            ],
            secrets=[
                "test-api-key",
                "",  # jira token left blank -> partial fields, should skip
            ],
        )
        put_calls = [c for c in calls if c[0] == "PUT" and c[1] == "/settings/global"]
        assert put_calls == []
        assert "all four" in capsys.readouterr().out.lower()

"""Tests for settings-secret resolution in notifier.py (Phase 2): secrets
are stored as `ssm:` references (src/domain/settings_secrets.py), not
plaintext, and load_global_settings must resolve them back to real values
in place so every existing per-channel read site needs no changes.
"""
from __future__ import annotations

import os
from unittest.mock import MagicMock

import pytest

os.environ.setdefault("LOGS_TABLE_NAME", "test-logs-table")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

import src.handlers.notifier as notifier
from src.handlers.notifier import _resolve_secret_refs, load_global_settings


def _ddb_item(d: dict) -> dict:
    """Marshals a plain dict into the low-level DynamoDB AttributeValue
    shape load_global_settings expects back from aws._ddb.get_item."""
    def marshal(v):
        if isinstance(v, bool):
            return {"BOOL": v}
        if isinstance(v, str):
            return {"S": v}
        if isinstance(v, dict):
            return {"M": {k: marshal(val) for k, val in v.items()}}
        if isinstance(v, list):
            return {"L": [marshal(x) for x in v]}
        raise TypeError(type(v))

    return {k: marshal(v) for k, v in d.items()}


@pytest.fixture(autouse=True)
def reset_settings_cache(monkeypatch):
    monkeypatch.setattr(notifier, "_cached_settings", None)
    monkeypatch.setattr(notifier, "_cached_settings_loaded_at", 0.0)
    monkeypatch.setattr(notifier, "SETTINGS_TABLE_NAME", "test-settings-table")


class TestResolveSecretRefsHelper:
    def test_resolves_ssm_ref_to_real_value(self):
        aws = MagicMock()
        aws.ssm_get_secure_param.return_value = "https://hooks.slack.com/real"
        settings = {"channels": {"slack": {"webhook_url": "ssm:/opencdr-dev/settings/global/slack/webhook_url"}}}

        _resolve_secret_refs(settings, aws=aws)

        assert settings["channels"]["slack"]["webhook_url"] == "https://hooks.slack.com/real"
        aws.ssm_get_secure_param.assert_called_once_with(name="/opencdr-dev/settings/global/slack/webhook_url")

    def test_leaves_non_ref_values_untouched(self):
        aws = MagicMock()
        settings = {"channels": {"slack": {"webhook_url": "https://hooks.slack.com/plain"}}}

        _resolve_secret_refs(settings, aws=aws)

        assert settings["channels"]["slack"]["webhook_url"] == "https://hooks.slack.com/plain"
        aws.ssm_get_secure_param.assert_not_called()

    def test_missing_param_resolves_to_empty_string(self):
        aws = MagicMock()
        aws.ssm_get_secure_param.return_value = None
        settings = {"channels": {"jira": {"api_token": "ssm:/opencdr-dev/settings/global/jira/api_token"}}}

        _resolve_secret_refs(settings, aws=aws)

        assert settings["channels"]["jira"]["api_token"] == ""

    def test_resolves_webhook_target_header_refs(self):
        aws = MagicMock()
        aws.ssm_get_secure_param.return_value = "Bearer real-token"
        settings = {
            "channels": {
                "webhook": {
                    "targets": [
                        {"headers": {"Authorization": "ssm:/opencdr-dev/settings/global/webhook/targets/0/headers/Authorization"}}
                    ]
                }
            }
        }

        _resolve_secret_refs(settings, aws=aws)

        assert settings["channels"]["webhook"]["targets"][0]["headers"]["Authorization"] == "Bearer real-token"


class TestLoadGlobalSettingsResolvesSecrets:
    def test_load_resolves_ssm_ref_before_caching(self):
        aws = MagicMock()
        aws._ddb.get_item.return_value = {
            "Item": _ddb_item(
                {
                    "setting_id": "global",
                    "channels": {
                        "slack": {"enabled": True, "webhook_url": "ssm:/opencdr-dev/settings/global/slack/webhook_url"}
                    },
                }
            )
        }
        aws.ssm_get_secure_param.return_value = "https://hooks.slack.com/resolved"
        logger = MagicMock()

        settings = load_global_settings(aws=aws, logger=logger)

        assert settings["channels"]["slack"]["webhook_url"] == "https://hooks.slack.com/resolved"

    def test_cached_settings_do_not_re_resolve_within_ttl(self):
        aws = MagicMock()
        aws._ddb.get_item.return_value = {
            "Item": _ddb_item(
                {
                    "setting_id": "global",
                    "channels": {
                        "slack": {"enabled": True, "webhook_url": "ssm:/opencdr-dev/settings/global/slack/webhook_url"}
                    },
                }
            )
        }
        aws.ssm_get_secure_param.return_value = "https://hooks.slack.com/resolved"
        logger = MagicMock()

        load_global_settings(aws=aws, logger=logger)
        load_global_settings(aws=aws, logger=logger)

        aws.ssm_get_secure_param.assert_called_once()

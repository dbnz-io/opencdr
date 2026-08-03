"""Tests for src/domain/settings_secrets.py -- the shared `ssm:` reference
convention used by both api.py (write path) and notifier.py (read path)
for indirecting settings secrets through SSM Parameter Store."""
from __future__ import annotations

from src.domain.settings_secrets import (
    is_ssm_ref,
    iter_secret_locations,
    ssm_param_name,
    ssm_ref,
    ssm_ref_param_name,
)


class TestIsSsmRef:
    def test_true_for_ssm_prefixed_string(self):
        assert is_ssm_ref("ssm:/opencdr-dev/settings/global/slack/webhook_url")

    def test_false_for_plain_string(self):
        assert not is_ssm_ref("https://hooks.slack.com/real")

    def test_false_for_non_string(self):
        assert not is_ssm_ref(None)
        assert not is_ssm_ref(123)
        assert not is_ssm_ref({"a": 1})


class TestSsmParamNameAndRef:
    def test_ssm_param_name_uses_stage_env_var(self, monkeypatch):
        monkeypatch.setenv("STAGE", "prod")
        assert ssm_param_name("global", "slack", "webhook_url") == "/opencdr-prod/settings/global/slack/webhook_url"

    def test_ssm_param_name_defaults_to_dev(self, monkeypatch):
        monkeypatch.delenv("STAGE", raising=False)
        assert ssm_param_name("global", "jira", "api_token") == "/opencdr-dev/settings/global/jira/api_token"

    def test_ref_round_trips_param_name(self):
        name = "/opencdr-dev/settings/global/slack/webhook_url"
        assert ssm_ref_param_name(ssm_ref(name)) == name


class TestIterSecretLocations:
    def test_yields_static_channel_fields_when_channel_dict_present(self):
        """A location is yielded whenever the channel dict itself exists
        (so the write path can populate a field that isn't set yet);
        `email` isn't a secret channel at all and is never yielded."""
        channels = {
            "slack": {"enabled": True, "webhook_url": "https://hooks.slack.com/x"},
            "discord": {"enabled": False},
            "jira": {"enabled": True, "api_token": "tok"},
            "email": {"enabled": True},
        }
        locations = iter_secret_locations(channels)
        found_channels = {path[0] for _, _, path in locations}
        assert found_channels == {"slack", "discord", "jira"}

    def test_yields_dynamic_webhook_target_headers(self):
        channels = {
            "webhook": {
                "targets": [
                    {"headers": {"Authorization": "Bearer x", "X-Api-Key": "y"}},
                    {"headers": {}},
                    "not-a-dict",
                ]
            }
        }
        locations = iter_secret_locations(channels)
        paths = {path for _, _, path in locations}
        assert ("webhook", "targets", "0", "headers", "Authorization") in paths
        assert ("webhook", "targets", "0", "headers", "X-Api-Key") in paths
        assert len(paths) == 2

    def test_non_dict_channels_returns_empty(self):
        assert iter_secret_locations(None) == []
        assert iter_secret_locations("not-a-dict") == []

    def test_container_and_key_resolve_back_to_the_value(self):
        channels = {"slack": {"webhook_url": "https://hooks.slack.com/x"}}
        (container, key, path) = iter_secret_locations(channels)[0]
        assert container[key] == "https://hooks.slack.com/x"
        assert path == ("slack", "webhook_url")

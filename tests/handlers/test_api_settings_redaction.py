"""Focused tests for settings-secret redaction (src/handlers/api.py).

Covers the Phase 0 fix: GET /settings must never return plaintext
integration secrets (Slack/Discord webhook URLs, Jira API tokens, custom
webhook headers), while POST/PUT continue to round-trip the caller's own
write unredacted.
"""
from __future__ import annotations

import json
import os
from unittest.mock import MagicMock, patch

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

from src.handlers import api


def make_event(method: str, path: str, *, path_params=None, body=None) -> dict:
    return {
        "httpMethod": method,
        "path": path,
        "queryStringParameters": None,
        "pathParameters": path_params,
        "body": body,
        "isBase64Encoded": False,
    }


def make_context():
    ctx = MagicMock()
    ctx.aws_request_id = "test-req-id"
    return ctx


def body_of(resp: dict) -> dict:
    return json.loads(resp["body"])


class TestRedactSettingsHelper:
    def test_masks_known_secret_fields(self):
        item = {
            "setting_id": "global",
            "channels": {
                "slack": {"enabled": True, "webhook_url": "https://hooks.slack.com/secret"},
                "discord": {"enabled": True, "webhook_url": "https://discord.com/api/webhooks/x"},
                "jira": {
                    "enabled": True,
                    "api_token": "super-secret-token",
                    "user_email": "ops@example.com",
                    "base_url": "https://example.atlassian.net",
                },
            },
        }
        redacted = api._redact_settings(item)
        assert redacted["channels"]["slack"]["webhook_url"] == api._REDACTED
        assert redacted["channels"]["discord"]["webhook_url"] == api._REDACTED
        assert redacted["channels"]["jira"]["api_token"] == api._REDACTED
        # non-secret jira fields pass through untouched
        assert redacted["channels"]["jira"]["user_email"] == "ops@example.com"
        assert redacted["channels"]["jira"]["base_url"] == "https://example.atlassian.net"

    def test_masks_webhook_target_headers(self):
        item = {
            "setting_id": "global",
            "channels": {
                "webhook": {
                    "enabled": True,
                    "targets": [
                        {
                            "name": "internal",
                            "url": "https://example.com/hook",
                            "headers": {"Authorization": "Bearer abc123"},
                        }
                    ],
                }
            },
        }
        redacted = api._redact_settings(item)
        target = redacted["channels"]["webhook"]["targets"][0]
        assert target["headers"]["Authorization"] == api._REDACTED
        # url itself is not treated as a secret
        assert target["url"] == "https://example.com/hook"

    def test_does_not_mutate_input(self):
        item = {
            "setting_id": "global",
            "channels": {"slack": {"webhook_url": "https://hooks.slack.com/secret"}},
        }
        api._redact_settings(item)
        assert item["channels"]["slack"]["webhook_url"] == "https://hooks.slack.com/secret"

    def test_missing_channels_key_does_not_error(self):
        item = {"setting_id": "global"}
        assert api._redact_settings(item) == item

    def test_empty_secret_value_left_as_is(self):
        item = {"setting_id": "global", "channels": {"slack": {"webhook_url": ""}}}
        redacted = api._redact_settings(item)
        assert redacted["channels"]["slack"]["webhook_url"] == ""


class TestGetSettingsEndpointRedaction:
    def test_get_global_settings_redacts_secrets(self):
        stored = {
            "setting_id": "global",
            "channels": {
                "slack": {"enabled": True, "webhook_url": "https://hooks.slack.com/secret"},
                "jira": {"enabled": True, "api_token": "super-secret-token"},
            },
        }
        with patch.object(api, "settings_table") as mock_table:
            mock_table.get_item.return_value = {"Item": stored}
            resp = api.lambda_handler(make_event("GET", "/settings"), make_context())
        assert resp["statusCode"] == 200
        body = body_of(resp)
        assert body["channels"]["slack"]["webhook_url"] == api._REDACTED
        assert body["channels"]["jira"]["api_token"] == api._REDACTED

    def test_get_settings_by_id_redacts_secrets(self):
        stored = {
            "setting_id": "team-a",
            "channels": {"discord": {"enabled": True, "webhook_url": "https://discord.com/api/webhooks/y"}},
        }
        with patch.object(api, "settings_table") as mock_table:
            mock_table.get_item.return_value = {"Item": stored}
            resp = api.lambda_handler(
                make_event("GET", "/settings/team-a", path_params={"setting_id": "team-a"}), make_context()
            )
        assert resp["statusCode"] == 200
        body = body_of(resp)
        assert body["channels"]["discord"]["webhook_url"] == api._REDACTED


class TestWriteSettingsEndpointsExternalizeSecretsToSsm:
    """Secrets are no longer stored in DynamoDB at all (Phase 2): POST/PUT
    now write the real value through to SSM Parameter Store and store only
    an `ssm:` reference -- so even the caller's own write no longer sees
    the raw secret reflected back, unlike the earlier plaintext-storage
    design this replaces."""

    def test_post_settings_externalizes_secret_to_ssm(self):
        payload = {"channels": {"slack": {"enabled": True, "webhook_url": "https://hooks.slack.com/new"}}}
        with patch.object(api, "settings_table") as mock_table, patch.object(api, "ssm") as mock_ssm:
            resp = api.lambda_handler(
                make_event("POST", "/settings", body=json.dumps(payload)), make_context()
            )
        assert resp["statusCode"] == 201
        body = body_of(resp)
        ref = body["channels"]["slack"]["webhook_url"]
        assert ref.startswith("ssm:/opencdr-")
        assert "/settings/global/slack/webhook_url" in ref

        mock_ssm.put_parameter.assert_called_once()
        put_kwargs = mock_ssm.put_parameter.call_args.kwargs
        assert put_kwargs["Value"] == "https://hooks.slack.com/new"
        assert put_kwargs["Type"] == "SecureString"

        mock_table.put_item.assert_called_once()
        stored_item = mock_table.put_item.call_args.kwargs["Item"]
        assert stored_item["channels"]["slack"]["webhook_url"] == ref

    def test_put_settings_externalizes_secret_to_ssm(self):
        payload = {"channels": {"jira": {"enabled": True, "api_token": "brand-new-token"}}}
        with patch.object(api, "settings_table") as mock_table, patch.object(api, "ssm") as mock_ssm:
            resp = api.lambda_handler(
                make_event(
                    "PUT", "/settings/team-a", path_params={"setting_id": "team-a"}, body=json.dumps(payload)
                ),
                make_context(),
            )
        assert resp["statusCode"] == 200
        body = body_of(resp)
        ref = body["channels"]["jira"]["api_token"]
        assert ref.startswith("ssm:/opencdr-")
        assert "/settings/team-a/jira/api_token" in ref

        mock_ssm.put_parameter.assert_called_once()
        assert mock_ssm.put_parameter.call_args.kwargs["Value"] == "brand-new-token"

    def test_put_settings_does_not_rewrite_an_existing_ssm_ref(self):
        """A payload that already holds an ssm: reference (e.g. a client
        echoing back a prior GET without knowing to supply the real value)
        is left alone rather than treated as a new secret to store."""
        existing_ref = "ssm:/opencdr-dev/settings/team-a/jira/api_token"
        payload = {"channels": {"jira": {"enabled": True, "api_token": existing_ref}}}
        with patch.object(api, "settings_table"), patch.object(api, "ssm") as mock_ssm:
            resp = api.lambda_handler(
                make_event(
                    "PUT", "/settings/team-a", path_params={"setting_id": "team-a"}, body=json.dumps(payload)
                ),
                make_context(),
            )
        assert resp["statusCode"] == 200
        assert body_of(resp)["channels"]["jira"]["api_token"] == existing_ref
        mock_ssm.put_parameter.assert_not_called()

    def test_empty_secret_value_is_not_sent_to_ssm(self):
        payload = {"channels": {"slack": {"enabled": False, "webhook_url": ""}}}
        with patch.object(api, "settings_table"), patch.object(api, "ssm") as mock_ssm:
            resp = api.lambda_handler(
                make_event("POST", "/settings", body=json.dumps(payload)), make_context()
            )
        assert resp["statusCode"] == 201
        assert body_of(resp)["channels"]["slack"]["webhook_url"] == ""
        mock_ssm.put_parameter.assert_not_called()


class TestRedactedRoundTripDoesNotCorruptSecrets:
    """A client that GETs settings (secrets masked to _REDACTED), edits one
    channel, and PUTs the whole document back -- exactly what
    scripts/opencdr.py's settings set already does, and what a UI editing
    one channel at a time must do too -- must not have untouched channels'
    _REDACTED sentinel treated as a brand new real secret."""

    def test_redacted_sentinel_preserves_existing_ssm_ref(self):
        existing_ref = "ssm:/opencdr-dev/settings/team-a/slack/webhook_url"
        stored = {"setting_id": "team-a", "channels": {"slack": {"enabled": True, "webhook_url": existing_ref}}}
        payload = {"channels": {"slack": {"enabled": True, "webhook_url": api._REDACTED}}}
        with patch.object(api, "settings_table") as mock_table, patch.object(api, "ssm") as mock_ssm:
            mock_table.get_item.return_value = {"Item": stored}
            resp = api.lambda_handler(
                make_event(
                    "PUT", "/settings/team-a", path_params={"setting_id": "team-a"}, body=json.dumps(payload)
                ),
                make_context(),
            )
        assert resp["statusCode"] == 200
        assert body_of(resp)["channels"]["slack"]["webhook_url"] == existing_ref
        mock_ssm.put_parameter.assert_not_called()

    def test_untouched_channel_redacted_sentinel_preserved_while_editing_another(self):
        """The realistic case: editing jira while slack, already configured,
        is round-tripped untouched -- slack's real ssm ref must survive."""
        slack_ref = "ssm:/opencdr-dev/settings/team-a/slack/webhook_url"
        stored = {
            "setting_id": "team-a",
            "channels": {
                "slack": {"enabled": True, "webhook_url": slack_ref},
                "jira": {"enabled": True, "api_token": "ssm:/opencdr-dev/settings/team-a/jira/api_token"},
            },
        }
        payload = {
            "channels": {
                "slack": {"enabled": True, "webhook_url": api._REDACTED},
                "jira": {"enabled": True, "api_token": "brand-new-token"},
            }
        }
        with patch.object(api, "settings_table") as mock_table, patch.object(api, "ssm") as mock_ssm:
            mock_table.get_item.return_value = {"Item": stored}
            resp = api.lambda_handler(
                make_event(
                    "PUT", "/settings/team-a", path_params={"setting_id": "team-a"}, body=json.dumps(payload)
                ),
                make_context(),
            )
        assert resp["statusCode"] == 200
        body = body_of(resp)
        assert body["channels"]["slack"]["webhook_url"] == slack_ref
        assert body["channels"]["jira"]["api_token"].startswith("ssm:")
        mock_ssm.put_parameter.assert_called_once()
        assert mock_ssm.put_parameter.call_args.kwargs["Value"] == "brand-new-token"

    def test_redacted_sentinel_with_no_existing_document_clears_to_empty(self):
        payload = {"channels": {"slack": {"enabled": True, "webhook_url": api._REDACTED}}}
        with patch.object(api, "settings_table") as mock_table, patch.object(api, "ssm") as mock_ssm:
            mock_table.get_item.return_value = {}
            resp = api.lambda_handler(
                make_event("POST", "/settings", body=json.dumps(payload)), make_context()
            )
        assert resp["statusCode"] == 201
        assert body_of(resp)["channels"]["slack"]["webhook_url"] == ""
        mock_ssm.put_parameter.assert_not_called()

    def test_no_redacted_sentinel_skips_the_extra_get_item(self):
        payload = {"channels": {"slack": {"enabled": True, "webhook_url": "https://hooks.slack.com/new"}}}
        with patch.object(api, "settings_table") as mock_table, patch.object(api, "ssm"):
            resp = api.lambda_handler(
                make_event("POST", "/settings", body=json.dumps(payload)), make_context()
            )
        assert resp["statusCode"] == 201
        mock_table.get_item.assert_not_called()


class TestDeleteSettingsCleansUpSsmRefs:
    def test_delete_removes_referenced_ssm_params(self):
        stored = {
            "setting_id": "team-a",
            "channels": {
                "slack": {"webhook_url": "ssm:/opencdr-dev/settings/team-a/slack/webhook_url"},
                "jira": {"api_token": "ssm:/opencdr-dev/settings/team-a/jira/api_token"},
            },
        }
        with patch.object(api, "settings_table") as mock_table, patch.object(api, "ssm") as mock_ssm:
            mock_table.get_item.return_value = {"Item": stored}
            resp = api.lambda_handler(
                make_event("DELETE", "/settings/team-a", path_params={"setting_id": "team-a"}), make_context()
            )
        assert resp["statusCode"] == 200
        mock_ssm.delete_parameters.assert_called_once_with(
            Names=[
                "/opencdr-dev/settings/team-a/slack/webhook_url",
                "/opencdr-dev/settings/team-a/jira/api_token",
            ]
        )

    def test_delete_with_no_secrets_skips_ssm_call(self):
        stored = {"setting_id": "team-a", "channels": {"email": {"enabled": True}}}
        with patch.object(api, "settings_table") as mock_table, patch.object(api, "ssm") as mock_ssm:
            mock_table.get_item.return_value = {"Item": stored}
            resp = api.lambda_handler(
                make_event("DELETE", "/settings/team-a", path_params={"setting_id": "team-a"}), make_context()
            )
        assert resp["statusCode"] == 200
        mock_ssm.delete_parameters.assert_not_called()

    def test_delete_swallows_ssm_cleanup_failure(self):
        stored = {
            "setting_id": "team-a",
            "channels": {"slack": {"webhook_url": "ssm:/opencdr-dev/settings/team-a/slack/webhook_url"}},
        }
        with patch.object(api, "settings_table") as mock_table, patch.object(api, "ssm") as mock_ssm:
            mock_table.get_item.return_value = {"Item": stored}
            mock_ssm.delete_parameters.side_effect = RuntimeError("SSM unavailable")
            resp = api.lambda_handler(
                make_event("DELETE", "/settings/team-a", path_params={"setting_id": "team-a"}), make_context()
            )
        assert resp["statusCode"] == 200

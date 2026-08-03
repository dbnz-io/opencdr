"""Tests for the REST API handler (src/handlers/api.py).

These are characterization tests: they lock in *current* behavior (including
known gaps such as no semantic rule validation and a repr(e) leak on 500s)
so future fixes to those gaps show up as deliberate, visible diffs here
rather than silent regressions. GET /settings redaction is covered here
(TestSettingsCrud.test_get_settings_redacts_credentials) and further in
tests/handlers/test_api_settings_redaction.py.
"""
from __future__ import annotations

import base64
import json
import os
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

from src.handlers import api


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_event(method: str, path: str, *, qs=None, path_params=None, body=None, is_base64=False) -> dict:
    return {
        "httpMethod": method,
        "path": path,
        "queryStringParameters": qs,
        "pathParameters": path_params,
        "body": body,
        "isBase64Encoded": is_base64,
    }


def make_context():
    ctx = MagicMock()
    ctx.aws_request_id = "test-req-id"
    return ctx


def body_of(resp: dict) -> dict:
    return json.loads(resp["body"])


def conditional_check_failed() -> ClientError:
    return ClientError(
        {"Error": {"Code": "ConditionalCheckFailedException", "Message": "condition failed"}},
        "PutItem",
    )


VALID_RULE_BODY = {
    "rule_kind": "signal",
    "description": "test rule",
    "severity": "high",
    "conditions": [{"field": "activity_name", "op": "equals", "value": "ConsoleLogin"}],
}


# ---------------------------------------------------------------------------
# /status, /help
# ---------------------------------------------------------------------------


class TestStatusAndHelp:
    def test_status_ok(self):
        resp = api.lambda_handler(make_event("GET", "/status"), make_context())
        assert resp["statusCode"] == 200
        body = body_of(resp)
        assert body["status"] == "ok"
        assert body["request_id"] == "test-req-id"

    def test_help_lists_endpoints(self):
        resp = api.lambda_handler(make_event("GET", "/help"), make_context())
        assert resp["statusCode"] == 200
        body = body_of(resp)
        assert "/signals" in body["endpoints"]
        assert "/rules" in body["endpoints"]

    def test_unknown_route_returns_404(self):
        resp = api.lambda_handler(make_event("GET", "/nonexistent"), make_context())
        assert resp["statusCode"] == 404
        assert "not found" in body_of(resp)["message"]

    def test_unsupported_method_on_known_path_returns_404(self):
        # /rules/{id} matches the prefix but PATCH isn't handled -> falls through to 404
        resp = api.lambda_handler(make_event("PATCH", "/rules/abc"), make_context())
        assert resp["statusCode"] == 404


# ---------------------------------------------------------------------------
# Query-string helpers
# ---------------------------------------------------------------------------


class TestParseLimit:
    def test_default_when_absent(self):
        assert api._parse_limit({}) == 20

    def test_uses_page_size(self):
        assert api._parse_limit({"page_size": "50"}) == 50

    def test_falls_back_to_limit_param(self):
        assert api._parse_limit({"limit": "33"}) == 33

    def test_clamped_to_max(self):
        assert api._parse_limit({"page_size": "9999"}) == 200

    def test_non_numeric_falls_back_to_default(self):
        assert api._parse_limit({"page_size": "not-a-number"}) == 20

    def test_zero_or_negative_falls_back_to_default(self):
        assert api._parse_limit({"page_size": "0"}) == 20
        assert api._parse_limit({"page_size": "-5"}) == 20


class TestOrder:
    def test_default_desc(self):
        assert api._parse_order({}) == "desc"

    def test_asc_accepted(self):
        assert api._parse_order({"order": "ASC"}) == "asc"

    def test_invalid_falls_back_to_desc(self):
        assert api._parse_order({"order": "sideways"}) == "desc"


class TestCursorTokens:
    def test_round_trip(self):
        lek = {"severity": "HIGH", "timestamp": "2026-01-01T00:00:00Z"}
        token = api._encode_next_token(lek)
        assert token is not None
        assert api._decode_next_token(token) == lek

    def test_none_when_no_last_evaluated_key(self):
        assert api._encode_next_token(None) is None
        assert api._decode_next_token(None) is None

    def test_malformed_token_treated_as_no_cursor_not_an_error(self):
        # Garbage input must not raise -- it's swallowed and treated as "start fresh".
        assert api._decode_next_token("!!!not-base64-json!!!") is None

    def test_valid_base64_but_non_dict_json_returns_none(self):
        token = base64.urlsafe_b64encode(json.dumps([1, 2, 3]).encode()).decode()
        assert api._decode_next_token(token) is None


# ---------------------------------------------------------------------------
# GET /signals
# ---------------------------------------------------------------------------


class TestListSignals:
    def test_requires_exactly_one_selector(self):
        resp = api.lambda_handler(make_event("GET", "/signals", qs={}), make_context())
        assert resp["statusCode"] == 400
        assert "exactly one" in body_of(resp)["message"]

    def test_two_selectors_rejected(self):
        resp = api.lambda_handler(
            make_event("GET", "/signals", qs={"severity": "HIGH", "event_id": "abc"}),
            make_context(),
        )
        assert resp["statusCode"] == 400

    def test_by_severity_happy_path(self):
        with patch.object(api, "signals_table") as mock_table:
            mock_table.query.return_value = {"Items": [{"detection_id": "d1"}], "LastEvaluatedKey": None}
            resp = api.lambda_handler(
                make_event("GET", "/signals", qs={"severity": "high", "page_size": "5"}),
                make_context(),
            )
        assert resp["statusCode"] == 200
        body = body_of(resp)
        assert body["items"] == [{"detection_id": "d1"}]
        assert body["has_next"] is False
        assert body["next_token"] is None
        # severity is upper-cased before querying
        _, kwargs = mock_table.query.call_args
        assert kwargs["Limit"] == 5

    def test_invalid_severity_rejected(self):
        resp = api.lambda_handler(
            make_event("GET", "/signals", qs={"severity": "NOT_A_LEVEL"}), make_context()
        )
        assert resp["statusCode"] == 400

    def test_by_event_id_uses_gsi(self):
        with patch.object(api, "signals_table") as mock_table:
            mock_table.query.return_value = {"Items": [], "LastEvaluatedKey": None}
            api.lambda_handler(make_event("GET", "/signals", qs={"event_id": "evt-1"}), make_context())
        _, kwargs = mock_table.query.call_args
        assert kwargs["IndexName"] == "gsi_signal_event_id"

    def test_by_category_uses_gsi(self):
        with patch.object(api, "signals_table") as mock_table:
            mock_table.query.return_value = {"Items": [], "LastEvaluatedKey": None}
            api.lambda_handler(make_event("GET", "/signals", qs={"category": "iam"}), make_context())
        _, kwargs = mock_table.query.call_args
        assert kwargs["IndexName"] == "gsi_signal_category_id"

    def test_pagination_cursor_round_trip_across_two_pages(self):
        page_1_lek = {"severity": "HIGH", "timestamp": "t1"}
        with patch.object(api, "signals_table") as mock_table:
            mock_table.query.return_value = {"Items": [{"id": 1}], "LastEvaluatedKey": page_1_lek}
            resp1 = api.lambda_handler(
                make_event("GET", "/signals", qs={"severity": "high"}), make_context()
            )
        body1 = body_of(resp1)
        assert body1["has_next"] is True
        token = body1["next_token"]

        with patch.object(api, "signals_table") as mock_table2:
            mock_table2.query.return_value = {"Items": [{"id": 2}], "LastEvaluatedKey": None}
            resp2 = api.lambda_handler(
                make_event("GET", "/signals", qs={"severity": "high", "next_token": token}),
                make_context(),
            )
            _, kwargs = mock_table2.query.call_args
            assert kwargs["ExclusiveStartKey"] == page_1_lek
        body2 = body_of(resp2)
        assert body2["has_next"] is False


# ---------------------------------------------------------------------------
# GET /logs
# ---------------------------------------------------------------------------


class TestListLogs:
    def test_requires_exactly_one_selector(self):
        resp = api.lambda_handler(make_event("GET", "/logs", qs={}), make_context())
        assert resp["statusCode"] == 400

    def test_by_service_happy_path(self):
        with patch.object(api, "logs_table") as mock_table:
            mock_table.query.return_value = {"Items": [{"x": 1}], "LastEvaluatedKey": None}
            resp = api.lambda_handler(
                make_event("GET", "/logs", qs={"service": "OPENCDR-API"}), make_context()
            )
        assert resp["statusCode"] == 200
        assert body_of(resp)["items"] == [{"x": 1}]

    def test_by_event_name_uses_gsi(self):
        with patch.object(api, "logs_table") as mock_table:
            mock_table.query.return_value = {"Items": [], "LastEvaluatedKey": None}
            api.lambda_handler(
                make_event("GET", "/logs", qs={"event_name": "ConsoleLogin"}), make_context()
            )
        _, kwargs = mock_table.query.call_args
        assert kwargs["IndexName"] == "gsi_activity_name"


# ---------------------------------------------------------------------------
# GET /rules (list) -- single-partition query vs. all-partitions query
#
# Compound-cursor-specific coverage (exhausted-partition skip, next_token
# round-trip, malformed tokens) lives in test_api_rules_pagination.py.
# ---------------------------------------------------------------------------


class TestListRules:
    def test_with_rule_kind_uses_query_not_scan(self):
        with patch.object(api, "detection_rules_table") as mock_table:
            mock_table.query.return_value = {"Items": [{"rule_id": "001"}], "LastEvaluatedKey": None}
            resp = api.lambda_handler(
                make_event("GET", "/rules", qs={"rule_kind": "signal"}), make_context()
            )
        assert resp["statusCode"] == 200
        mock_table.query.assert_called_once()
        mock_table.scan.assert_not_called()
        assert body_of(resp)["items"] == [{"rule_id": "001"}]

    def test_invalid_rule_kind_rejected(self):
        resp = api.lambda_handler(
            make_event("GET", "/rules", qs={"rule_kind": "bogus"}), make_context()
        )
        assert resp["statusCode"] == 400

    def test_without_rule_kind_queries_every_partition_not_scan(self):
        """Fixed: omitting rule_kind queries every ALLOWED_RULE_KINDS partition
        directly (never a table scan) and merges the results."""
        with patch.object(api, "detection_rules_table") as mock_table:
            # sorted(ALLOWED_RULE_KINDS) == ["correlation", "signal"]
            mock_table.query.side_effect = [
                {"Items": [{"rule_id": "corr-1"}], "LastEvaluatedKey": None},
                {"Items": [{"rule_id": "sig-1"}], "LastEvaluatedKey": None},
            ]
            resp = api.lambda_handler(make_event("GET", "/rules", qs={}), make_context())
        assert resp["statusCode"] == 200
        assert mock_table.query.call_count == 2
        mock_table.scan.assert_not_called()
        body = body_of(resp)
        assert body["query"] == {"queried_partitions": ["correlation", "signal"]}
        assert body["items"] == [{"rule_id": "corr-1"}, {"rule_id": "sig-1"}]
        assert body["has_next"] is False
        assert body["next_token"] is None


# ---------------------------------------------------------------------------
# /rules/{rule_id} + create/update/delete
# ---------------------------------------------------------------------------


class TestRuleCrud:
    def test_get_rule_requires_rule_kind(self):
        resp = api.lambda_handler(make_event("GET", "/rules/001"), make_context())
        assert resp["statusCode"] == 400

    def test_get_rule_not_found(self):
        with patch.object(api, "detection_rules_table") as mock_table:
            mock_table.get_item.return_value = {}
            resp = api.lambda_handler(
                make_event("GET", "/rules/001", qs={"rule_kind": "signal"}), make_context()
            )
        assert resp["statusCode"] == 404

    def test_get_rule_found_via_path_params(self):
        with patch.object(api, "detection_rules_table") as mock_table:
            mock_table.get_item.return_value = {"Item": {"rule_id": "001", "rule_kind": "signal"}}
            resp = api.lambda_handler(
                make_event(
                    "GET", "/rules/001", qs={"rule_kind": "signal"}, path_params={"rule_id": "001"}
                ),
                make_context(),
            )
        assert resp["statusCode"] == 200
        assert body_of(resp)["rule_id"] == "001"

    def test_get_rule_found_via_path_split_when_no_path_params(self):
        with patch.object(api, "detection_rules_table") as mock_table:
            mock_table.get_item.return_value = {"Item": {"rule_id": "001"}}
            resp = api.lambda_handler(
                make_event("GET", "/rules/001", qs={"rule_kind": "signal"}), make_context()
            )
        assert resp["statusCode"] == 200
        # confirms the id was recovered by splitting the raw path, not just pathParameters
        args, kwargs = mock_table.get_item.call_args
        assert kwargs["Key"]["rule_id"] == "001"

    def test_create_rule_happy_path(self):
        with patch.object(api, "detection_rules_table") as mock_table:
            resp = api.lambda_handler(
                make_event("POST", "/rules", body=json.dumps(VALID_RULE_BODY)), make_context()
            )
        assert resp["statusCode"] == 201
        body = body_of(resp)
        assert body["rule_kind"] == "signal"
        assert "rule_id" in body
        mock_table.put_item.assert_called_once()
        _, kwargs = mock_table.put_item.call_args
        assert "attribute_not_exists" in kwargs["ConditionExpression"]

    def test_create_rule_missing_rule_kind_rejected(self):
        bad = dict(VALID_RULE_BODY)
        bad.pop("rule_kind")
        resp = api.lambda_handler(make_event("POST", "/rules", body=json.dumps(bad)), make_context())
        assert resp["statusCode"] == 400

    def test_create_rule_invalid_condition_op_rejected(self):
        bad = dict(VALID_RULE_BODY)
        bad["conditions"] = [{"field": "x", "op": "frobnicate", "value": "y"}]
        resp = api.lambda_handler(make_event("POST", "/rules", body=json.dumps(bad)), make_context())
        assert resp["statusCode"] == 400

    def test_create_rule_conflict_returns_409(self):
        with patch.object(api, "detection_rules_table") as mock_table:
            mock_table.put_item.side_effect = conditional_check_failed()
            resp = api.lambda_handler(
                make_event("POST", "/rules", body=json.dumps(VALID_RULE_BODY)), make_context()
            )
        assert resp["statusCode"] == 409

    def test_create_rule_with_invalid_regex_in_matches_condition_is_rejected(self):
        """Fixed: matches/not_matches condition values are now compiled as
        regex at rule-creation time, not accepted blindly."""
        bad_regex_body = dict(VALID_RULE_BODY)
        bad_regex_body["conditions"] = [
            {"field": "user_agent", "op": "matches", "value": "(unclosed["}
        ]
        resp = api.lambda_handler(
            make_event("POST", "/rules", body=json.dumps(bad_regex_body)), make_context()
        )
        assert resp["statusCode"] == 400

    def test_update_rule_requires_rule_kind_in_body(self):
        body = {"description": "no rule_kind here"}
        resp = api.lambda_handler(
            make_event("PUT", "/rules/001", body=json.dumps(body)), make_context()
        )
        assert resp["statusCode"] == 400

    def test_update_rule_preserves_rule_id_from_path(self):
        with patch.object(api, "detection_rules_table") as mock_table:
            resp = api.lambda_handler(
                make_event("PUT", "/rules/fixed-id", body=json.dumps(VALID_RULE_BODY)),
                make_context(),
            )
        assert resp["statusCode"] == 200
        assert body_of(resp)["rule_id"] == "fixed-id"
        mock_table.put_item.assert_called_once()

    def test_delete_rule_requires_rule_kind(self):
        resp = api.lambda_handler(make_event("DELETE", "/rules/001"), make_context())
        assert resp["statusCode"] == 400

    def test_delete_rule_not_found(self):
        with patch.object(api, "detection_rules_table") as mock_table:
            mock_table.get_item.return_value = {}
            resp = api.lambda_handler(
                make_event("DELETE", "/rules/001", qs={"rule_kind": "signal"}), make_context()
            )
        assert resp["statusCode"] == 404

    def test_delete_rule_happy_path(self):
        with patch.object(api, "detection_rules_table") as mock_table:
            mock_table.get_item.return_value = {"Item": {"rule_id": "001"}}
            resp = api.lambda_handler(
                make_event("DELETE", "/rules/001", qs={"rule_kind": "signal"}), make_context()
            )
        assert resp["statusCode"] == 200
        mock_table.delete_item.assert_called_once()


class TestNormalizeRulePayload:
    def test_generates_rule_id_when_absent(self):
        out = api._normalize_rule_payload(dict(VALID_RULE_BODY), force_rule_id=None)
        assert out["rule_id"]

    def test_force_rule_id_overrides_payload(self):
        payload = dict(VALID_RULE_BODY)
        payload["rule_id"] = "ignored"
        out = api._normalize_rule_payload(payload, force_rule_id="forced")
        assert out["rule_id"] == "forced"

    def test_non_dict_payload_rejected(self):
        with pytest.raises(ValueError):
            api._normalize_rule_payload([], force_rule_id=None)  # type: ignore[arg-type]

    def test_notify_must_be_bool(self):
        payload = dict(VALID_RULE_BODY)
        payload["notify"] = "yes"
        with pytest.raises(ValueError):
            api._normalize_rule_payload(payload, force_rule_id=None)

    def test_in_op_requires_nonempty_list_value(self):
        payload = dict(VALID_RULE_BODY)
        payload["conditions"] = [{"field": "x", "op": "in", "value": "not-a-list"}]
        with pytest.raises(ValueError):
            api._normalize_rule_payload(payload, force_rule_id=None)

    def test_exists_op_allows_missing_value(self):
        payload = dict(VALID_RULE_BODY)
        payload["conditions"] = [{"field": "x", "op": "exists"}]
        out = api._normalize_rule_payload(payload, force_rule_id=None)
        assert out["conditions"][0]["op"] == "exists"

    def test_severity_normalized_and_validated(self):
        payload = dict(VALID_RULE_BODY)
        payload["severity"] = "critical"
        out = api._normalize_rule_payload(payload, force_rule_id=None)
        assert out["severity"] == "CRITICAL"

        payload["severity"] = "not-real"
        with pytest.raises(ValueError):
            api._normalize_rule_payload(payload, force_rule_id=None)


# ---------------------------------------------------------------------------
# /settings
# ---------------------------------------------------------------------------


class TestSettingsCrud:
    def test_get_global_settings_not_found(self):
        with patch.object(api, "settings_table") as mock_table:
            mock_table.get_item.return_value = {}
            resp = api.lambda_handler(make_event("GET", "/settings"), make_context())
        assert resp["statusCode"] == 404

    def test_get_settings_redacts_credentials(self):
        """Confirms the redaction fix: no plaintext secrets in GET /settings."""
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
        assert body["channels"]["slack"]["webhook_url"] == "***REDACTED***"
        assert body["channels"]["jira"]["api_token"] == "***REDACTED***"
        # enabled flags and non-secret fields still pass through
        assert body["channels"]["slack"]["enabled"] is True

    def test_create_settings_happy_path(self):
        with patch.object(api, "settings_table") as mock_table:
            resp = api.lambda_handler(
                make_event("POST", "/settings", body=json.dumps({"channels": {}})), make_context()
            )
        assert resp["statusCode"] == 201
        assert body_of(resp)["setting_id"] == "global"
        mock_table.put_item.assert_called_once()

    def test_create_settings_conflict_returns_409(self):
        with patch.object(api, "settings_table") as mock_table:
            mock_table.put_item.side_effect = conditional_check_failed()
            resp = api.lambda_handler(
                make_event("POST", "/settings", body=json.dumps({})), make_context()
            )
        assert resp["statusCode"] == 409

    def test_channel_enabled_must_be_bool(self):
        body = {"channels": {"slack": {"enabled": "yes"}}}
        resp = api.lambda_handler(make_event("POST", "/settings", body=json.dumps(body)), make_context())
        assert resp["statusCode"] == 400

    def test_upsert_settings_by_id(self):
        with patch.object(api, "settings_table") as mock_table:
            resp = api.lambda_handler(
                make_event("PUT", "/settings/team-a", body=json.dumps({"channels": {}})),
                make_context(),
            )
        assert resp["statusCode"] == 200
        assert body_of(resp)["setting_id"] == "team-a"
        mock_table.put_item.assert_called_once()

    def test_delete_settings_not_found(self):
        with patch.object(api, "settings_table") as mock_table:
            mock_table.get_item.return_value = {}
            resp = api.lambda_handler(make_event("DELETE", "/settings/team-a"), make_context())
        assert resp["statusCode"] == 404

    def test_delete_settings_happy_path(self):
        with patch.object(api, "settings_table") as mock_table:
            mock_table.get_item.return_value = {"Item": {"setting_id": "team-a"}}
            resp = api.lambda_handler(make_event("DELETE", "/settings/team-a"), make_context())
        assert resp["statusCode"] == 200
        mock_table.delete_item.assert_called_once()

    def test_settings_path_without_id_returns_400(self):
        resp = api.lambda_handler(make_event("GET", "/settings/"), make_context())
        assert resp["statusCode"] == 400


# ---------------------------------------------------------------------------
# Body parsing + error handling
# ---------------------------------------------------------------------------


class TestBodyParsingAndErrors:
    def test_invalid_json_body_returns_400(self):
        resp = api.lambda_handler(make_event("POST", "/rules", body="{not json"), make_context())
        assert resp["statusCode"] == 400

    def test_non_object_json_body_rejected(self):
        resp = api.lambda_handler(make_event("POST", "/rules", body="[1, 2, 3]"), make_context())
        assert resp["statusCode"] == 400

    def test_base64_encoded_body_is_decoded(self):
        raw = json.dumps(VALID_RULE_BODY).encode()
        encoded = base64.b64encode(raw).decode()
        with patch.object(api, "detection_rules_table"):
            resp = api.lambda_handler(
                make_event("POST", "/rules", body=encoded, is_base64=True), make_context()
            )
        assert resp["statusCode"] == 201

    def test_missing_body_treated_as_empty_object(self):
        # POST /rules with no body -> {} -> fails validation (missing rule_kind) as 400, not a crash
        resp = api.lambda_handler(make_event("POST", "/rules"), make_context())
        assert resp["statusCode"] == 400

    def test_unexpected_exception_returns_500_with_repr(self):
        """Documents the known gap: raw repr(e) is leaked into the response body."""
        with patch.object(api, "signals_table") as mock_table:
            mock_table.query.side_effect = RuntimeError("boom: table on fire")
            resp = api.lambda_handler(
                make_event("GET", "/signals", qs={"severity": "high"}), make_context()
            )
        assert resp["statusCode"] == 500
        body = body_of(resp)
        assert "boom: table on fire" in body["message"]
        assert body["request_id"] == "test-req-id"

    def test_request_context_v2_event_shape_is_supported(self):
        event = {
            "requestContext": {"http": {"method": "GET"}},
            "rawPath": "/status",
            "queryStringParameters": None,
            "pathParameters": None,
        }
        resp = api.lambda_handler(event, make_context())
        assert resp["statusCode"] == 200

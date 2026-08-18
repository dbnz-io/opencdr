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


def make_event(
    method: str, path: str, *, qs=None, path_params=None, body=None, is_base64=False, api_key_id=None
) -> dict:
    event = {
        "httpMethod": method,
        "path": path,
        "queryStringParameters": qs,
        "pathParameters": path_params,
        "body": body,
        "isBase64Encoded": is_base64,
    }
    if api_key_id is not None:
        event["requestContext"] = {"identity": {"apiKeyId": api_key_id}}
    return event


# _default_full_scope_api_key in tests/handlers/conftest.py (autouse) gives
# every test here a full-access key by default -- TestApiKeyScoping below
# overrides it per-test to prove enforcement actually works.


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
        # date_from == date_to pins this to a single day-bucket, one
        # query call -- multi-day fan-out has its own dedicated coverage
        # in TestListSignalsDateBucketing below.
        with patch.object(api, "signals_table") as mock_table:
            mock_table.query.return_value = {"Items": [{"detection_id": "d1"}], "LastEvaluatedKey": None}
            resp = api.lambda_handler(
                make_event(
                    "GET", "/signals",
                    qs={"severity": "high", "page_size": "5", "date_from": "2026-08-12", "date_to": "2026-08-12"},
                ),
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
        assert "HIGH#2026-08-12" in kwargs["KeyConditionExpression"].get_expression()["values"]

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
        # Single day-bucket (date_from == date_to) so each page is
        # exactly one query call -- the cursor round-trip mechanism this
        # test targets, not the multi-day merge (see
        # TestListSignalsDateBucketing below).
        date_qs = {"date_from": "2026-08-12", "date_to": "2026-08-12"}
        page_1_lek = {"severity_bucket": "HIGH#2026-08-12", "timestamp": "t1"}
        with patch.object(api, "signals_table") as mock_table:
            mock_table.query.return_value = {"Items": [{"id": 1}], "LastEvaluatedKey": page_1_lek}
            resp1 = api.lambda_handler(
                make_event("GET", "/signals", qs={"severity": "high", **date_qs}), make_context()
            )
        body1 = body_of(resp1)
        assert body1["has_next"] is True
        token = body1["next_token"]

        with patch.object(api, "signals_table") as mock_table2:
            mock_table2.query.return_value = {"Items": [{"id": 2}], "LastEvaluatedKey": None}
            resp2 = api.lambda_handler(
                make_event("GET", "/signals", qs={"severity": "high", "next_token": token, **date_qs}),
                make_context(),
            )
            _, kwargs = mock_table2.query.call_args
            assert kwargs["ExclusiveStartKey"] == page_1_lek
        body2 = body_of(resp2)
        assert body2["has_next"] is False


# ---------------------------------------------------------------------------
# GET /signals?severity=.. -- date-range defaults/validation and the
# multi-day merge-pagination fan-out (_query_bucketed_range). Basic
# single-day happy-path/cursor-round-trip coverage lives in
# TestListSignals above.
# ---------------------------------------------------------------------------


class TestListSignalsDateBucketing:
    def test_default_range_is_last_7_days(self):
        import datetime as dt

        today = dt.datetime.now(dt.UTC).date()
        expected_from = (today - dt.timedelta(days=6)).strftime("%Y-%m-%d")
        expected_to = today.strftime("%Y-%m-%d")

        with patch.object(api, "signals_table") as mock_table:
            mock_table.query.return_value = {"Items": [], "LastEvaluatedKey": None}
            resp = api.lambda_handler(make_event("GET", "/signals", qs={"severity": "high"}), make_context())

        body = body_of(resp)
        assert body["query"]["date_from"] == expected_from
        assert body["query"]["date_to"] == expected_to

    def test_date_range_wider_than_max_is_rejected(self):
        resp = api.lambda_handler(
            make_event(
                "GET", "/signals",
                qs={"severity": "high", "date_from": "2026-01-01", "date_to": "2026-12-31"},
            ),
            make_context(),
        )
        assert resp["statusCode"] == 400

    def test_date_from_after_date_to_is_rejected(self):
        resp = api.lambda_handler(
            make_event(
                "GET", "/signals",
                qs={"severity": "high", "date_from": "2026-08-12", "date_to": "2026-08-01"},
            ),
            make_context(),
        )
        assert resp["statusCode"] == 400

    def test_invalid_date_format_is_rejected(self):
        resp = api.lambda_handler(
            make_event("GET", "/signals", qs={"severity": "high", "date_from": "08/12/2026"}),
            make_context(),
        )
        assert resp["statusCode"] == 400

    def test_multi_day_merge_preserves_chronological_order(self):
        # order=desc (default) -> newest day queried first: 12, 11, 10.
        # None with items still under page_size each day means every day
        # gets exhausted and queried within the same page.
        with patch.object(api, "signals_table") as mock_table:
            mock_table.query.side_effect = [
                {"Items": [{"id": "day12"}], "LastEvaluatedKey": None},
                {"Items": [{"id": "day11"}], "LastEvaluatedKey": None},
                {"Items": [{"id": "day10"}], "LastEvaluatedKey": None},
            ]
            resp = api.lambda_handler(
                make_event(
                    "GET", "/signals",
                    qs={"severity": "high", "date_from": "2026-08-10", "date_to": "2026-08-12"},
                ),
                make_context(),
            )

        body = body_of(resp)
        assert body["items"] == [{"id": "day12"}, {"id": "day11"}, {"id": "day10"}]
        assert body["has_next"] is False

        queried_buckets = [
            call.kwargs["KeyConditionExpression"].get_expression()["values"][1]
            for call in mock_table.query.call_args_list
        ]
        assert queried_buckets == ["HIGH#2026-08-12", "HIGH#2026-08-11", "HIGH#2026-08-10"]

    def test_multi_day_stops_page_at_first_unexhausted_day(self):
        # day12 isn't exhausted (non-null LastEvaluatedKey) -- day11/day10
        # must not be queried in this same page, preserving order.
        with patch.object(api, "signals_table") as mock_table:
            mock_table.query.return_value = {
                "Items": [{"id": "day12"}],
                "LastEvaluatedKey": {"severity_bucket": "HIGH#2026-08-12", "timestamp": "t"},
            }
            resp = api.lambda_handler(
                make_event(
                    "GET", "/signals",
                    qs={"severity": "high", "date_from": "2026-08-10", "date_to": "2026-08-12"},
                ),
                make_context(),
            )

        assert mock_table.query.call_count == 1
        body = body_of(resp)
        assert body["items"] == [{"id": "day12"}]
        assert body["has_next"] is True


class TestSignalStats:
    def test_single_day_counts_per_severity(self):
        # One day in range * 6 severities = 6 Select=COUNT queries.
        with patch.object(api, "signals_table") as mock_table:
            mock_table.query.return_value = {"Count": 3, "LastEvaluatedKey": None}
            resp = api.lambda_handler(
                make_event("GET", "/signals/stats", qs={"date_from": "2026-08-17", "date_to": "2026-08-17"}),
                make_context(),
            )

        assert resp["statusCode"] == 200
        body = body_of(resp)
        assert body["date_from"] == "2026-08-17"
        assert body["date_to"] == "2026-08-17"
        assert body["counts"] == {
            "CRITICAL": 3, "HIGH": 3, "MEDIUM": 3, "LOW": 3, "INFO": 3, "INFORMATIONAL": 3,
        }
        assert body["total"] == 18
        assert mock_table.query.call_count == 6

    def test_every_severity_present_even_at_zero(self):
        with patch.object(api, "signals_table") as mock_table:
            mock_table.query.return_value = {"Count": 0, "LastEvaluatedKey": None}
            resp = api.lambda_handler(
                make_event("GET", "/signals/stats", qs={"date_from": "2026-08-17", "date_to": "2026-08-17"}),
                make_context(),
            )
        body = body_of(resp)
        assert set(body["counts"].keys()) == {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "INFORMATIONAL"}
        assert body["total"] == 0

    def test_sums_across_multiple_days(self):
        # 3 days * 6 severities = 18 calls, each contributing 1.
        with patch.object(api, "signals_table") as mock_table:
            mock_table.query.return_value = {"Count": 1, "LastEvaluatedKey": None}
            resp = api.lambda_handler(
                make_event("GET", "/signals/stats", qs={"date_from": "2026-08-15", "date_to": "2026-08-17"}),
                make_context(),
            )
        body = body_of(resp)
        assert body["counts"]["HIGH"] == 3
        assert body["total"] == 18
        assert mock_table.query.call_count == 18

    def test_paginates_within_a_single_severity_day_bucket(self):
        # A single (severity, day) bucket whose Select=COUNT response is
        # itself paginated (DynamoDB's ~1MB-per-response cap) must sum
        # across pages, not just take the first response's Count.
        with patch.object(api, "signals_table") as mock_table:
            mock_table.query.side_effect = [
                {"Count": 500, "LastEvaluatedKey": {"severity_bucket": "CRITICAL#2026-08-17", "timestamp": "t1"}},
                {"Count": 500, "LastEvaluatedKey": {"severity_bucket": "CRITICAL#2026-08-17", "timestamp": "t2"}},
                {"Count": 42, "LastEvaluatedKey": None},
            ]
            total = api._count_signals_for_day("CRITICAL", "2026-08-17")
        assert total == 1042
        assert mock_table.query.call_count == 3

    def test_default_range_is_last_7_days(self):
        import datetime as dt

        today = dt.datetime.now(dt.UTC).date()
        expected_from = (today - dt.timedelta(days=6)).strftime("%Y-%m-%d")
        expected_to = today.strftime("%Y-%m-%d")

        with patch.object(api, "signals_table") as mock_table:
            mock_table.query.return_value = {"Count": 0, "LastEvaluatedKey": None}
            resp = api.lambda_handler(make_event("GET", "/signals/stats"), make_context())

        body = body_of(resp)
        assert body["date_from"] == expected_from
        assert body["date_to"] == expected_to

    def test_date_range_wider_than_max_is_rejected(self):
        resp = api.lambda_handler(
            make_event("GET", "/signals/stats", qs={"date_from": "2026-01-01", "date_to": "2026-12-31"}),
            make_context(),
        )
        assert resp["statusCode"] == 400

    def test_queries_the_expected_severity_bucket_keys(self):
        with patch.object(api, "signals_table") as mock_table:
            mock_table.query.return_value = {"Count": 0, "LastEvaluatedKey": None}
            api.lambda_handler(
                make_event("GET", "/signals/stats", qs={"date_from": "2026-08-17", "date_to": "2026-08-17"}),
                make_context(),
            )

        queried_buckets = {
            call.kwargs["KeyConditionExpression"].get_expression()["values"][1]
            for call in mock_table.query.call_args_list
        }
        assert queried_buckets == {
            "CRITICAL#2026-08-17", "HIGH#2026-08-17", "MEDIUM#2026-08-17",
            "LOW#2026-08-17", "INFO#2026-08-17", "INFORMATIONAL#2026-08-17",
        }
        for call in mock_table.query.call_args_list:
            assert call.kwargs["Select"] == "COUNT"


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
                make_event(
                    "GET", "/logs",
                    qs={"service": "OPENCDR-API", "date_from": "2026-08-12", "date_to": "2026-08-12"},
                ),
                make_context(),
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

    def test_unpacks_rule_body_loaded_rules(self):
        """scripts/load_rules.sh writes rules as {rule_kind, rule_id, rule_body:
        "<json>"} rather than flat top-level attributes -- GET /rules must
        return the real fields (description, severity, conditions, enabled,
        response_module, ...), not just the wrapper, or every load_rules.sh
        -loaded rule looks blank/disabled to any caller of this endpoint
        (CLI, MCP, a UI) even though the detection engine matches it fine."""
        stored = {
            "rule_kind": "signal",
            "rule_id": "001_console_login_no_mfa",
            "rule_body": json.dumps(
                {
                    "rule_id": "001_console_login_no_mfa",
                    "rule_kind": "signal",
                    "description": "Console login without MFA",
                    "severity": "MEDIUM",
                    "enabled": True,
                    "response_module": "",
                    "conditions": [{"field": "activity_name", "op": "equals", "value": "ConsoleLogin"}],
                }
            ),
        }
        with patch.object(api, "detection_rules_table") as mock_table:
            mock_table.query.return_value = {"Items": [stored], "LastEvaluatedKey": None}
            resp = api.lambda_handler(
                make_event("GET", "/rules", qs={"rule_kind": "signal"}), make_context()
            )
        assert resp["statusCode"] == 200
        item = body_of(resp)["items"][0]
        assert item["description"] == "Console login without MFA"
        assert item["severity"] == "MEDIUM"
        assert item["enabled"] is True
        assert item["conditions"] == [{"field": "activity_name", "op": "equals", "value": "ConsoleLogin"}]
        # Real table keys win over any copy embedded in rule_body.
        assert item["rule_id"] == "001_console_login_no_mfa"
        assert item["rule_kind"] == "signal"

    def test_flat_rules_pass_through_unchanged(self):
        """A rule created/edited through this API's own POST/PUT (which write
        flat, no rule_body) must be returned exactly as stored -- no
        regression from adding the rule_body unpacking above."""
        stored = {"rule_kind": "signal", "rule_id": "030_custom", "description": "x", "enabled": True}
        with patch.object(api, "detection_rules_table") as mock_table:
            mock_table.query.return_value = {"Items": [stored], "LastEvaluatedKey": None}
            resp = api.lambda_handler(
                make_event("GET", "/rules", qs={"rule_kind": "signal"}), make_context()
            )
        assert body_of(resp)["items"][0] == stored


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

    def test_get_rule_unpacks_rule_body(self):
        stored = {
            "rule_kind": "signal",
            "rule_id": "001",
            "rule_body": json.dumps({"rule_id": "001", "rule_kind": "signal", "severity": "HIGH", "enabled": False}),
        }
        with patch.object(api, "detection_rules_table") as mock_table:
            mock_table.get_item.return_value = {"Item": stored}
            resp = api.lambda_handler(
                make_event(
                    "GET", "/rules/001", qs={"rule_kind": "signal"}, path_params={"rule_id": "001"}
                ),
                make_context(),
            )
        assert resp["statusCode"] == 200
        body = body_of(resp)
        assert body["severity"] == "HIGH"
        assert body["enabled"] is False

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

    def test_response_module_absent_is_valid(self):
        out = api._normalize_rule_payload(dict(VALID_RULE_BODY), force_rule_id=None)
        assert out.get("response_module") is None

    def test_response_module_empty_string_is_valid(self):
        payload = dict(VALID_RULE_BODY)
        payload["response_module"] = ""
        out = api._normalize_rule_payload(payload, force_rule_id=None)
        assert out["response_module"] == ""

    def test_response_module_registered_name_accepted(self):
        payload = dict(VALID_RULE_BODY)
        payload["response_module"] = "disable_access_key"
        out = api._normalize_rule_payload(payload, force_rule_id=None)
        assert out["response_module"] == "disable_access_key"

    def test_response_module_unknown_name_rejected(self):
        payload = dict(VALID_RULE_BODY)
        payload["response_module"] = "delete_everything"
        with pytest.raises(ValueError, match="response_module"):
            api._normalize_rule_payload(payload, force_rule_id=None)

    def test_response_module_typo_of_real_module_rejected(self):
        # The exact motivating case: a typo during setup should fail loudly
        # here, not silently no-op later in responder's logs.
        payload = dict(VALID_RULE_BODY)
        payload["response_module"] = "isolate_ec2_instance"  # missing trailing "s"
        with pytest.raises(ValueError, match="response_module"):
            api._normalize_rule_payload(payload, force_rule_id=None)


class TestAllowedResponseModulesSync:
    def test_matches_responder_registered_handlers_exactly(self):
        # Regression guard against the exact drift class INFORME-AUTOR-ES.md
        # §3.1 already found once for ALLOWED_CONDITION_OPS vs. the engine --
        # api.py can't import responder.py (would pull dredge into the api
        # Lambda's cold start), so this hand-kept set is only trustworthy if
        # a test proves it matches the real registry on every run.
        from src.handlers import responder

        assert api.ALLOWED_RESPONSE_MODULES == set(responder.RESPONSE_MODULE_HANDLERS.keys())


class TestRollbackEligibleModulesSync:
    def test_matches_responder_rollback_undo_module_exactly(self):
        # Same class of drift guard as TestAllowedResponseModulesSync above,
        # this time for the rollback-eligible subset.
        from src.handlers import responder

        assert api.ROLLBACK_ELIGIBLE_MODULES == set(responder.ROLLBACK_UNDO_MODULE.keys())


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


# ---------------------------------------------------------------------------
# API key route scoping
# ---------------------------------------------------------------------------


class TestRequiredScopeFor:
    """Exhaustive over every route serverless.yml actually declares (22 routes) --
    the regression guard against a new route being wired up without scoping."""

    @pytest.mark.parametrize(
        "method,path,expected",
        [
            ("GET", "/status", None),
            ("GET", "/help", None),
            ("GET", "/signals", "read"),
            ("GET", "/logs", "read"),
            ("GET", "/rules", "read"),
            ("POST", "/rules", "rules"),
            ("GET", "/rules/001_console_login", "read"),
            ("PUT", "/rules/001_console_login", "rules"),
            ("DELETE", "/rules/001_console_login", "rules"),
            ("GET", "/settings", "read"),
            ("POST", "/settings", "settings"),
            ("GET", "/settings/global", "read"),
            ("PUT", "/settings/global", "settings"),
            ("DELETE", "/settings/global", "settings"),
            ("GET", "/ir-roles", "read"),
            ("POST", "/ir-roles", "ir_roles"),
            ("GET", "/ir-roles/123456789012", "read"),
            ("PUT", "/ir-roles/123456789012", "ir_roles"),
            ("DELETE", "/ir-roles/123456789012", "ir_roles"),
            ("GET", "/ir-actions", "read"),
            ("GET", "/ir-actions/d-1", "read"),
            ("POST", "/ir-actions/d-1/rollback", "ir_actions"),
        ],
    )
    def test_required_scope(self, method, path, expected):
        assert api._required_scope_for(method, path) == expected

    def test_unknown_route_requires_no_scope(self):
        # Falls through to the existing 404 -- scoping shouldn't mask that.
        assert api._required_scope_for("GET", "/nonexistent") is None


class TestScopesFromKeyName:
    def test_bare_key_name_gets_all_scopes(self):
        assert api._scopes_from_key_name(api._API_KEY_NAME_PREFIX) == api.ALL_SCOPES

    def test_settings_suffix_gets_settings_scope_only(self):
        name = f"{api._API_KEY_NAME_PREFIX}-settings"
        assert api._scopes_from_key_name(name) == {"settings"}

    def test_multi_scope_suffix_parsed(self):
        name = f"{api._API_KEY_NAME_PREFIX}-read-rules"
        assert api._scopes_from_key_name(name) == {"read", "rules"}

    def test_ir_roles_suffix_alone_parsed_correctly(self):
        # Regression guard: "ir_roles" uses an underscore specifically so it
        # can't be split apart by the dash-joined suffix parser the way a
        # dash-containing scope name ("ir-roles") would be.
        name = f"{api._API_KEY_NAME_PREFIX}-ir_roles"
        assert api._scopes_from_key_name(name) == {"ir_roles"}

    def test_all_five_scopes_combined_in_one_suffix(self):
        name = f"{api._API_KEY_NAME_PREFIX}-read-rules-settings-ir_roles-ir_actions"
        assert api._scopes_from_key_name(name) == api.ALL_SCOPES

    def test_unrecognized_name_gets_no_scopes(self):
        assert api._scopes_from_key_name("totally-unrelated-key") == frozenset()

    def test_unknown_suffix_token_ignored_not_erroring(self):
        name = f"{api._API_KEY_NAME_PREFIX}-settings-bogus"
        assert api._scopes_from_key_name(name) == {"settings"}


class TestGetKeyScopes:
    def test_missing_api_key_id_gets_no_scopes(self, monkeypatch):
        monkeypatch.undo()  # remove the autouse full-access override for this test
        assert api._get_key_scopes(None) == frozenset()

    def test_resolves_scopes_via_get_api_key(self, monkeypatch):
        monkeypatch.undo()
        api._key_scope_cache.clear()
        with patch.object(
            api.apigateway, "get_api_key", return_value={"name": f"{api._API_KEY_NAME_PREFIX}-settings"}
        ) as mock_get:
            scopes = api._get_key_scopes("key-id-1")
        assert scopes == {"settings"}
        mock_get.assert_called_once_with(apiKey="key-id-1")

    def test_caches_within_ttl(self, monkeypatch):
        monkeypatch.undo()
        api._key_scope_cache.clear()
        with patch.object(
            api.apigateway, "get_api_key", return_value={"name": f"{api._API_KEY_NAME_PREFIX}-settings"}
        ) as mock_get:
            api._get_key_scopes("key-id-2")
            api._get_key_scopes("key-id-2")
        assert mock_get.call_count == 1

    def test_get_api_key_failure_fails_closed(self, monkeypatch):
        monkeypatch.undo()
        api._key_scope_cache.clear()
        with patch.object(api.apigateway, "get_api_key", side_effect=RuntimeError("boom")):
            assert api._get_key_scopes("key-id-3") == frozenset()


class TestApiKeyScoping:
    """End-to-end: lambda_handler actually enforces _required_scope_for
    against _get_key_scopes, not just that the two pieces work standalone."""

    def test_read_only_key_cannot_mutate_settings(self, monkeypatch):
        monkeypatch.setattr(api, "_get_key_scopes", lambda api_key_id: frozenset({"read"}))
        resp = api.lambda_handler(
            make_event("POST", "/settings", body=json.dumps({"channels": {}}), api_key_id="k1"),
            make_context(),
        )
        assert resp["statusCode"] == 403
        assert "settings" in body_of(resp)["message"]

    def test_settings_only_key_cannot_read_signals(self, monkeypatch):
        monkeypatch.setattr(api, "_get_key_scopes", lambda api_key_id: frozenset({"settings"}))
        resp = api.lambda_handler(
            make_event("GET", "/signals", qs={"severity": "HIGH"}, api_key_id="k2"), make_context()
        )
        assert resp["statusCode"] == 403
        assert "read" in body_of(resp)["message"]

    def test_settings_scoped_key_can_read_and_write_settings(self, monkeypatch):
        monkeypatch.setattr(api, "_get_key_scopes", lambda api_key_id: frozenset({"read", "settings"}))
        with patch.object(api, "settings_table") as mock_table:
            mock_table.get_item.return_value = {"Item": {"setting_id": "global", "channels": {}}}
            resp = api.lambda_handler(make_event("GET", "/settings", api_key_id="k3"), make_context())
        assert resp["statusCode"] == 200

    def test_bare_full_access_key_succeeds_on_every_scope(self, monkeypatch):
        monkeypatch.setattr(api, "_get_key_scopes", lambda api_key_id: api.ALL_SCOPES)
        resp = api.lambda_handler(
            make_event("DELETE", "/ir-roles/123456789012", api_key_id="k4"), make_context()
        )
        # Not 403 -- may still 404/500 depending on table mocking, but scoping itself must not block it.
        assert resp["statusCode"] != 403

    def test_missing_api_key_id_is_rejected_on_scoped_route(self, monkeypatch):
        monkeypatch.undo()  # exercise the real _get_key_scopes(None) -> no scopes path
        resp = api.lambda_handler(make_event("GET", "/signals", qs={"severity": "HIGH"}), make_context())
        assert resp["statusCode"] == 403

    def test_settings_only_key_cannot_read_signal_stats(self, monkeypatch):
        monkeypatch.setattr(api, "_get_key_scopes", lambda api_key_id: frozenset({"settings"}))
        resp = api.lambda_handler(make_event("GET", "/signals/stats", api_key_id="k5"), make_context())
        assert resp["statusCode"] == 403
        assert "read" in body_of(resp)["message"]

    def test_status_and_help_unaffected_by_missing_key(self, monkeypatch):
        monkeypatch.undo()
        resp = api.lambda_handler(make_event("GET", "/status"), make_context())
        assert resp["statusCode"] == 200

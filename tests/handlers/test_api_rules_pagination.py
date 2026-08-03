"""Tests for GET /rules' compound-cursor pagination when rule_kind is
omitted (src/handlers/api.py _list_rules_all_partitions).

There are only as many partitions as ALLOWED_RULE_KINDS
({"signal", "correlation"}), so instead of scanning, every partition is
queried directly and merged. Pagination uses a compound cursor --
{rule_kind: ExclusiveStartKey | None} -- rather than a single
ExclusiveStartKey, since two independently-paged partitions can't share
one cursor. This file covers that cursor's behavior specifically; basic
query-vs-scan coverage lives in test_api.py::TestListRules.
"""
from __future__ import annotations

import json
import os
from unittest.mock import MagicMock, patch

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

from src.handlers import api

# sorted(ALLOWED_RULE_KINDS) -- the fixed partition query order this file
# asserts against throughout.
PARTITIONS = sorted(api.ALLOWED_RULE_KINDS)


def make_event(method: str, path: str, *, qs=None) -> dict:
    return {
        "httpMethod": method,
        "path": path,
        "queryStringParameters": qs,
        "pathParameters": None,
        "body": None,
        "isBase64Encoded": False,
    }


def make_context():
    ctx = MagicMock()
    ctx.aws_request_id = "test-req-id"
    return ctx


def body_of(resp: dict) -> dict:
    return json.loads(resp["body"])


class TestFirstPage:
    def test_queries_every_partition_from_the_start(self):
        with patch.object(api, "detection_rules_table") as mock_table:
            mock_table.query.side_effect = [
                {"Items": [{"rule_id": f"{PARTITIONS[0]}-1"}]},
                {"Items": [{"rule_id": f"{PARTITIONS[1]}-1"}]},
            ]
            resp = api.lambda_handler(make_event("GET", "/rules", qs={}), make_context())

        assert resp["statusCode"] == 200
        assert mock_table.query.call_count == 2
        for call in mock_table.query.call_args_list:
            assert "ExclusiveStartKey" not in call.kwargs
        body = body_of(resp)
        assert [item["rule_id"] for item in body["items"]] == [f"{PARTITIONS[0]}-1", f"{PARTITIONS[1]}-1"]

    def test_merges_up_to_page_size_per_partition_not_a_global_cap(self):
        with patch.object(api, "detection_rules_table") as mock_table:
            mock_table.query.side_effect = [
                {"Items": [{"rule_id": f"{PARTITIONS[0]}-{i}"} for i in range(5)]},
                {"Items": [{"rule_id": f"{PARTITIONS[1]}-{i}"} for i in range(5)]},
            ]
            resp = api.lambda_handler(make_event("GET", "/rules", qs={"page_size": "5"}), make_context())

        body = body_of(resp)
        # 5 + 5 = 10 items even though page_size=5 -- documented, deliberate.
        assert len(body["items"]) == 10


class TestExhaustedPartitionSkipped:
    def test_only_queries_the_non_exhausted_partition(self):
        incoming_cursor = {PARTITIONS[0]: None, PARTITIONS[1]: {"rule_kind": PARTITIONS[1], "rule_id": "x"}}
        token = api._encode_next_token(incoming_cursor)

        with patch.object(api, "detection_rules_table") as mock_table:
            mock_table.query.return_value = {"Items": [{"rule_id": f"{PARTITIONS[1]}-next"}]}
            resp = api.lambda_handler(make_event("GET", "/rules", qs={"next_token": token}), make_context())

        assert mock_table.query.call_count == 1
        call_kwargs = mock_table.query.call_args.kwargs
        assert call_kwargs["ExclusiveStartKey"] == {"rule_kind": PARTITIONS[1], "rule_id": "x"}
        body = body_of(resp)
        assert body["items"] == [{"rule_id": f"{PARTITIONS[1]}-next"}]


class TestHasNextAndNextToken:
    def test_has_next_true_when_one_partition_has_more(self):
        with patch.object(api, "detection_rules_table") as mock_table:
            mock_table.query.side_effect = [
                {"Items": [], "LastEvaluatedKey": {"rule_kind": PARTITIONS[0], "rule_id": "last"}},
                {"Items": []},
            ]
            resp = api.lambda_handler(make_event("GET", "/rules", qs={}), make_context())

        body = body_of(resp)
        assert body["has_next"] is True
        assert body["next_token"] is not None

    def test_has_next_false_and_no_token_when_both_partitions_done(self):
        with patch.object(api, "detection_rules_table") as mock_table:
            mock_table.query.side_effect = [{"Items": []}, {"Items": []}]
            resp = api.lambda_handler(make_event("GET", "/rules", qs={}), make_context())

        body = body_of(resp)
        assert body["has_next"] is False
        assert body["next_token"] is None

    def test_next_token_round_trips_to_the_right_partition(self):
        with patch.object(api, "detection_rules_table") as mock_table:
            mock_table.query.side_effect = [
                {"Items": [], "LastEvaluatedKey": {"rule_kind": PARTITIONS[0], "rule_id": "p0-last"}},
                {"Items": []},
            ]
            resp = api.lambda_handler(make_event("GET", "/rules", qs={}), make_context())

        token = body_of(resp)["next_token"]
        decoded = api._decode_next_token(token)
        assert decoded[PARTITIONS[0]] == {"rule_kind": PARTITIONS[0], "rule_id": "p0-last"}
        assert decoded[PARTITIONS[1]] is None

        # Second page: partition 0 resumes from its cursor, partition 1 is skipped.
        with patch.object(api, "detection_rules_table") as mock_table:
            mock_table.query.return_value = {"Items": [{"rule_id": f"{PARTITIONS[0]}-page2"}]}
            resp2 = api.lambda_handler(make_event("GET", "/rules", qs={"next_token": token}), make_context())

        assert mock_table.query.call_count == 1
        assert mock_table.query.call_args.kwargs["ExclusiveStartKey"] == {
            "rule_kind": PARTITIONS[0],
            "rule_id": "p0-last",
        }
        assert body_of(resp2)["items"] == [{"rule_id": f"{PARTITIONS[0]}-page2"}]


class TestMalformedToken:
    def test_foreign_shaped_token_starts_both_partitions_fresh(self):
        # A single-partition-style ESK dict, not a compound cursor -- .get(rk)
        # on it just returns None for both partition keys, degrading safely.
        foreign_token = api._encode_next_token({"rule_kind": "signal", "rule_id": "001"})

        with patch.object(api, "detection_rules_table") as mock_table:
            mock_table.query.side_effect = [{"Items": []}, {"Items": []}]
            resp = api.lambda_handler(
                make_event("GET", "/rules", qs={"next_token": foreign_token}), make_context()
            )

        assert resp["statusCode"] == 200
        assert mock_table.query.call_count == 2
        for call in mock_table.query.call_args_list:
            assert "ExclusiveStartKey" not in call.kwargs

    def test_garbage_token_starts_both_partitions_fresh(self):
        with patch.object(api, "detection_rules_table") as mock_table:
            mock_table.query.side_effect = [{"Items": []}, {"Items": []}]
            resp = api.lambda_handler(
                make_event("GET", "/rules", qs={"next_token": "not-valid-base64!!"}), make_context()
            )

        assert resp["statusCode"] == 200
        assert mock_table.query.call_count == 2

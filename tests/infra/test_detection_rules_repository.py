"""Tests for src/infra/detection_rules_repository.py (load_detection_rules).

Previously exercised only incidentally, via handler tests that patch this
module out entirely -- this is the module that actually queries DynamoDB
for signal/correlation/list rules, and had no dedicated suite (24% coverage).
"""
from __future__ import annotations

import os
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

from src.infra.detection_rules_repository import load_detection_rules


def _client_error(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": code}}, "Query")


def make_aws() -> MagicMock:
    aws = MagicMock()
    aws._ddb = MagicMock()
    return aws


@pytest.fixture(autouse=True)
def table_name_env(monkeypatch):
    monkeypatch.setenv("DETECTION_RULES_TABLE_NAME", "test-rules-table")


class TestMissingConfig:
    def test_missing_table_name_returns_empty_and_logs(self, monkeypatch):
        monkeypatch.delenv("DETECTION_RULES_TABLE_NAME", raising=False)
        aws = make_aws()
        logger = MagicMock()

        result = load_detection_rules(aws, logger, rule_kind="signal")

        assert result == []
        logger.error.assert_called_once()
        assert logger.error.call_args.kwargs["event_name"] == "RULES_TABLE_MISSING"
        aws._ddb.query.assert_not_called()

    def test_missing_rule_kind_returns_empty_and_logs(self):
        aws = make_aws()
        logger = MagicMock()

        result = load_detection_rules(aws, logger, rule_kind="")

        assert result == []
        logger.error.assert_called_once()
        assert logger.error.call_args.kwargs["event_name"] == "RULES_KIND_MISSING"
        aws._ddb.query.assert_not_called()


class TestQueryAndUnmarshal:
    def test_returns_unmarshalled_enabled_rules(self):
        aws = make_aws()
        aws._ddb.query.return_value = {
            "Items": [
                {"rule_id": {"S": "r1"}, "rule_kind": {"S": "signal"}, "enabled": {"BOOL": True}},
            ]
        }
        logger = MagicMock()

        result = load_detection_rules(aws, logger, rule_kind="signal")

        assert result == [{"rule_id": "r1", "rule_kind": "signal", "enabled": True}]

    def test_defaults_enabled_true_when_field_absent(self):
        aws = make_aws()
        aws._ddb.query.return_value = {"Items": [{"rule_id": {"S": "r1"}}]}
        logger = MagicMock()

        result = load_detection_rules(aws, logger, rule_kind="signal")

        assert len(result) == 1

    def test_filters_out_disabled_rules(self):
        aws = make_aws()
        aws._ddb.query.return_value = {
            "Items": [
                {"rule_id": {"S": "r1"}, "enabled": {"BOOL": True}},
                {"rule_id": {"S": "r2"}, "enabled": {"BOOL": False}},
            ]
        }
        logger = MagicMock()

        result = load_detection_rules(aws, logger, rule_kind="signal")

        assert [r["rule_id"] for r in result] == ["r1"]

    def test_query_uses_expected_key_condition(self):
        aws = make_aws()
        aws._ddb.query.return_value = {"Items": []}
        logger = MagicMock()

        load_detection_rules(aws, logger, rule_kind="correlation")

        kwargs = aws._ddb.query.call_args.kwargs
        assert kwargs["TableName"] == "test-rules-table"
        assert kwargs["KeyConditionExpression"] == "#pk = :rk"
        assert kwargs["ExpressionAttributeNames"] == {"#pk": "rule_kind"}
        assert kwargs["ExpressionAttributeValues"] == {":rk": {"S": "correlation"}}
        assert "ExclusiveStartKey" not in kwargs


class TestPagination:
    def test_handles_pagination_across_multiple_pages(self):
        aws = make_aws()
        aws._ddb.query.side_effect = [
            {
                "Items": [{"rule_id": {"S": "r1"}, "enabled": {"BOOL": True}}],
                "LastEvaluatedKey": {"rule_kind": {"S": "signal"}, "rule_id": {"S": "r1"}},
            },
            {"Items": [{"rule_id": {"S": "r2"}, "enabled": {"BOOL": True}}]},
        ]
        logger = MagicMock()

        result = load_detection_rules(aws, logger, rule_kind="signal")

        assert [r["rule_id"] for r in result] == ["r1", "r2"]
        assert aws._ddb.query.call_count == 2
        second_call_kwargs = aws._ddb.query.call_args_list[1].kwargs
        assert second_call_kwargs["ExclusiveStartKey"] == {
            "rule_kind": {"S": "signal"},
            "rule_id": {"S": "r1"},
        }


class TestErrorHandling:
    def test_client_error_logs_and_reraises(self):
        aws = make_aws()
        aws._ddb.query.side_effect = _client_error("AccessDenied")
        logger = MagicMock()

        with pytest.raises(ClientError):
            load_detection_rules(aws, logger, rule_kind="signal")

        logger.error.assert_called_once()
        assert logger.error.call_args.kwargs["event_name"] == "RULES_QUERY_FAILED"

    def test_generic_exception_logs_and_reraises(self):
        aws = make_aws()
        aws._ddb.query.side_effect = RuntimeError("boom")
        logger = MagicMock()

        with pytest.raises(RuntimeError, match="boom"):
            load_detection_rules(aws, logger, rule_kind="signal")

        logger.error.assert_called_once()
        assert logger.error.call_args.kwargs["event_name"] == "RULES_QUERY_FAILED"

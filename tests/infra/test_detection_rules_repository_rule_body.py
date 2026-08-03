"""Tests for _unmarshal_item's rule_body parsing in
src/infra/detection_rules_repository.py.

Covers the schema scripts/load_rules.sh actually writes (rule_kind/rule_id
as table keys, the full rule content serialized as a JSON string under
rule_body) -- the existing test_detection_rules_repository.py suite predates
this schema and never mocks a rule_body field at all, which is exactly why
it never caught that every rule's conditions were silently evaluating as []
(found via the Phase 5 post-deploy integrity check against a real deploy).
"""
from __future__ import annotations

import json
import os
from unittest.mock import MagicMock

import pytest

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

from src.infra.detection_rules_repository import load_detection_rules


def make_aws() -> MagicMock:
    aws = MagicMock()
    aws._ddb = MagicMock()
    return aws


@pytest.fixture(autouse=True)
def table_name_env(monkeypatch):
    monkeypatch.setenv("DETECTION_RULES_TABLE_NAME", "test-rules-table")


def _rule_body_item(rule: dict) -> dict:
    return {
        "rule_kind": {"S": rule["rule_kind"]},
        "rule_id": {"S": rule["rule_id"]},
        "rule_body": {"S": json.dumps(rule)},
    }


class TestRuleBodyParsing:
    def test_conditions_and_fields_surface_at_top_level(self):
        rule = {
            "rule_id": "001_console_login_no_mfa",
            "rule_kind": "signal",
            "enabled": True,
            "severity": "HIGH",
            "response_module": "",
            "conditions": [
                {"field": "activity_name", "op": "equals", "value": "ConsoleLogin"},
                {
                    "field": "raw_event.detail.additionalEventData.MFAUsed",
                    "op": "equals",
                    "value": "No",
                },
            ],
        }
        aws = make_aws()
        aws._ddb.query.return_value = {"Items": [_rule_body_item(rule)]}
        logger = MagicMock()

        result = load_detection_rules(aws, logger, rule_kind="signal")

        assert len(result) == 1
        assert result[0]["conditions"] == rule["conditions"]
        assert result[0]["severity"] == "HIGH"
        assert result[0]["response_module"] == ""

    def test_table_key_rule_id_and_rule_kind_win_over_embedded_copy(self):
        rule = {"rule_id": "embedded-id", "rule_kind": "signal", "enabled": True}
        item = _rule_body_item(rule)
        # Table keys are authoritative even if a stale rule_body copy disagrees.
        item["rule_id"] = {"S": "table-key-id"}
        aws = make_aws()
        aws._ddb.query.return_value = {"Items": [item]}
        logger = MagicMock()

        result = load_detection_rules(aws, logger, rule_kind="signal")

        assert result[0]["rule_id"] == "table-key-id"

    def test_disabled_rule_from_rule_body_is_filtered_out(self):
        rule = {"rule_id": "r1", "rule_kind": "signal", "enabled": False}
        aws = make_aws()
        aws._ddb.query.return_value = {"Items": [_rule_body_item(rule)]}
        logger = MagicMock()

        result = load_detection_rules(aws, logger, rule_kind="signal")

        assert result == []

    def test_malformed_rule_body_json_falls_back_to_raw_item(self):
        aws = make_aws()
        aws._ddb.query.return_value = {
            "Items": [
                {
                    "rule_kind": {"S": "signal"},
                    "rule_id": {"S": "r1"},
                    "rule_body": {"S": "{not valid json"},
                }
            ]
        }
        logger = MagicMock()

        result = load_detection_rules(aws, logger, rule_kind="signal")

        assert result == [{"rule_kind": "signal", "rule_id": "r1", "rule_body": "{not valid json"}]

    def test_rule_body_parsing_to_non_dict_falls_back_to_raw_item(self):
        aws = make_aws()
        aws._ddb.query.return_value = {
            "Items": [
                {
                    "rule_kind": {"S": "signal"},
                    "rule_id": {"S": "r1"},
                    "rule_body": {"S": "[1, 2, 3]"},
                }
            ]
        }
        logger = MagicMock()

        result = load_detection_rules(aws, logger, rule_kind="signal")

        assert result == [{"rule_kind": "signal", "rule_id": "r1", "rule_body": "[1, 2, 3]"}]

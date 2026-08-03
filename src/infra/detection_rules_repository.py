# src/infra/detection_rules_repository.py
from __future__ import annotations

import json
import os
from typing import Any

from boto3.dynamodb.types import TypeDeserializer
from botocore.exceptions import ClientError

from .aws_handler import AwsHandler
from .logger import Logger

_deser = TypeDeserializer()


def _unmarshal_item(item: dict[str, Any]) -> dict[str, Any]:
    # DynamoDB AttributeValue map -> plain python dict
    raw = {k: _deser.deserialize(v) for k, v in (item or {}).items()}

    # Current schema (scripts/load_rules.sh, PK=rule_kind/SK=rule_id) stores
    # the actual rule content as a JSON string under rule_body -- everything
    # a caller needs (conditions, enabled, severity, ...) lives in there, not
    # at this top level. Parse it back out rather than returning the raw
    # item wrapper: previously nothing did, so every rule's conditions
    # silently evaluated as [] and no rule could ever match (found via the
    # post-deploy integrity check, Phase 5 -- no existing unit test caught
    # this because none of them mock a rule_body field at all, they predate
    # this schema). rule_kind/rule_id from the actual table keys win over
    # any copy embedded in rule_body, since those are structurally
    # guaranteed correct.
    rule_body = raw.get("rule_body")
    if isinstance(rule_body, str):
        try:
            parsed = json.loads(rule_body)
        except (json.JSONDecodeError, TypeError):
            parsed = None
        if isinstance(parsed, dict):
            return {**parsed, "rule_kind": raw.get("rule_kind"), "rule_id": raw.get("rule_id")}

    return raw


def load_detection_rules(
    aws: AwsHandler,
    logger: Logger,
    *,
    rule_kind: str,
) -> list[dict[str, Any]]:
    """
    Load rules using the new schema:
      PK = rule_kind
      SK = rule_id

    Returns plain JSON dict rules (NOT DynamoDB typed attributes).
    """
    table_name = os.environ.get("DETECTION_RULES_TABLE_NAME", "")
    if not table_name:
        logger.error(
            event_name="RULES_TABLE_MISSING",
            event_type="SYSTEM",
            message="DETECTION_RULES_TABLE_NAME env var is not set",
        )
        return []

    if not rule_kind:
        logger.error(
            event_name="RULES_KIND_MISSING",
            event_type="SYSTEM",
            message="rule_kind was not provided to load_detection_rules",
        )
        return []

    rules: list[dict[str, Any]] = []
    last_evaluated_key: dict[str, Any] | None = None

    # NOTE: we must use ExpressionAttributeNames because "rule_kind" is safe,
    # but doing it consistently avoids surprises if you rename later.
    expr_attr_names = {"#pk": "rule_kind"}
    expr_attr_values = {":rk": {"S": str(rule_kind)}}

    try:
        while True:
            kwargs: dict[str, Any] = {
                "TableName": table_name,
                "KeyConditionExpression": "#pk = :rk",
                "ExpressionAttributeNames": expr_attr_names,
                "ExpressionAttributeValues": expr_attr_values,
            }
            if last_evaluated_key:
                kwargs["ExclusiveStartKey"] = last_evaluated_key

            resp = aws._ddb.query(**kwargs)
            for it in resp.get("Items", []) or []:
                rules.append(_unmarshal_item(it))

            last_evaluated_key = resp.get("LastEvaluatedKey")
            if not last_evaluated_key:
                break

    except ClientError as e:
        logger.error(
            event_name="RULES_QUERY_FAILED",
            event_type="SYSTEM",
            message="Failed to query detection rules table",
            details={"rule_kind": rule_kind, "error_code": e.response.get("Error", {}).get("Code")},
        )
        raise
    except Exception as e:
        logger.error(
            event_name="RULES_QUERY_FAILED",
            event_type="SYSTEM",
            message="Failed to query detection rules table",
            details={"rule_kind": rule_kind, "error": str(e)},
        )
        raise

    enabled = [r for r in rules if bool(r.get("enabled", True))]

    logger.info(
        event_name="LOAD_RULES_OK",
        event_type="SYSTEM",
        message="Loaded rules",
        details={"rule_kind": rule_kind, "total": len(rules), "enabled": len(enabled)},
    )

    return enabled

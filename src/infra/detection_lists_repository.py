"""Read active, versioned detection-list snapshots from DynamoDB."""

from __future__ import annotations

import os
from typing import Any

from boto3.dynamodb.types import TypeDeserializer
from botocore.exceptions import ClientError

from .aws_handler import AwsHandler
from .detection_rules_repository import load_detection_rules
from .logger import Logger

_deser = TypeDeserializer()


def _plain(item: dict[str, Any]) -> dict[str, Any]:
    return {key: _deser.deserialize(value) for key, value in item.items()}


def load_detection_lists(
    aws: AwsHandler, logger: Logger, *, legacy_fallback: bool = True
) -> dict[str, dict[str, Any]]:
    """Return active snapshots keyed by list ID.

    The new table is authoritative when it contains any metadata records.
    Legacy rule_kind=list rows are read only while the migration fallback is
    enabled and the dedicated table has no lists yet.
    """
    table_name = os.environ.get("DETECTION_LISTS_TABLE_NAME", "")
    snapshots: dict[str, dict[str, Any]] = {}
    dedicated_metadata_found = False
    if table_name:
        try:
            metadata: list[dict[str, Any]] = []
            cursor = None
            while True:
                kwargs: dict[str, Any] = {
                    "TableName": table_name,
                    "IndexName": "gsi_list_metadata",
                    "KeyConditionExpression": "item_type = :metadata",
                    "ExpressionAttributeValues": {":metadata": {"S": "METADATA"}},
                }
                if cursor:
                    kwargs["ExclusiveStartKey"] = cursor
                response = aws._ddb.query(**kwargs)
                metadata.extend(_plain(item) for item in response.get("Items", []))
                cursor = response.get("LastEvaluatedKey")
                if not cursor:
                    break

            dedicated_metadata_found = bool(metadata)

            for meta in metadata:
                version_id = str(meta.get("active_version_id") or "")
                if not version_id:
                    continue
                values: list[str] = []
                cursor = None
                prefix = f"VERSION#{version_id}#VALUE#"
                while True:
                    kwargs = {
                        "TableName": table_name,
                        "KeyConditionExpression": "list_id = :list_id AND begins_with(item_key, :prefix)",
                        "ExpressionAttributeValues": {
                            ":list_id": {"S": str(meta["list_id"])},
                            ":prefix": {"S": prefix},
                        },
                        "ConsistentRead": True,
                    }
                    if cursor:
                        kwargs["ExclusiveStartKey"] = cursor
                    response = aws._ddb.query(**kwargs)
                    values.extend(
                        str(_plain(item).get("value")) for item in response.get("Items", [])
                    )
                    cursor = response.get("LastEvaluatedKey")
                    if not cursor:
                        break
                if not values:
                    logger.error(
                        event_name="LIST_ACTIVE_VERSION_EMPTY",
                        event_type="SYSTEM",
                        message="Ignoring a list whose active version has no values",
                        details={"list_id": str(meta["list_id"])},
                    )
                    continue
                snapshots[str(meta["list_id"])] = {
                    "matcher": str(meta.get("matcher") or "exact"),
                    "value_type": str(meta.get("value_type") or "string"),
                    "version": int(meta.get("active_version") or 1),
                    "values": values,
                }
        except ClientError as exc:
            logger.error(
                event_name="LISTS_QUERY_FAILED",
                event_type="SYSTEM",
                message="Failed to load dedicated detection lists",
                details={"error_code": exc.response.get("Error", {}).get("Code")},
            )
            raise

    if dedicated_metadata_found or snapshots or not legacy_fallback:
        return snapshots

    legacy = load_detection_rules(aws, logger, rule_kind="list")
    if legacy:
        logger.warning(
            event_name="LEGACY_LISTS_FALLBACK",
            event_type="SYSTEM",
            message="Using rule_kind=list rows; migrate them to the dedicated lists table",
        )
    return {
        str(item["rule_id"]): {
            "matcher": "exact",
            "value_type": "string",
            "version": int(item.get("version") or 1),
            "values": list(item.get("values") or []),
        }
        for item in legacy
    }

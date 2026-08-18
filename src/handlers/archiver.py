# src/handlers/archiver.py
"""
Streams new signals/alerts/logs to S3 (Parquet, via Kinesis Data Firehose)
for cold-storage/investigation -- DynamoDB now TTLs these tables at 90
days (see docs/data-archival.md), so this is what makes that safe rather
than a silent data-loss policy.

One Lambda, three DynamoDB Streams event sources (signals/alerts/logs
tables) -- which table a given invocation's batch came from is read off
each record's eventSourceARN, not passed via environment (event source
mappings don't support per-mapping env var overrides). In practice one
invocation's Records are always from a single stream (each event source
mapping is bound to one stream), but the routing is written generically
rather than assuming that.

Deliberately does NOT ask Firehose/Glue to model nested JSON structs
(actor/network/api/resources) or do date-math in Firehose's own JQ
metadata-extraction processor -- both are real, easy-to-get-subtly-wrong
AWS-side configurations with no way to verify them without a real
deploy (no AWS credentials exist in the environment this was built in).
Instead this Lambda flattens each record to a handful of stable, useful
scalar columns plus one raw_item column holding the full original item
as a JSON string, and precomputes the account/year/month/day/hour
partition fields directly in Python, where they're actually testable.
Firehose's processor just extracts fields that already exist verbatim.
"""
from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from typing import Any

import boto3
from boto3.dynamodb.types import TypeDeserializer

from ..infra.logger import Logger
from ..infra.xray_setup import patch_boto3

patch_boto3()

LAMBDA_NAME = os.getenv("LAMBDA_NAME", "unknown")
_SERVICE = os.getenv("SERVICE_NAME", "OPENCDR-ARCHIVER")

_firehose = boto3.client("firehose")
_deserializer = TypeDeserializer()

# eventSourceARN table-name fragment -> (env var holding the target
# Firehose delivery stream's name, doc type / flattener to use)
_STREAM_ROUTES: dict[str, tuple[str, str]] = {
    "signals-table": ("SIGNALS_FIREHOSE_STREAM_NAME", "signal"),
    "alerts-table": ("ALERTS_FIREHOSE_STREAM_NAME", "alert"),
    "logs-table": ("LOGS_FIREHOSE_STREAM_NAME", "log"),
}


def _route_for(event_source_arn: str) -> tuple[str, str] | None:
    for fragment, route in _STREAM_ROUTES.items():
        if fragment in event_source_arn:
            return route
    return None


def _ddb_image_to_dict(image: dict[str, Any]) -> dict[str, Any]:
    return {k: _deserializer.deserialize(v) for k, v in (image or {}).items()}


def partition_fields(timestamp_iso: str | None, account_id: str | None) -> dict[str, str]:
    """
    Hive-style partition values: account=X/year=Y/month=M/day=D/hour=H.
    Falls back to "unknown"-shaped values rather than raising -- a
    partition-field problem must not be able to drop an archival record
    entirely (it still lands in S3, just under a less useful prefix).
    """
    try:
        dt = datetime.fromisoformat((timestamp_iso or "").replace("Z", "+00:00"))
    except (ValueError, TypeError):
        dt = datetime.now(UTC)

    return {
        "account": str(account_id) if account_id else "none",
        "year": f"{dt.year:04d}",
        "month": f"{dt.month:02d}",
        "day": f"{dt.day:02d}",
        "hour": f"{dt.hour:02d}",
    }


def flatten_signal(item: dict) -> dict:
    actor = item.get("actor") or {}
    return {
        "detection_id": str(item.get("detection_id") or ""),
        "event_id": str(item.get("event_id") or ""),
        "rule_id": str(item.get("rule_id") or ""),
        "severity": str(item.get("severity") or ""),
        "timestamp": str(item.get("timestamp") or ""),
        "category": str(item.get("category") or ""),
        "activity_name": str(item.get("activity_name") or ""),
        "cloud_account_id": str(item.get("cloud_account_id") or ""),
        "cloud_region": str(item.get("cloud_region") or ""),
        "source": str(item.get("source") or ""),
        "actor_user_name": str(actor.get("user_name") or ""),
        "raw_item": json.dumps(item, default=str),
        **partition_fields(item.get("timestamp"), item.get("cloud_account_id")),
    }


def flatten_alert(item: dict) -> dict:
    primary_signal = item.get("primary_signal") or {}
    account_id = primary_signal.get("cloud_account_id")
    return {
        "alert_id": str(item.get("alert_id") or ""),
        "alert_key": str(item.get("alert_key") or ""),
        "rule_id": str(item.get("rule_id") or ""),
        "severity": str(item.get("severity") or ""),
        "timestamp": str(item.get("timestamp") or ""),
        "type": str(item.get("type") or ""),
        "group_value": str(item.get("group_value") or ""),
        "cloud_account_id": str(account_id or ""),
        "match_count": int(item.get("match_count") or 0),
        "raw_item": json.dumps(item, default=str),
        **partition_fields(item.get("timestamp"), account_id),
    }


def flatten_log(item: dict) -> dict:
    # Logs are OpenCDR's own operational/audit trail, not always tied to
    # a monitored AWS account the way a signal/alert is -- an
    # account-less log (most of them) archives under account=none,
    # which is the correct, expected outcome, not a bug.
    details = item.get("details") or {}
    account_id = details.get("account_id") or details.get("aws_account_id")
    return {
        "log_id": str(item.get("log_id") or ""),
        "event_id": str(item.get("event_id") or ""),
        "event_name": str(item.get("event_name") or ""),
        "event_type": str(item.get("event_type") or ""),
        "service": str(item.get("service") or ""),
        "source": str(item.get("source") or ""),
        "timestamp": str(item.get("timestamp") or ""),
        "level": str(details.get("level") or ""),
        "raw_item": json.dumps(item, default=str),
        **partition_fields(item.get("timestamp"), account_id),
    }


_FLATTENERS = {
    "signal": flatten_signal,
    "alert": flatten_alert,
    "log": flatten_log,
}


def _record_id(flattened: dict) -> str:
    """Whichever id column a flattened record actually has -- used only
    for the archived_ids trace in the batch-complete log below."""
    for column in ("detection_id", "alert_id", "log_id"):
        if flattened.get(column):
            return flattened[column]
    return ""


def lambda_handler(event: dict, context) -> dict:
    request_id = getattr(context, "aws_request_id", None)
    logger = Logger(service=_SERVICE, source=LAMBDA_NAME, request_id=request_id)

    skipped = 0
    flatten_failed = 0
    # doc records to send, grouped by target Firehose stream so each
    # stream gets one PutRecordBatch call instead of one PutRecord per
    # DynamoDB record.
    batches: dict[str, list[dict]] = {}

    for record in event.get("Records", []) or []:
        if record.get("eventName") != "INSERT":
            # TTL-driven deletes (and any future MODIFY) arrive on this
            # same stream as REMOVE/MODIFY events -- only a genuinely new
            # item is something to archive; re-archiving on every update
            # or reacting to an expiry would be wrong.
            skipped += 1
            continue

        route = _route_for(record.get("eventSourceARN", "") or "")
        if route is None:
            skipped += 1
            continue
        stream_env_var, doc_type = route

        stream_name = os.environ.get(stream_env_var)
        if not stream_name:
            skipped += 1
            continue

        new_image = (record.get("dynamodb") or {}).get("NewImage")
        if not new_image:
            skipped += 1
            continue

        try:
            item = _ddb_image_to_dict(new_image)
            flattened = _FLATTENERS[doc_type](item)
        except Exception as e:
            # A single malformed record must not take the rest of the
            # batch down with it -- same reasoning as responder.py's own
            # per-record isolation.
            flatten_failed += 1
            logger.error(
                event_name="ARCHIVE_FLATTEN_FAILED",
                event_type="ERROR",
                message="Failed to flatten a DynamoDB record for archival",
                details={"doc_type": doc_type, "error": repr(e)},
            )
            continue

        batches.setdefault(stream_name, []).append(flattened)

    sent = 0
    delivery_failed = 0
    archived_ids: list[str] = []
    for stream_name, records in batches.items():
        firehose_records = [
            {"Data": (json.dumps(r, default=str) + "\n").encode("utf-8")} for r in records
        ]
        resp = _firehose.put_record_batch(DeliveryStreamName=stream_name, Records=firehose_records)
        failed_count = resp.get("FailedPutCount", 0)
        sent += len(records) - failed_count
        delivery_failed += failed_count
        archived_ids.extend(_record_id(r) for r in records)

    # archived_ids goes in this one already-existing summary log line
    # rather than a new log per record -- the whole point of this feature
    # is reducing DynamoDB log volume (see LOGS_MIN_LEVEL_TO_STORE), not
    # adding to it. Lets a post-deploy check (or a real operator) confirm
    # a specific detection_id/alert_id/log_id actually made it through
    # archival by grepping this Lambda's recent logs, without needing to
    # wait for the slower, eventually-consistent S3/Parquet write itself.
    logger.info(
        event_name="ARCHIVE_BATCH_COMPLETE",
        event_type="PROCESSING",
        message="Archival batch processed",
        details={
            "sent": sent,
            "skipped": skipped,
            "flatten_failed": flatten_failed,
            "delivery_failed": delivery_failed,
            "archived_ids": archived_ids,
        },
    )

    if delivery_failed:
        # Raise so this batch retries via the stream's own
        # bisectBatchOnFunctionError/maximumRetryAttempts/DLQ config
        # (same reliability pattern already used by alerter/publisher) --
        # a Firehose PutRecordBatch partial failure is usually transient
        # (throttling), worth retrying automatically rather than
        # silently losing archival records.
        raise RuntimeError(
            f"{delivery_failed} of {sent + delivery_failed} record(s) rejected by Firehose"
        )

    return {"sent": sent, "skipped": skipped, "flatten_failed": flatten_failed}

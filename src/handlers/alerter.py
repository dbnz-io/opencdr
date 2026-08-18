# src/handlers/alerter.py
from __future__ import annotations

import json
import os
import time
import uuid
from datetime import UTC, datetime
from typing import Any

from boto3.dynamodb.conditions import Key
from boto3.dynamodb.types import TypeDeserializer

from ..domain.correlation_engine import CorrelationEngine
from ..infra.aws_handler import AwsHandler, ttl_expires_at
from ..infra.detection_rules_repository import load_detection_rules
from ..infra.logger import Logger
from ..infra.metrics import emit_metric
from ..infra.xray_setup import patch_boto3

patch_boto3()

# ----------------------------
# Env
# ----------------------------

SIGNALS_TABLE_NAME = os.getenv("SIGNALS_TABLE_NAME", "")
SIGNALS_WRITE_QUEUE_URL = os.getenv("SIGNALS_WRITE_QUEUE_URL", "")
ALERTS_TABLE_NAME = os.getenv("ALERTS_TABLE_NAME", "")  # optional, but recommended
OUTBOX_TABLE_NAME = os.getenv("OUTBOX_TABLE_NAME", "")  # optional
DEFAULT_QUERY_LIMIT = int(os.getenv("CORRELATION_QUERY_LIMIT", "300"))


# ----------------------------
# DynamoDB stream helpers
# ----------------------------

_deser = TypeDeserializer()


def _ddb_image_to_dict(image: dict[str, Any]) -> dict[str, Any]:
    return {k: _deser.deserialize(v) for k, v in (image or {}).items()}


def _parse_iso(ts: Any) -> datetime | None:
    if not ts or not isinstance(ts, str):
        return None
    t = ts.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(t)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt
    except Exception:
        return None


# ----------------------------
# Rules cache
# ----------------------------

# Same pattern as notifier.py's settings cache (SETTINGS_TTL_SECONDS).
CORR_RULES_TTL_SECONDS = int(os.getenv("ALERTER_CORR_RULES_TTL_SECONDS", "60"))

CORR_RULES_CACHE: list[dict[str, Any]] | None = None
CORR_RULES_CACHE_LOADED_AT: float = 0.0


def get_correlation_rules(*, aws: AwsHandler, logger: Logger) -> list[dict[str, Any]]:
    global CORR_RULES_CACHE, CORR_RULES_CACHE_LOADED_AT
    now = time.time()
    if CORR_RULES_CACHE is None or (now - CORR_RULES_CACHE_LOADED_AT) >= CORR_RULES_TTL_SECONDS:
        CORR_RULES_CACHE = load_detection_rules(aws, logger, rule_kind="correlation")
        CORR_RULES_CACHE_LOADED_AT = now
    return CORR_RULES_CACHE


# ----------------------------
# Repo for correlation engine
# ----------------------------

# group_by dot-path -> (GSI name, flat top-level attribute it's keyed on).
# Only actor.user_name is indexed today -- it's the highest-volume group_by
# (all pure-CloudTrail correlation rules, support_files/detection_rules/
# cloudtrail/020-023_correlation_*.json, plus 029's cross-source rule).
# A rule using any other group_by falls back to the scan-and-filter path --
# see 030_correlation_guardduty_backdoor_then_secrets_access.json
# (support_files/detection_rules/correlation/), grouped by network.source_ip,
# for the first (and so far only) rule that actually uses it.
_INDEXED_GROUP_BY_FIELDS: dict[str, tuple[str, str]] = {
    "actor.user_name": ("gsi_signal_actor_user_name", "actor_user_name"),
}


class DynamoSignalsRepository:
    """
    Signal lookups for correlation. Indexed group_by fields (see
    _INDEXED_GROUP_BY_FIELDS) query a GSI directly; anything else falls
    back to a full table scan-and-filter -- correct for any dot-path, but
    expensive, and only meant as a rare/generic path today.
    """

    def __init__(self, *, aws: AwsHandler, logger: Logger, table_name: str):
        self.aws = aws
        self.logger = logger
        self.table_name = table_name

    def query_signals(
        self,
        *,
        since: datetime,
        group_by_field: str,
        group_value: str,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        if not self.table_name:
            return []

        start = datetime.now(UTC)
        indexed = _INDEXED_GROUP_BY_FIELDS.get(group_by_field)

        if indexed:
            index_name, key_attr = indexed
            query_mode = "gsi"
            results = self._query_via_gsi(
                index_name=index_name,
                key_attr=key_attr,
                since=since,
                group_value=group_value,
                limit=limit,
            )
        else:
            query_mode = "scan"
            results = self._scan_and_filter(
                since=since,
                group_by_field=group_by_field,
                group_value=group_value,
                limit=limit,
            )

        self.logger.info(
            event_name="ALERTER_SIGNALS_QUERY",
            event_type="PROCESSING",
            message="Fetched signals for correlation",
            details={
                "table": self.table_name,
                "since": since.isoformat(),
                "group_by": group_by_field,
                "group_value": str(group_value),
                "returned": len(results),
                "limit": limit,
                "query_mode": query_mode,
                "latency_ms": int((datetime.now(UTC) - start).total_seconds() * 1000),
            },
        )

        return results

    def _query_via_gsi(
        self,
        *,
        index_name: str,
        key_attr: str,
        since: datetime,
        group_value: str,
        limit: int,
    ) -> list[dict[str, Any]]:
        table = self.aws._ddb_resource.Table(self.table_name)
        results: list[dict[str, Any]] = []
        query_kwargs: dict[str, Any] = {
            "IndexName": index_name,
            "KeyConditionExpression": Key(key_attr).eq(group_value) & Key("timestamp").gte(since.isoformat()),
        }

        while True:
            resp = table.query(**query_kwargs)

            for item in resp.get("Items", []) or []:
                # Skip correlation records — they are outputs, not inputs
                if item.get("item_type") == "correlation":
                    continue
                results.append(item)
                if len(results) >= limit:
                    break

            if len(results) >= limit:
                break

            lek = resp.get("LastEvaluatedKey")
            if not lek:
                break
            query_kwargs["ExclusiveStartKey"] = lek

        return results

    def _scan_and_filter(
        self,
        *,
        since: datetime,
        group_by_field: str,
        group_value: str,
        limit: int,
    ) -> list[dict[str, Any]]:
        """
        Generic fallback for a group_by field with no GSI (see
        _INDEXED_GROUP_BY_FIELDS above) -- correct for any dot-path, but
        scans the whole table. Used by
        030_correlation_guardduty_backdoor_then_secrets_access.json
        (group_by="network.source_ip") -- the first shipped rule to hit
        this path; no GSI added for it since nothing else uses it yet.
        """
        self.logger.warning(
            event_name="ALERTER_SIGNALS_SCAN_FALLBACK",
            event_type="PROCESSING",
            message="group_by has no GSI, falling back to a full table scan",
            details={"table": self.table_name, "group_by": group_by_field},
        )

        results: list[dict[str, Any]] = []
        scan_kwargs: dict[str, Any] = {}

        while True:
            resp = self.aws._ddb.scan(TableName=self.table_name, **scan_kwargs)
            items = resp.get("Items", []) or []

            for it in items:
                s = {k: _deser.deserialize(v) for k, v in it.items()}

                # Skip correlation records — they are outputs, not inputs
                if s.get("item_type") == "correlation":
                    continue

                ts_dt = _parse_iso(s.get("timestamp"))
                if not ts_dt or ts_dt < since:
                    continue

                # Resolve group_by_field from dict (supports dot-path)
                cur: Any = s
                ok = True
                for part in group_by_field.split("."):
                    if isinstance(cur, dict) and part in cur:
                        cur = cur.get(part)
                    else:
                        ok = False
                        break
                if not ok or cur is None:
                    continue

                if str(cur) != str(group_value):
                    continue

                results.append(s)
                if len(results) >= limit:
                    break

            if len(results) >= limit:
                break

            lek = resp.get("LastEvaluatedKey")
            if not lek:
                break
            scan_kwargs["ExclusiveStartKey"] = lek

        return results


# ----------------------------
# Storage builders
# ----------------------------
def _build_alert_item(alert: dict[str, Any]) -> dict[str, Any]:
    return {
        # keys you query on
        "alert_key": alert["alert_key"],
        "timestamp": alert["timestamp"],
        "alert_id": alert["alert_id"],
        "rule_id": alert.get("rule_id", ""),
        "severity": alert.get("severity", "UNKNOWN"),
        # full object for responders/notifications
        "payload": alert,  # <-- store FULL alert, not the reduced one
    }


def _marshal_outbox(*, payload: dict[str, Any], destinations: list[str]) -> dict[str, Any]:
    outbox_id = str(uuid.uuid4())
    now = datetime.now(UTC).isoformat()

    return {
        "outbox_id": {"S": outbox_id},
        "timestamp": {"S": now},
        "status": {"S": "PENDING"},
        "destinations": {"S": json.dumps(destinations)},
        "attempts": {"N": "0"},
        "payload": {"S": json.dumps(payload)},
        "expires_at": {"N": str(ttl_expires_at())},
    }


# ----------------------------
# Lambda handler
# ----------------------------


def lambda_handler(event, context):
    request_id = context.aws_request_id if context else None

    base_logger = Logger(
        service=os.getenv("SERVICE_NAME", "OPENCDR"),
        source="ocdr.alerter",
        request_id=request_id,
        event_id="NOT_USED",
    )

    # logger may be rebound inside the loop; initialise here so it's always defined
    logger = base_logger

    for rec in event.get("Records", []) or []:
        if rec.get("eventName") not in ("INSERT", "MODIFY"):
            continue

        new_image = (rec.get("dynamodb") or {}).get("NewImage")
        if not new_image:
            continue

        signal = _ddb_image_to_dict(new_image)

        # Skip correlation records written back to the signals table — prevents infinite loop
        if signal.get("item_type") == "correlation":
            continue

        eid = (signal.get("event_id") or "").strip()
        logger = base_logger.bind(event_id=eid) if eid else base_logger

        logger.info(
            event_name="ALERTER_SIGNAL_RECEIVED",
            message="Got signal from stream",
            details={"rule_id": signal.get("rule_id"), "detection_id": signal.get("detection_id")},
        )

    aws = AwsHandler(logger=base_logger)

    records = event.get("Records", []) or []
    logger.info(
        event_name="ALERTER_START",
        event_type="PROCESSING",
        message="Processing stream batch",
        details={"records": len(records)},
    )

    if not SIGNALS_TABLE_NAME:
        logger.error(
            event_name="ALERTER_MISCONFIG",
            event_type="SYSTEM",
            message="SIGNALS_TABLE_NAME is not set",
        )
        raise RuntimeError("Missing SIGNALS_TABLE_NAME")

    # Correlation engine + repo
    repo = DynamoSignalsRepository(aws=aws, logger=logger, table_name=SIGNALS_TABLE_NAME)
    engine = CorrelationEngine(repo=repo)

    # Load correlation rules (cached)
    corr_rules = get_correlation_rules(aws=aws, logger=logger)
    if not corr_rules:
        logger.info(
            event_name="ALERTER_NO_RULES",
            event_type="SYSTEM",
            message="No correlation rules configured/enabled (rule_kind=correlation)",
        )
        return {"status": "no_rules"}

    created_alerts = 0
    stored_alerts = 0
    outboxed = 0

    for rec in records:
        if rec.get("eventName") not in ("INSERT", "MODIFY"):
            continue

        ddb = rec.get("dynamodb") or {}
        new_image = ddb.get("NewImage")
        if not new_image:
            continue

        signal = _ddb_image_to_dict(new_image)

        # Skip correlation records written back to the signals table — prevents infinite loop
        if signal.get("item_type") == "correlation":
            continue

        now = datetime.now(UTC)

        alerts = engine.correlate(new_signal=signal, rules=corr_rules, now=now)
        if not alerts:
            continue

        created_alerts += len(alerts)

        for alert in alerts:
            logger.info(
                event_name="ALERT_CREATED",
                event_type="DETECTION",
                message="Correlation alert produced",
                details={
                    "alert_key": alert.get("alert_key"),
                    "rule_id": alert.get("rule_id"),
                    "match_count": alert.get("match_count"),
                },
            )
            emit_metric(
                "CorrelationMatches",
                dimensions={"rule_id": str(alert.get("rule_id", "unknown"))},
            )

            # Store alert idempotently (recommended). should_outbox defaults
            # True: with no ALERTS_TABLE_NAME configured there's no dedup
            # mechanism at all, so outboxing every match is the accepted
            # behavior for that configuration choice, not a bug. Once
            # ALERTS_TABLE_NAME *is* configured, only a genuinely new
            # (non-duplicate) alert should reach the outbox.
            should_outbox = True
            if ALERTS_TABLE_NAME:
                alert_item = _build_alert_item(alert)

                inserted = aws.put_alert_if_not_exists(
                    table_name=ALERTS_TABLE_NAME,
                    alert_item=alert_item,
                    id_attribute="alert_key",
                    success_event_name="ALERT_STORE_OK",
                    duplicate_event_name="ALERT_STORE_DUP",
                    failure_event_name="ALERT_STORE_FAIL",
                    details={"rule_id": alert.get("rule_id")},
                )
                should_outbox = inserted
                if inserted:
                    stored_alerts += 1

                    # Write correlation result back to signals table so it appears
                    # in the unified signal log. item_type="correlation" prevents
                    # the alerter stream trigger from re-processing it. Enqueued
                    # via signal_writer.py (see serverless.yml's SIGNALS TABLE V2
                    # comment) rather than written directly, same as processor.py
                    # -- this was already fire-and-forget (return value unused),
                    # so routing it through the buffer is a zero-risk swap.
                    if SIGNALS_TABLE_NAME:
                        corr_signal = dict(alert)
                        corr_signal["item_type"] = "correlation"
                        corr_signal["detection_id"] = str(alert["alert_id"])
                        aws.sqs_send(
                            queue_url=SIGNALS_WRITE_QUEUE_URL,
                            body=corr_signal,
                            success_event_name="SIGNAL_ENQUEUED",
                            failure_event_name="SIGNAL_ENQUEUE_FAIL",
                        )

            # Write outbox for publisher (optional) -- only for a genuinely
            # new alert (see should_outbox above), not a duplicate.
            if should_outbox and OUTBOX_TABLE_NAME:
                outbox_item = _marshal_outbox(
                    payload=alert, destinations=["notifications", "responses"]
                )
                aws.ddb_put_item(
                    table_name=OUTBOX_TABLE_NAME,
                    item=outbox_item,
                    log_event_name="ALERT_OUTBOX_PUT_OK",
                    details={"alert_key": alert.get("alert_key"), "rule_id": alert.get("rule_id")},
                )
                outboxed += 1

    logger.info(
        event_name="ALERTER_DONE",
        event_type="PROCESSING",
        message="Finished processing batch",
        details={
            "alerts_created": created_alerts,
            "alerts_stored": stored_alerts,
            "outboxed": outboxed,
        },
    )

    return {
        "status": "ok",
        "alerts_created": created_alerts,
        "alerts_stored": stored_alerts,
        "outboxed": outboxed,
    }

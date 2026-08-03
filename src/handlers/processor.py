# src/handlers/processor.py
from __future__ import annotations

import os
import time

from ..domain.detection_engine import run_detection
from ..domain.ocsf_min_parser import build_default_router
from ..infra.aws_handler import AwsHandler
from ..infra.detection_rules_repository import load_detection_rules  # used by get_rules()
from ..infra.logger import Logger
from ..infra.metrics import emit_metric
from ..infra.xray_setup import patch_boto3

patch_boto3()

SIGNALS_TABLE_NAME = os.environ["SIGNALS_TABLE_NAME"]
ALERTS_TABLE_NAME = os.getenv("ALERTS_TABLE_NAME", "")
OUTBOX_TABLE_NAME = os.getenv("OUTBOX_TABLE_NAME", "")

# Rule/list cache TTL (warm Lambda reuse) -- same pattern as notifier.py's
# settings cache (SETTINGS_TTL_SECONDS).
RULES_TTL_SECONDS = int(os.getenv("PROCESSOR_RULES_TTL_SECONDS", "60"))

# ----------------------------
# Globals (cold start cache)
# ----------------------------
RULES_CACHE = None
RULES_CACHE_LOADED_AT = 0.0
LISTS_CACHE = None
LISTS_CACHE_LOADED_AT = 0.0
router = build_default_router()


def get_rules(aws: AwsHandler, ocdr_logger: Logger):
    """
    Load rules once per Lambda container, refreshed every RULES_TTL_SECONDS.
    """
    global RULES_CACHE, RULES_CACHE_LOADED_AT
    now = time.time()
    if RULES_CACHE is None or (now - RULES_CACHE_LOADED_AT) >= RULES_TTL_SECONDS:
        ocdr_logger.info(
            event_name="RULES_CACHE_MISS",
            event_type="SYSTEM",
            message="Loading detection rules",
        )
        RULES_CACHE = load_detection_rules(aws, ocdr_logger, rule_kind="signal")
        RULES_CACHE_LOADED_AT = now

    return RULES_CACHE


def get_lists(aws: AwsHandler, ocdr_logger: Logger) -> dict[str, list]:
    """
    Load lists once per Lambda container, refreshed every RULES_TTL_SECONDS.
    Returns {list_id: [values]}.
    """
    global LISTS_CACHE, LISTS_CACHE_LOADED_AT
    now = time.time()
    if LISTS_CACHE is None or (now - LISTS_CACHE_LOADED_AT) >= RULES_TTL_SECONDS:
        ocdr_logger.info(
            event_name="LISTS_CACHE_MISS",
            event_type="SYSTEM",
            message="Loading detection lists",
        )
        raw = load_detection_rules(aws, ocdr_logger, rule_kind="list")
        LISTS_CACHE = {item["rule_id"]: item.get("values", []) for item in raw}
        LISTS_CACHE_LOADED_AT = now

    return LISTS_CACHE


# ----------------------------
# Lambda Handler
# ----------------------------


def lambda_handler(event, context):
    request_id = context.aws_request_id if context else None

    # Start logger without event_id first (because parse can fail)
    base_logger = Logger(
        service=os.getenv("SERVICE_NAME", "OPENCDR"),
        source="ocdr.processor",
        request_id=request_id,
    )

    try:
        normalized = router.parse(event)
    except Exception as e:
        base_logger.exception(
            event_name="PARSE_FAIL",
            error=e,
            details={
                "eventbridge_id": event.get("id"),
                "detail_type": event.get("detail-type"),
                "source": event.get("source"),
            },
        )
        raise

    event_id = getattr(normalized, "event_id", None)
    ocdr_logger = base_logger.bind(event_id=event_id)

    ocdr_logger.info(
        event_name="PROCESSOR_START",
        message="Processor received event",
        event_type="PROCESSING",
    )

    aws = AwsHandler(logger=ocdr_logger)

    # ----------------------------
    # 1. Parse → NormalizedEvent
    # ----------------------------

    if not normalized:
        ocdr_logger.info(
            event_name="EVENT_NOT_SUPPORTED",
            event_type="PROCESSING",
            message="No parser matched event",
        )
        return {"status": "ignored"}

    # ----------------------------
    # 2. Load rules
    # ----------------------------

    rules = get_rules(aws, ocdr_logger)

    if not rules:
        ocdr_logger.warning(
            event_name="NO_RULES",
            event_type="SYSTEM",
            message="No detection rules loaded",
        )
        return {"status": "no_rules"}

    # ----------------------------
    # 3. Run detection engine
    # ----------------------------

    lists = get_lists(aws, ocdr_logger)
    detections = run_detection(normalized, rules, lists=lists)

    if not detections:
        ocdr_logger.info(
            event_name="NO_DETECTION",
            event_type="PROCESSING",
            message="No rules matched",
        )
        return {"status": "no_detection"}

    # ----------------------------
    # 4. Store signals (idempotent)
    # ----------------------------

    stored = 0

    for detection in detections:
        try:
            inserted = aws.put_signal_if_not_exists(
                table_name=SIGNALS_TABLE_NAME,
                signal_item=detection,
            )

            if inserted:
                stored += 1
                emit_metric(
                    "SignalsCreated",
                    dimensions={
                        "rule_id": str(detection.get("rule_id", "unknown")),
                        "severity": str(detection.get("severity", "UNKNOWN")),
                    },
                )

        except Exception as e:
            ocdr_logger.error(
                event_name="SIGNAL_STORE_ERROR",
                event_type="STORAGE",
                message="Failed storing detection signal",
                details={
                    "error": str(e),
                    "detection_id": detection.get("detection_id"),
                },
            )
            raise

        if not inserted:
            continue

        if not detection.get("notify"):
            continue

        # Build a notifier-friendly alert item from the signal detection
        alert_item = {
            "alert_key": detection["detection_id"],
            "alert_id": detection["detection_id"],
            "detection_id": detection["detection_id"],
            "timestamp": detection["timestamp"],
            "rule_id": detection.get("rule_id", ""),
            "severity": detection.get("severity", "UNKNOWN"),
            "notify": True,
            "response_module": detection.get("response_module", "") or "",
            "playbook": detection.get("playbook", "") or "",
            "type": "signal",
            "match_count": 1,
            "event_id": detection.get("event_id", ""),
            "activity_name": detection.get("activity_name", ""),
            "actor": detection.get("actor", {}),
            "network": detection.get("network", {}),
            "api": detection.get("api", {}),
            "cloud_account_id": detection.get("cloud_account_id", ""),
            "cloud_region": detection.get("cloud_region", ""),
            "raw_event": detection.get("raw_event", {}),
        }

        if ALERTS_TABLE_NAME:
            try:
                alert_inserted = aws.put_alert_if_not_exists(
                    table_name=ALERTS_TABLE_NAME,
                    alert_item=alert_item,
                )
            except Exception as e:
                ocdr_logger.error(
                    event_name="ALERT_STORE_ERROR",
                    event_type="STORAGE",
                    message="Failed storing signal alert",
                    details={"error": str(e), "detection_id": detection.get("detection_id")},
                )
                alert_inserted = False
        else:
            alert_inserted = True  # no alerts table configured; still try outbox

        if alert_inserted and OUTBOX_TABLE_NAME:
            try:
                aws.put_outbox_record(
                    table_name=OUTBOX_TABLE_NAME,
                    payload=alert_item,
                    destinations=["notifications", "responses"],
                )
            except Exception as e:
                ocdr_logger.error(
                    event_name="OUTBOX_WRITE_ERROR",
                    event_type="STORAGE",
                    message="Failed writing signal to outbox",
                    details={"error": str(e), "detection_id": detection.get("detection_id")},
                )

    ocdr_logger.info(
        event_name="PROCESSOR_COMPLETE",
        event_type="PROCESSING",
        message="Processor finished",
        details={
            "detections": len(detections),
            "stored": stored,
        },
    )

    return {
        "status": "processed",
        "detections": len(detections),
        "stored": stored,
    }

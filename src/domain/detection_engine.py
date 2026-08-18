from __future__ import annotations

import logging
import re
import uuid
from datetime import UTC, datetime
from typing import Any

from .ocsf_min_parser import NormalizedEvent

# Pure domain logic deliberately has no dependency on src/infra/ (no Logger
# instance threaded through get_field/evaluate_condition/rule_matches/
# run_detection). Stdlib logging reaches CloudWatch automatically under
# Lambda's default logging config without that coupling.
_log = logging.getLogger(__name__)

# ----------------------------
# Field Resolver
# ----------------------------


def get_field(obj: Any, path: str):
    """
    Supports:
      actor.user_name
      network.source_ip
      api.operation
    """

    cur = obj

    for part in path.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            cur = getattr(cur, part, None)

        if cur is None:
            return None

    return cur


# ----------------------------
# Condition Engine
# ----------------------------


def evaluate_condition(
    event: NormalizedEvent, cond: dict, lists: dict[str, list] | None = None
) -> bool:
    field = cond.get("field")
    op = cond.get("op", "exists")
    value = cond.get("value")

    if op == "wildcard":
        return True

    observed = get_field(event, field)

    if op == "exists":
        return observed is not None

    if op == "not_exists":
        return observed is None

    if observed is None:
        return False

    observed = str(observed)

    if op == "equals":
        return observed == str(value)

    if op == "not_equals":
        return observed != str(value)

    def _as_list(v: Any) -> list[Any]:
        if v is None:
            return []
        if isinstance(v, list):
            return v
        return [v]

    if op == "in":
        return observed in [str(x) for x in _as_list(value)]
    if op == "not_in":
        return observed not in [str(x) for x in _as_list(value)]

    if op == "in_list":
        list_id = cond.get("list_id", "")
        values = (lists or {}).get(list_id, [])
        return observed in [str(v) for v in values]

    if op == "not_in_list":
        list_id = cond.get("list_id", "")
        values = (lists or {}).get(list_id, [])
        return observed not in [str(v) for v in values]

    if op == "contains":
        return str(value) in observed

    if op == "not_contains":
        return str(value) not in observed

    if op == "prefix":
        return observed.startswith(str(value))

    if op == "not_prefix":
        return not observed.startswith(str(value))

    if op == "suffix":
        return observed.endswith(str(value))

    if op == "not_suffix":
        return not observed.endswith(str(value))

    if op == "matches":
        try:
            return re.search(value, observed) is not None
        except re.error as exc:
            _log.warning(
                "detection_engine: regex compile failed for op=matches field=%r value=%r: %s",
                field,
                value,
                exc,
            )
            return False

    if op == "not_matches":
        try:
            return re.search(value, observed) is None
        except re.error as exc:
            _log.warning(
                "detection_engine: regex compile failed for op=not_matches field=%r value=%r: %s",
                field,
                value,
                exc,
            )
            return False

    _log.warning(
        "detection_engine: unknown condition operator op=%r field=%r -- treating as no-match",
        op,
        field,
    )
    return False


def rule_matches(
    event: NormalizedEvent, rule: dict, lists: dict[str, list] | None = None
) -> bool:
    conditions = rule.get("conditions", [])

    if not conditions:
        return False

    for cond in conditions:
        if not evaluate_condition(event, cond, lists=lists):
            return False

    return True


# ----------------------------
# Detection Builder
# ----------------------------


def build_detection_event(
    normalized_event: NormalizedEvent,
    rule: dict,
) -> dict:

    now = datetime.now(UTC).isoformat()

    severity = rule.get("severity", "LOW")

    detection = {
        # Required for DynamoDB signal table
        "detection_id": str(uuid.uuid4()),
        "timestamp": now,
        "severity": severity,
        "rule_id": rule.get("rule_id"),
        "notify": rule.get("notify", True),
        "response_module": rule.get("response_module"),
        "playbook": rule.get("playbook"),
        # normalized event context
        "event_id": normalized_event.event_id,
        "activity_name": normalized_event.activity_name,
        "category": normalized_event.category,
        "class_name": normalized_event.class_name,
        "source": normalized_event.source,
        "actor": normalized_event.actor.__dict__,
        "network": normalized_event.network.__dict__,
        "api": normalized_event.api.__dict__,
        "resources": [r.__dict__ for r in normalized_event.resources],
        "cloud_account_id": normalized_event.cloud_account_id,
        "cloud_region": normalized_event.cloud_region,
        "gd_resource_type": normalized_event.gd_resource_type,
        "raw_event": normalized_event.raw_event,
    }

    # Denormalized mirror of actor.user_name for gsi_signal_actor_user_name
    # (serverless.yml) -- GSI keys must be top-level scalars, not nested
    # inside a map. Only set when present so the GSI stays sparse: a signal
    # with no actor.user_name simply doesn't appear in it, same as it
    # couldn't be grouped by that field for correlation anyway.
    if normalized_event.actor.user_name:
        detection["actor_user_name"] = normalized_event.actor.user_name

    return detection


# ----------------------------
# Detection Pipeline
# ----------------------------


def run_detection(
    normalized_event: NormalizedEvent,
    rules: list[dict],
    lists: dict[str, list] | None = None,
) -> list[dict]:

    detections: list[dict] = []

    for rule in rules:
        if not rule.get("enabled", True):
            continue

        if not rule_matches(normalized_event, rule, lists=lists):
            continue

        detection = build_detection_event(normalized_event, rule)
        detections.append(detection)

    return detections

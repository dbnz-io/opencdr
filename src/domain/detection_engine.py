from __future__ import annotations

import logging
import os
import uuid
from datetime import UTC, datetime
from typing import Any

import regex

from .ocsf_min_parser import NormalizedEvent

# Pure domain logic deliberately has no dependency on src/infra/ (no Logger
# instance threaded through get_field/evaluate_condition/rule_matches/
# run_detection). Stdlib logging reaches CloudWatch automatically under
# Lambda's default logging config without that coupling.
_log = logging.getLogger(__name__)

# ReDoS protection for rule-supplied `matches`/`not_matches` patterns.
#
# The processor evaluates every event against every enabled rule, so a single
# catastrophic-backtracking pattern (e.g. authored by an attacker who wants a
# customer blind) can stall detection account-wide. The `regex` module has a
# more backtracking-resistant engine than stdlib `re` AND accepts a per-call
# `timeout=`, which raises TimeoutError rather than hanging -- the hard bound.
# A subject-length cap is cheap defense-in-depth. On timeout / oversized input
# / invalid pattern the match is treated as "could not evaluate" -> the
# condition is not satisfied (no spurious detection), mirroring the prior
# re.error behaviour. Tunable per deployment without a code change.
_REGEX_TIMEOUT_SECONDS = float(os.getenv("REGEX_EVAL_TIMEOUT_SECONDS", "1.0"))
_REGEX_MAX_SUBJECT_LEN = int(os.getenv("REGEX_MAX_SUBJECT_LEN", "100000"))


def _bounded_regex_search(pattern: str, subject: str, field, op) -> bool | None:
    """Return True/False for a match, or None if the pattern could not be
    safely evaluated (oversized subject, timeout, or invalid pattern).

    Never raises and never hangs -- the timeout bounds wall-time regardless of
    how pathological the pattern is.
    """
    if len(subject) > _REGEX_MAX_SUBJECT_LEN:
        _log.warning(
            "detection_engine: subject too long (%d > %d) for op=%s field=%r -- skipping regex",
            len(subject),
            _REGEX_MAX_SUBJECT_LEN,
            op,
            field,
        )
        return None
    try:
        return regex.search(pattern, subject, timeout=_REGEX_TIMEOUT_SECONDS) is not None
    except TimeoutError:
        _log.warning(
            "detection_engine: regex timed out after %ss for op=%s field=%r value=%r -- "
            "treating as no-match (possible ReDoS pattern)",
            _REGEX_TIMEOUT_SECONDS,
            op,
            field,
            pattern,
        )
        return None
    except (regex.error, TypeError) as exc:
        _log.warning(
            "detection_engine: regex failed for op=%s field=%r value=%r: %s",
            op,
            field,
            pattern,
            exc,
        )
        return None

# ----------------------------
# Field Resolver
# ----------------------------


def get_field(obj: Any, path: str):
    """
    Supports:
      actor.user_name
      network.source_ip
      api.operation

    Security: dotted paths are resolved by dict lookup where the current value
    is a dict, and by getattr otherwise. A real event field never starts with
    an underscore, so a path segment like "__class__"/"__globals__" is not a
    field lookup -- it is an attempt to walk out of the event object into
    Python internals (turning "can author a rule" into a memory-read
    primitive). Underscore-prefixed segments are refused on the getattr path
    and the field resolves to None. Dict-key access is left untouched (it
    cannot reach code objects), so arbitrary `raw_event.*` keys still work.
    """

    cur = obj

    for part in path.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            if part.startswith("_"):
                _log.warning(
                    "detection_engine: refusing disallowed field segment %r in path %r "
                    "(underscore-prefixed attribute access is not permitted)",
                    part,
                    path,
                )
                return None
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
        # None (could-not-evaluate) -> condition not satisfied.
        return _bounded_regex_search(value, observed, field, op) is True

    if op == "not_matches":
        # None (could-not-evaluate) -> condition not satisfied (no spurious fire).
        return _bounded_regex_search(value, observed, field, op) is False

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

    if normalized_event.integration_id:
        from .ingestion import CONTEXT_FIELDS, identity
        detection.update({key: getattr(normalized_event, key) for key in CONTEXT_FIELDS})
        entity = normalized_event.container.get("id") or normalized_event.host.get("id") or normalized_event.host.get("name")
        if entity:
            detection["runtime_entity"] = normalized_event.integration_id + ":" + identity(normalized_event.host.get("name"), entity)
        detection.update(integration_id=normalized_event.integration_id,
                         provenance=normalized_event.provenance,
                         event_time=normalized_event.time, cloud_provider=normalized_event.cloud_provider,
                         response_module=None, playbook=None)

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

# src/domain/correlation/correlation_engine.py
from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

# -------------------------------------------------------------------
# Repository contract (implemented by your infra layer / aws_handler)
# -------------------------------------------------------------------


class SignalsRepository(Protocol):
    """
    Correlation engine depends on an abstract repo so it stays testable and
    independent from DynamoDB specifics.

    You will implement this in infra/ (likely backed by DynamoDB):
      - query_signals(...) should return signals as dicts with at least:
          - timestamp (ISO8601 string)
          - rule_id
          - event_id
          - actor / network / api / etc (whatever you stored as the signal)
    """

    def query_signals(
        self,
        *,
        since: datetime,
        group_by_field: str,
        group_value: str,
        limit: int = 200,
    ) -> list[dict[str, Any]]: ...


# -------------------------------------------------------------------
# Helpers (shared condition semantics with your detection engine)
# -------------------------------------------------------------------


def _get_field(obj: Any, path: str) -> Any:
    """
    Supports dicts and objects. Example:
      actor.user_name
      network.source_ip
      api.operation
      severity
      rule_id
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


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _parse_iso(ts: str) -> datetime | None:
    if not ts or not isinstance(ts, str):
        return None
    # Accept "Z" (Zulu) and standard ISO8601
    t = ts.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(t)
    except Exception:
        return None


def _evaluate_condition(signal: dict[str, Any], cond: dict[str, Any]) -> bool:
    """
    Condition model (compatible with what you already had in spirit):
      {
        "field": "actor.user_name",
        "op": "equals|not_equals|in|not_in|contains|prefix|suffix|exists|not_exists|matches",
        "value": "admin"  (or list for in/not_in)
      }

    NOTE: this is intentionally minimal and safe.
    You can extend later (numeric comparisons, CIDR, etc).
    """
    field = cond.get("field")
    op = (cond.get("op") or "exists").lower()
    value = cond.get("value")

    observed = _get_field(signal, field) if field else None

    if op == "exists":
        return observed is not None
    if op == "not_exists":
        return observed is None

    if observed is None:
        return False

    # Normalize to string for most ops
    observed_s = str(observed)

    if op == "equals":
        return observed_s == str(value)
    if op == "not_equals":
        return observed_s != str(value)

    if op == "in":
        vals = [str(v) for v in _as_list(value)]
        return observed_s in vals
    if op == "not_in":
        vals = [str(v) for v in _as_list(value)]
        return observed_s not in vals

    if op == "contains":
        return str(value) in observed_s
    if op == "prefix":
        return observed_s.startswith(str(value))
    if op == "suffix":
        return observed_s.endswith(str(value))

    if op == "matches":
        # Keep regex optional to avoid importing re unless used
        import re  # local import

        try:
            return re.search(str(value), observed_s) is not None
        except Exception:
            return False

    return False


def _all_conditions_match(signal: dict[str, Any], conditions: list[dict[str, Any]]) -> bool:
    if not conditions:
        return True
    for c in conditions:
        if not _evaluate_condition(signal, c):
            return False
    return True


def _hash_id(*parts: str) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update((p or "").encode("utf-8"))
        h.update(b"|")
    return h.hexdigest()[:32]


# -------------------------------------------------------------------
# Correlation rule model
# -------------------------------------------------------------------


@dataclass(frozen=True)
class CorrelationRule:
    """
    Minimal correlation rule (count-based) for MVP.

    Example:
      {
        "rule_id": "C001_consolelogin_fail_burst",
        "enabled": true,
        "severity": "HIGH",
        "group_by": "actor.user_name",
        "time_window_seconds": 300,
        "threshold": 5,
        "signal_conditions": [
          {"field": "activity_name", "op": "equals", "value": "ConsoleLogin"},
          {"field": "api.error_code", "op": "exists"}
        ],
        "notify": true,
        "response_module": ""
      }
    """

    rule_id: str
    enabled: bool = True
    severity: str = "MEDIUM"
    group_by: str = "actor.user_name"
    time_window_seconds: int = 300
    threshold: int = 5
    signal_conditions: list[dict[str, Any]] = None

    notify: bool = True
    response_module: str = ""
    playbook: str = ""


def parse_correlation_rule(rule: dict[str, Any]) -> CorrelationRule | None:
    if not isinstance(rule, dict):
        return None

    rule_id = rule.get("rule_id")
    if not rule_id or not isinstance(rule_id, str):
        return None

    return CorrelationRule(
        rule_id=rule_id,
        enabled=bool(rule.get("enabled", True)),
        severity=str(rule.get("severity", "MEDIUM")),
        group_by=str(rule.get("group_by", "actor.user_name")),
        time_window_seconds=int(rule.get("time_window_seconds", 300)),
        threshold=int(rule.get("threshold", 5)),
        signal_conditions=list(rule.get("signal_conditions") or []),
        notify=bool(rule.get("notify", True)),
        response_module=str(rule.get("response_module", "") or ""),
        playbook=str(rule.get("playbook", "") or ""),
    )


# -------------------------------------------------------------------
# Engine
# -------------------------------------------------------------------


class CorrelationEngine:
    """
    Streaming-friendly correlation:
    - invoked per NEW signal
    - for each rule:
        - if the new signal matches rule's signal_conditions
        - group_value = signal[group_by]
        - fetch recent signals for that group within window
        - count matches; if >= threshold => emit alert
    """

    def __init__(self, *, repo: SignalsRepository) -> None:
        self.repo = repo

    def correlate(
        self,
        *,
        new_signal: dict[str, Any],
        rules: list[dict[str, Any]],
        now: datetime | None = None,
    ) -> list[dict[str, Any]]:
        now = now or datetime.now(UTC)
        alerts: list[dict[str, Any]] = []

        for raw_rule in rules:
            rule = parse_correlation_rule(raw_rule)
            if not rule or not rule.enabled:
                continue

            # Gate 1: does the incoming signal itself match the rule conditions?
            if not _all_conditions_match(new_signal, rule.signal_conditions):
                continue

            # Determine group value (e.g., actor.user_name)
            group_value = _get_field(new_signal, rule.group_by)
            if group_value is None or (isinstance(group_value, str) and not group_value.strip()):
                # If you can't group, you can't correlate safely
                continue

            group_value = str(group_value)

            window_start = now - timedelta(seconds=rule.time_window_seconds)

            # Pull recent signals for this group (repo should query efficiently)
            recent = self.repo.query_signals(
                since=window_start,
                group_by_field=rule.group_by,
                group_value=group_value,
                limit=max(rule.threshold * 5, 100),  # small safety margin
            )

            # Keep only those that match rule conditions (AND)
            matched = [s for s in recent if _all_conditions_match(s, rule.signal_conditions)]

            if len(matched) < rule.threshold:
                continue

            # Build alert
            alerts.append(
                self._build_alert(
                    rule=rule,
                    now=now,
                    group_value=group_value,
                    matched_signals=matched,
                )
            )

        return alerts

    def _build_alert(
        self,
        *,
        rule: CorrelationRule,
        now: datetime,
        group_value: str,
        matched_signals: list[dict[str, Any]],
    ) -> dict[str, Any]:
        # Bucket by time window so repeated triggers in the same window coalesce.
        bucket = int(now.timestamp() // max(getattr(rule, "time_window_seconds", 300) or 300, 1))
        alert_key = _hash_id(
            str(getattr(rule, "rule_id", "") or ""),
            str(getattr(rule, "group_by", "") or ""),
            str(group_value or ""),
            str(bucket),
        )

        def _s(d: Any, default: str = "") -> str:
            """Safe stringify (never None)."""
            try:
                if d is None:
                    return default
                return str(d)
            except Exception:
                return default

        def _d(obj: Any) -> dict[str, Any]:
            """Safe dict."""
            return obj if isinstance(obj, dict) else {}

        def _l(obj: Any) -> list[Any]:
            """Safe list."""
            return obj if isinstance(obj, list) else []

        def _get(obj: Any, *path: str, default: Any = None) -> Any:
            """Safe nested get for dicts."""
            cur = obj
            for p in path:
                if not isinstance(cur, dict):
                    return default
                cur = cur.get(p)
                if cur is None:
                    return default
            return cur

        def _signal_snapshot(s_any: Any) -> dict[str, Any]:
            """
            Compact, responder/notifier-friendly snapshot.
            Always safe: missing keys/types won't crash.
            """
            s = _d(s_any)
            network = _d(s.get("network"))
            actor = _d(s.get("actor"))
            api = _d(s.get("api"))
            raw = _d(s.get("raw_event"))
            raw_detail = _d(raw.get("detail"))

            return {
                # IDs / linkage
                "event_id": _s(s.get("event_id")),
                "detection_id": _s(s.get("detection_id")),
                "rule_id": _s(s.get("rule_id")),
                "timestamp": _s(s.get("timestamp")),
                # normalized context
                "source": _s(s.get("source")),
                "severity": _s(s.get("severity")),
                "category": _s(s.get("category")),
                "class_name": _s(s.get("class_name")),
                "activity_name": _s(s.get("activity_name")),
                "cloud_account_id": _s(s.get("cloud_account_id")),
                "cloud_region": _s(s.get("cloud_region")),
                # principal + network + api (trimmed)
                "actor": {
                    "type": _s(actor.get("type")),
                    "user_name": _s(actor.get("user_name")),
                    "user_id": _s(actor.get("user_id")),
                    "account_id": _s(actor.get("account_id")),
                    "arn": _s(actor.get("arn")),
                    "session_arn": _s(actor.get("session_arn")),
                },
                "network": {
                    "source_ip": _s(network.get("source_ip")),
                    "user_agent": _s(network.get("user_agent")),
                },
                "api": {
                    "service": _s(api.get("service")),
                    "operation": _s(api.get("operation")),
                    "region": _s(api.get("region")),
                    "http_status": _s(api.get("http_status")),
                    "error_code": _s(api.get("error_code")),
                    "error_message": _s(api.get("error_message")),
                },
                # resources trimmed (avoid huge payload)
                "resources": _l(s.get("resources"))[:5],
                # minimal raw event hints (optional, but very useful)
                "raw_event_min": {
                    "id": _s(raw.get("id")),
                    "source": _s(raw.get("source")),
                    "detail-type": _s(raw.get("detail-type")),
                    "time": _s(raw.get("time")),
                    "region": _s(raw.get("region")),
                    "account": _s(raw.get("account")),
                    "detail": {
                        "eventSource": _s(raw_detail.get("eventSource")),
                        "eventName": _s(raw_detail.get("eventName")),
                        "eventID": _s(raw_detail.get("eventID")),
                        "requestID": _s(raw_detail.get("requestID")),
                        "sourceIPAddress": _s(raw_detail.get("sourceIPAddress")),
                        "userAgent": _s(raw_detail.get("userAgent")),
                        # keep requestParameters (can be big; if you hit 400KB, trim it)
                        "requestParameters": raw_detail.get("requestParameters", {}),
                    },
                },
            }

        # Pick a "primary" signal: newest by timestamp (ISO strings sort lexicographically)
        primary: dict[str, Any] = {}
        if matched_signals:
            try:
                primary = sorted(
                    [s for s in matched_signals if isinstance(s, dict)],
                    key=lambda x: _s(x.get("timestamp")),
                    reverse=True,
                )[0]
            except Exception:
                primary = _d(matched_signals[0])

        # Lightweight refs (bounded)
        max_refs = 25
        refs: list[dict[str, Any]] = []
        for s_any in matched_signals[:max_refs]:
            s = _d(s_any)
            refs.append(
                {
                    "event_id": _s(s.get("event_id")),
                    "detection_id": _s(s.get("detection_id")),
                    "rule_id": _s(s.get("rule_id")),
                    "timestamp": _s(s.get("timestamp")),
                }
            )

        # Small snapshot list (bounded)
        max_summaries = 10
        summaries = [_signal_snapshot(s) for s in matched_signals[:max_summaries]]

        return {
            "alert_id": str(uuid.uuid4()),
            "alert_key": alert_key,
            "timestamp": now.isoformat(),
            "rule_id": _s(getattr(rule, "rule_id", "")),
            "severity": _s(getattr(rule, "severity", "UNKNOWN")),
            "notify": bool(getattr(rule, "notify", True)),
            "response_module": _s(getattr(rule, "response_module", "")),
            "playbook": _s(getattr(rule, "playbook", "")),
            "type": "correlation",
            "group_by": _s(getattr(rule, "group_by", "")),
            "group_value": _s(group_value),
            "time_window_seconds": int(getattr(rule, "time_window_seconds", 300) or 300),
            "threshold": int(getattr(rule, "threshold", 1) or 1),
            "match_count": len(matched_signals),
            "signal_refs": refs,
            "primary_signal": _signal_snapshot(primary),
            "signals_summary": summaries,
        }

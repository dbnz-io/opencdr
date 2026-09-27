"""Versioned management contract and side-effect-free rule evaluation.

This module is deliberately pure: API, CLI, loaders and tests can share the
same contract without creating AWS clients or executing notification/response
pipelines.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict
from typing import Any

from .correlation_engine import CorrelationEngine, _get_field, parse_correlation_rule
from .detection_engine import rule_matches
from .ocsf_min_parser import build_default_router
from .rule_schema import (
    ALLOWED_CONDITION_OPS,
    ALLOWED_FIELD_ROOTS,
    ALLOWED_RESPONSE_MODULES,
    ALLOWED_RULE_KINDS,
    ALLOWED_SEVERITIES,
    MAX_THRESHOLD,
    MAX_TIME_WINDOW_SECONDS,
    MIN_THRESHOLD,
    MIN_TIME_WINDOW_SECONDS,
    validate_rule_document,
)

RULE_CONTRACT_VERSION = "2.0.0"


def rule_contract() -> dict[str, Any]:
    return {
        "contract_version": RULE_CONTRACT_VERSION,
        "rule_kinds": sorted(ALLOWED_RULE_KINDS),
        "severities": sorted(ALLOWED_SEVERITIES),
        "field_roots": sorted(ALLOWED_FIELD_ROOTS),
        "condition_operators": sorted(ALLOWED_CONDITION_OPS),
        "response_modules": sorted(ALLOWED_RESPONSE_MODULES),
        "bounds": {
            "threshold": {"minimum": MIN_THRESHOLD, "maximum": MAX_THRESHOLD},
            "time_window_seconds": {
                "minimum": MIN_TIME_WINDOW_SECONDS,
                "maximum": MAX_TIME_WINDOW_SECONDS,
            },
        },
        "condition_requirements": {
            "no_value": ["exists", "not_exists", "wildcard"],
            "list_reference": ["in_list", "not_in_list"],
            "multiple_values": ["in", "not_in"],
        },
        "evaluation_modes": ["analysis", "shadow", "production"],
        "response_modes": ["unarmed", "dry-run", "armed"],
    }


def validate_candidate(payload: Any, *, available_lists: set[str] | None = None) -> dict[str, Any]:
    errors: list[dict[str, str]] = []
    warnings: list[dict[str, str]] = []
    try:
        validate_rule_document(payload)
    except ValueError as exc:
        errors.append({"code": "invalid_rule", "path": _error_path(str(exc)), "message": str(exc)})

    if isinstance(payload, dict) and payload.get("rule_kind") != "list":
        conditions = payload.get("conditions") or payload.get("signal_conditions") or []
        references = sorted({
            str(item.get("list_id")) for item in conditions
            if isinstance(item, dict) and item.get("op") in {"in_list", "not_in_list"} and item.get("list_id")
        })
        if available_lists is not None:
            for list_id in references:
                if list_id not in available_lists:
                    errors.append({"code": "missing_list", "path": "conditions", "message": f"Referenced list {list_id!r} is unavailable"})
        elif references:
            warnings.append({"code": "unverified_list", "path": "conditions", "message": f"List dependencies were not supplied: {', '.join(references)}"})

    return {
        "valid": not errors,
        "contract_version": RULE_CONTRACT_VERSION,
        "errors": errors,
        "warnings": warnings,
    }


def evaluate_candidate(payload: dict[str, Any], events: list[dict[str, Any]], *, lists: dict[str, list[str]] | None = None) -> dict[str, Any]:
    """Evaluate a candidate without notification, response, or persistence."""
    validation = validate_candidate(payload, available_lists=set((lists or {}).keys()))
    if not validation["valid"]:
        return {**validation, "matches": [], "evaluated": 0, "skipped": 0}

    rule = deepcopy(payload)
    # Candidate evaluation is explicit and side-effect free; disabled drafts
    # still need to be testable without first making them runtime-active.
    rule["enabled"] = True
    rule["notify"] = False
    rule.pop("response_module", None)
    rule["evaluation_mode"] = "analysis"
    kind = rule["rule_kind"]
    if kind == "list":
        return {**validation, "matches": [], "evaluated": 0, "skipped": 0, "list_values": len(rule.get("values") or [])}

    if kind == "correlation":
        parsed = parse_correlation_rule(rule)
        repo = _SequenceRepository()
        engine = CorrelationEngine(repo=repo)
        matches: list[dict[str, Any]] = []
        for index, signal in enumerate(events):
            candidate_signal = deepcopy(signal)
            candidate_signal.setdefault("timestamp", f"2026-01-01T00:00:{index:02d}+00:00")
            repo.signals.append(candidate_signal)
            for alert in engine.correlate(new_signal=candidate_signal, rules=[rule]):
                matches.append({"event_index": index, "rule_id": rule["rule_id"], "group_value": alert.get("group_value"), "match_count": alert.get("match_count")})
        return {**validation, "matches": matches, "evaluated": len(events), "skipped": 0, "correlation": asdict(parsed) if parsed else None}

    router = build_default_router()
    matches: list[dict[str, Any]] = []
    skipped = 0
    for index, event in enumerate(events):
        normalized = router.parse(event)
        if normalized is None:
            skipped += 1
            continue
        if rule_matches(normalized, rule, lists=lists or {}):
            matches.append({"event_index": index, "event_id": normalized.event_id, "rule_id": rule["rule_id"]})
    return {**validation, "matches": matches, "evaluated": len(events) - skipped, "skipped": skipped}


def _error_path(message: str) -> str:
    candidate = message.split(" must", 1)[0].split(" is ", 1)[0]
    return candidate if candidate and " " not in candidate else "rule"


class _SequenceRepository:
    def __init__(self) -> None:
        self.signals: list[dict[str, Any]] = []

    def query_signals(self, *, since: Any, group_by_field: str, group_value: str, limit: int = 200) -> list[dict[str, Any]]:
        del since
        return [item for item in self.signals if str(_get_field(item, group_by_field)) == group_value][-limit:]

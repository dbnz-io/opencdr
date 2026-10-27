"""Validation and matching for reusable detection lists."""

from __future__ import annotations

import ipaddress
import re
from typing import Any

ALLOWED_LIST_MATCHERS = frozenset({"exact", "cidr"})
ALLOWED_LIST_VALUE_TYPES = frozenset(
    {"string", "ip", "cidr", "iam_user", "arn", "aws_account_id", "resource_id"}
)
_LIST_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
MAX_LIST_VALUES = 10_000
MAX_LIST_VALUE_LENGTH = 2_048
MAX_DESCRIPTION_LENGTH = 2_048
MAX_LABELS = 50


def validate_list_document(payload: Any, *, force_list_id: str | None = None) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("list must be a JSON object")
    list_id = force_list_id or payload.get("list_id")
    if not isinstance(list_id, str) or not _LIST_ID_RE.fullmatch(list_id):
        raise ValueError("list_id must be 1-128 safe identifier characters")

    matcher = payload.get("matcher")
    if matcher is None:
        raise ValueError("matcher is required")
    if matcher not in ALLOWED_LIST_MATCHERS:
        raise ValueError(f"matcher must be one of {sorted(ALLOWED_LIST_MATCHERS)}")
    default_type = "cidr" if matcher == "cidr" else "string"
    value_type = payload.get("value_type", default_type)
    if value_type not in ALLOWED_LIST_VALUE_TYPES:
        raise ValueError(f"value_type must be one of {sorted(ALLOWED_LIST_VALUE_TYPES)}")

    values = payload.get("values")
    if not isinstance(values, list) or not values:
        raise ValueError("values must be a non-empty list")
    if len(values) > MAX_LIST_VALUES:
        raise ValueError(f"values must contain at most {MAX_LIST_VALUES} entries")
    normalized = normalize_list_values(values, matcher)

    description = payload.get("description", "")
    if not isinstance(description, str):
        raise ValueError("description must be a string")
    if len(description) > MAX_DESCRIPTION_LENGTH:
        raise ValueError(f"description must be at most {MAX_DESCRIPTION_LENGTH} characters")
    labels = payload.get("labels", [])
    if not isinstance(labels, list) or any(
        not isinstance(label, str) or not label.strip() for label in labels
    ):
        raise ValueError("labels must be a list of non-empty strings")
    if len(labels) > MAX_LABELS or any(len(label) > 128 for label in labels):
        raise ValueError(f"labels must contain at most {MAX_LABELS} values of 128 characters")

    result: dict[str, Any] = {
        "list_id": list_id,
        "matcher": matcher,
        "value_type": value_type,
        "values": normalized,
        "description": description,
        "labels": sorted(set(labels)),
    }
    if "expected_rev" in payload:
        expected_rev = payload["expected_rev"]
        if isinstance(expected_rev, bool) or not isinstance(expected_rev, int) or expected_rev < 0:
            raise ValueError("expected_rev must be a non-negative integer")
        result["expected_rev"] = expected_rev
    return result


def normalize_list_values(values: list[Any], matcher: str) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for index, value in enumerate(values):
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"values[{index}] must be a non-empty string")
        candidate = value.strip()
        if len(candidate) > MAX_LIST_VALUE_LENGTH:
            raise ValueError(f"values[{index}] must be at most {MAX_LIST_VALUE_LENGTH} characters")
        if matcher == "cidr":
            try:
                candidate = str(ipaddress.ip_network(candidate, strict=False))
            except ValueError as exc:
                raise ValueError(f"values[{index}] must be a valid IPv4 or IPv6 network") from exc
        if candidate not in seen:
            seen.add(candidate)
            normalized.append(candidate)
    return normalized


def list_matches(observed: Any, snapshot: Any) -> bool:
    """Match a scalar observed value against a rich or legacy list snapshot."""
    if observed is None:
        return False
    if isinstance(snapshot, list):
        matcher = "exact"
        values = snapshot
    elif isinstance(snapshot, dict):
        matcher = snapshot.get("matcher", "exact")
        values = snapshot.get("values", [])
    else:
        return False

    observed_s = str(observed)
    if matcher == "exact":
        return observed_s in {str(value) for value in values}
    if matcher == "cidr":
        try:
            address = ipaddress.ip_address(observed_s)
        except ValueError:
            return False
        for value in values:
            try:
                if address in ipaddress.ip_network(str(value), strict=False):
                    return True
            except ValueError:
                continue
    return False


def referenced_list_versions(rule: dict[str, Any], lists: dict[str, Any]) -> dict[str, int]:
    conditions = rule.get("conditions") or rule.get("signal_conditions") or []
    versions: dict[str, int] = {}
    for condition in conditions:
        if not isinstance(condition, dict) or condition.get("op") not in {"in_list", "not_in_list"}:
            continue
        list_id = condition.get("list_id")
        snapshot = lists.get(list_id) if isinstance(list_id, str) else None
        if isinstance(snapshot, dict) and isinstance(snapshot.get("version"), int):
            versions[list_id] = snapshot["version"]
    return versions

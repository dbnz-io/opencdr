"""Shared detection-rule schema validation.

The direct DynamoDB loader bypasses the API, so it must validate the same
closed sets and numeric bounds before writing a bundled rule.  Keep the
constants here so the API and offline loaders cannot drift apart.
"""

from __future__ import annotations

import re
from typing import Any

ALLOWED_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "INFORMATIONAL", "UNKNOWN"}
ALLOWED_RULE_KINDS = {"signal", "correlation", "list"}
ALLOWED_FIELD_ROOTS = frozenset(
    {
        "event_id",
        "source",
        "time",
        "category",
        "class_name",
        "activity_name",
        "severity",
        "actor",
        "api",
        "network",
        "resources",
        "cloud_provider",
        "cloud_account_id",
        "cloud_region",
        "gd_resource_type",
        "raw_event",
        "rule_id",
        "host",
        "process",
        "container",
        "kubernetes",
        "finding",
        "vendor",
        "integration_id",
        "provenance",
        "runtime_entity",
    }
)
ALLOWED_RESPONSE_MODULES = {
    "disable_access_key",
    "disable_user",
    "delete_user",
    "disable_role",
    "revoke_active_sessions",
    "delete_inline_policy",
    "block_s3_public_access",
    "block_s3_bucket_public_access",
    "block_s3_object_public_access",
    "quarantine_s3_bucket",
    "isolate_ec2_instances",
    "deauthorize_security_group_rules",
    "disable_lambda_function",
    "disable_secrets_manager_secret",
    "revoke_rds_snapshot_public_access",
    "enable_cloudtrail_logging",
    "enable_guardduty_detector",
    "start_config_recorder",
    "enable_security_hub",
}
ALLOWED_CONDITION_OPS = {
    "equals",
    "not_equals",
    "in",
    "not_in",
    "in_list",
    "not_in_list",
    "exists",
    "not_exists",
    "matches",
    "not_matches",
    "contains",
    "not_contains",
    "prefix",
    "not_prefix",
    "suffix",
    "not_suffix",
    "wildcard",
}
NO_VALUE_CONDITION_OPS = {"exists", "not_exists", "wildcard"}
LIST_CONDITION_OPS = {"in_list", "not_in_list"}
REGEX_CONDITION_OPS = {"matches", "not_matches"}
MIN_THRESHOLD = 1
MAX_THRESHOLD = 1000
MIN_TIME_WINDOW_SECONDS = 1
MAX_TIME_WINDOW_SECONDS = 86400


def _require_nonempty_string(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{path} must be a non-empty string")
    return value


def _validate_conditions(value: Any, path: str, *, require_nonempty: bool) -> None:
    if not isinstance(value, list) or (require_nonempty and not value):
        suffix = " and must not be empty" if require_nonempty else ""
        raise ValueError(f"{path} must be a list{suffix}")

    for index, condition in enumerate(value):
        condition_path = f"{path}[{index}]"
        if not isinstance(condition, dict):
            raise ValueError(f"{condition_path} must be an object")

        field = _require_nonempty_string(condition.get("field"), f"{condition_path}.field")
        field_root = field.strip().split(".", 1)[0]
        if field_root not in ALLOWED_FIELD_ROOTS:
            raise ValueError(
                f"{condition_path}.field root {field_root!r} is not one of {sorted(ALLOWED_FIELD_ROOTS)}"
            )

        op = condition.get("op")
        if not isinstance(op, str) or op not in ALLOWED_CONDITION_OPS:
            raise ValueError(f"{condition_path}.op must be one of {sorted(ALLOWED_CONDITION_OPS)}")

        if op in {"in", "not_in"}:
            if not isinstance(condition.get("value"), list) or not condition["value"]:
                raise ValueError(f"{condition_path}.value must be a non-empty list for op={op}")
        elif op in LIST_CONDITION_OPS:
            _require_nonempty_string(condition.get("list_id"), f"{condition_path}.list_id")
        elif op not in NO_VALUE_CONDITION_OPS and condition.get("value") is None:
            raise ValueError(f"{condition_path}.value is required for op={op}")

        if op in REGEX_CONDITION_OPS:
            pattern = condition.get("value")
            if not isinstance(pattern, str):
                raise ValueError(f"{condition_path}.value must be a string for op={op}")
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValueError(f"{condition_path}.value is not a valid regex: {exc}") from exc


def validate_rule_document(payload: Any) -> None:
    """Validate a complete rule document loaded from disk.

    This intentionally validates more strictly than an API update payload:
    bundled source files must be self-contained and correctly typed before a
    loader is allowed to write any part of the catalog to DynamoDB.
    """
    if not isinstance(payload, dict):
        raise ValueError("rule must be a JSON object")

    _require_nonempty_string(payload.get("rule_id"), "rule_id")
    rule_kind = payload.get("rule_kind")
    if rule_kind not in ALLOWED_RULE_KINDS:
        raise ValueError(f"rule_kind must be one of {sorted(ALLOWED_RULE_KINDS)}")

    if rule_kind == "list":
        values = payload.get("values")
        if not isinstance(values, list) or not values:
            raise ValueError("values must be a non-empty list for rule_kind=list")
        if any(not isinstance(value, str) or not value for value in values):
            raise ValueError("values must contain only non-empty strings")
        return

    if not isinstance(payload.get("enabled"), bool):
        raise ValueError("enabled must be boolean")
    if not isinstance(payload.get("notify"), bool):
        raise ValueError("notify must be boolean")

    severity = payload.get("severity")
    if not isinstance(severity, str) or severity.upper() not in ALLOWED_SEVERITIES:
        raise ValueError(f"severity must be one of {sorted(ALLOWED_SEVERITIES)}")

    response_module = payload.get("response_module", "")
    if not isinstance(response_module, str):
        raise ValueError("response_module must be a string")
    if response_module and response_module not in ALLOWED_RESPONSE_MODULES:
        raise ValueError(f"response_module must be one of {sorted(ALLOWED_RESPONSE_MODULES)} or empty")

    if rule_kind == "signal":
        _validate_conditions(payload.get("conditions"), "conditions", require_nonempty=True)
        source_conditions = payload["conditions"]
        if response_module and any(
            condition.get("field") == "integration_id"
            or (condition.get("field") == "source" and condition.get("value") in {"falco", "custom"})
            for condition in source_conditions
        ):
            raise ValueError("AWS response modules are not supported for Falco/custom integrations")
        return

    group_by = _require_nonempty_string(payload.get("group_by"), "group_by")
    group_root = group_by.strip().split(".", 1)[0]
    if group_root not in ALLOWED_FIELD_ROOTS:
        raise ValueError(f"group_by root {group_root!r} is not one of {sorted(ALLOWED_FIELD_ROOTS)}")
    threshold = payload.get("threshold")
    if isinstance(threshold, bool) or not isinstance(threshold, int):
        raise ValueError("threshold must be an integer")
    if not MIN_THRESHOLD <= threshold <= MAX_THRESHOLD:
        raise ValueError(f"threshold must be between {MIN_THRESHOLD} and {MAX_THRESHOLD}")

    window = payload.get("time_window_seconds")
    if isinstance(window, bool) or not isinstance(window, int):
        raise ValueError("time_window_seconds must be an integer")
    if not MIN_TIME_WINDOW_SECONDS <= window <= MAX_TIME_WINDOW_SECONDS:
        raise ValueError(
            f"time_window_seconds must be between {MIN_TIME_WINDOW_SECONDS} and {MAX_TIME_WINDOW_SECONDS}"
        )
    _validate_conditions(payload.get("signal_conditions"), "signal_conditions", require_nonempty=False)
    if response_module and any(
        condition.get("field") == "integration_id"
        or (condition.get("field") == "source" and condition.get("value") in {"falco", "custom"})
        for condition in payload["signal_conditions"]
    ):
        raise ValueError("AWS response modules are not supported for Falco/custom integrations")

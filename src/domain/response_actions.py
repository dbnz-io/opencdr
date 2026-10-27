"""Response-action contracts and deterministic event target resolution.

Rules choose *where* each fixed module argument comes from.  The paths are
resolved while the detection/alert is built and the responder only consumes
the resulting values; it never re-evaluates a user supplied path.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

MAX_RESPONSE_ACTIONS = 10

# ``required`` and ``optional`` are fixed argument names exposed by each
# response module.  Values are simple runtime type names so the contract can
# be returned directly by the management API.
RESPONSE_TARGET_CONTRACTS: dict[str, dict[str, Any]] = {
    "disable_access_key": {
        "required": {"user_name": "string", "access_key_id": "string"},
        "optional": {},
    },
    "disable_user": {"required": {"user_name": "string"}, "optional": {}},
    "delete_user": {"required": {"user_name": "string"}, "optional": {}},
    "disable_role": {"required": {"role_name": "string"}, "optional": {}},
    "revoke_active_sessions": {
        "required": {"user_name": "string"},
        "optional": {},
    },
    "delete_inline_policy": {
        "required": {"policy_name": "string"},
        "optional": {
            "user_name": "string",
            "role_name": "string",
            "principal_name": "string",
        },
        "exactly_one_of": [["user_name", "role_name", "principal_name"]],
    },
    "block_s3_public_access": {
        "required": {"account_id": "string"},
        "optional": {},
    },
    "block_s3_bucket_public_access": {
        "required": {"bucket_name": "string"},
        "optional": {},
    },
    "block_s3_object_public_access": {
        "required": {"bucket_name": "string", "key": "string"},
        "optional": {},
    },
    "quarantine_s3_bucket": {
        "required": {"bucket_name": "string"},
        "optional": {"account_id": "string"},
    },
    "isolate_ec2_instances": {
        "required": {"instance_ids": "string_or_string_list"},
        "optional": {},
    },
    "deauthorize_security_group_rules": {
        "required": {"group_id": "string"},
        "optional": {
            "rules": "object_list",
            "ingress_rules": "object_list",
            "egress_rules": "object_list",
        },
        "one_of": [["rules", "ingress_rules", "egress_rules"]],
    },
    "disable_lambda_function": {
        "required": {"function_name": "string"},
        "optional": {},
    },
    "disable_secrets_manager_secret": {
        "required": {"secret_id": "string"},
        "optional": {},
    },
    "revoke_rds_snapshot_public_access": {
        "required": {"snapshot_id": "string"},
        "optional": {"snapshot_type": "string"},
    },
    "enable_cloudtrail_logging": {
        "required": {"trail_name": "string"},
        "optional": {},
    },
    "enable_guardduty_detector": {
        "required": {"detector_id": "string"},
        "optional": {},
    },
    "start_config_recorder": {
        "required": {"recorder_name": "string"},
        "optional": {},
    },
    "enable_security_hub": {"required": {}, "optional": {}},
}

ALLOWED_RESPONSE_MODULES = frozenset(RESPONSE_TARGET_CONTRACTS)

# These are detection/alert roots, not arbitrary Python attributes.  Keeping a
# closed root set makes paths reviewable and prevents access to implementation
# internals if the resolver is ever given richer objects.
ALLOWED_RESPONSE_TARGET_ROOTS = frozenset(
    {
        "event_id",
        "source",
        "time",
        "timestamp",
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
        # Correlation alert context.
        "group_by",
        "group_value",
        "primary_signal",
        "signals_summary",
    }
)


def validate_response_actions(value: Any, *, path: str = "response_actions") -> None:
    """Validate rule-time action definitions without resolving their paths."""
    if not isinstance(value, list):
        raise ValueError(f"{path} must be a list")
    if len(value) > MAX_RESPONSE_ACTIONS:
        raise ValueError(f"{path} must contain at most {MAX_RESPONSE_ACTIONS} actions")

    for index, action in enumerate(value):
        action_path = f"{path}[{index}]"
        if not isinstance(action, dict):
            raise ValueError(f"{action_path} must be an object")
        unknown_fields = set(action) - {"module", "target"}
        if unknown_fields:
            raise ValueError(f"{action_path} has unsupported fields: {sorted(unknown_fields)}")

        module = action.get("module")
        if module not in RESPONSE_TARGET_CONTRACTS:
            raise ValueError(
                f"{action_path}.module must be one of {sorted(RESPONSE_TARGET_CONTRACTS)}"
            )
        target = action.get("target")
        if not isinstance(target, dict):
            raise ValueError(f"{action_path}.target must be an object")

        contract = RESPONSE_TARGET_CONTRACTS[module]
        required = set(contract["required"])
        allowed = required | set(contract["optional"])
        missing = required - set(target)
        unknown = set(target) - allowed
        if missing:
            raise ValueError(f"{action_path}.target is missing required keys: {sorted(missing)}")
        if unknown:
            raise ValueError(f"{action_path}.target has unsupported keys: {sorted(unknown)}")
        for alternatives in contract.get("one_of", []):
            if not any(key in target for key in alternatives):
                raise ValueError(
                    f"{action_path}.target requires at least one of {sorted(alternatives)}"
                )
        for alternatives in contract.get("exactly_one_of", []):
            if sum(key in target for key in alternatives) != 1:
                raise ValueError(
                    f"{action_path}.target requires exactly one of {sorted(alternatives)}"
                )

        for key, field_path in target.items():
            if not isinstance(field_path, str) or not field_path.strip():
                raise ValueError(f"{action_path}.target.{key} must be a non-empty field path")
            parts = field_path.split(".")
            if parts[0] not in ALLOWED_RESPONSE_TARGET_ROOTS:
                raise ValueError(f"{action_path}.target.{key} root {parts[0]!r} is not allowed")
            if any(not part or part.startswith("_") for part in parts):
                raise ValueError(f"{action_path}.target.{key} is not a safe field path")


def resolve_response_actions(event: dict[str, Any], actions: Any) -> list[dict[str, Any]]:
    """Resolve validated action mappings into immutable responder inputs.

    Resolution errors are represented on the individual action.  That keeps
    the detection observable while ensuring the responder can fail the action
    closed instead of guessing a target.
    """
    if not actions:
        return []
    validate_response_actions(actions)
    source_id = str(event.get("detection_id") or event.get("alert_id") or "response")
    resolved: list[dict[str, Any]] = []

    for index, action in enumerate(actions, start=1):
        module = action["module"]
        target: dict[str, Any] = {}
        errors: list[str] = []
        contract = RESPONSE_TARGET_CONTRACTS[module]
        types = {**contract["required"], **contract["optional"]}
        for key, field_path in action["target"].items():
            try:
                value = _get_path(event, field_path)
            except (KeyError, IndexError, TypeError, ValueError):
                errors.append(f"{key}: field {field_path!r} was not found")
                continue
            if not _value_matches_type(value, types[key]):
                errors.append(f"{key}: field {field_path!r} did not resolve to {types[key]}")
                continue
            target[key] = deepcopy(value)

        for key in contract["required"]:
            if key not in target and not any(error.startswith(f"{key}:") for error in errors):
                errors.append(f"{key}: required target was not resolved")
        for alternatives in contract.get("one_of", []):
            if not any(key in target for key in alternatives):
                errors.append(f"at least one of {sorted(alternatives)} must resolve")
        for alternatives in contract.get("exactly_one_of", []):
            if sum(key in target for key in alternatives) != 1:
                errors.append(f"exactly one of {sorted(alternatives)} must resolve")

        item: dict[str, Any] = {
            "action_id": f"{source_id}--r{index}",
            "module": module,
            "target": target,
        }
        if errors:
            item["resolution_error"] = "; ".join(errors)
        resolved.append(item)

    return resolved


def _get_path(value: Any, path: str) -> Any:
    current = value
    for part in path.split("."):
        if isinstance(current, dict):
            if part not in current:
                raise KeyError(part)
            current = current[part]
        elif isinstance(current, list):
            if not part.isdigit():
                raise TypeError(part)
            current = current[int(part)]
        else:
            raise TypeError(part)
    if current is None or current == "":
        raise ValueError(path)
    return current


def _value_matches_type(value: Any, expected: str) -> bool:
    if expected == "string":
        return isinstance(value, str) and bool(value)
    if expected == "string_list":
        return (
            isinstance(value, list)
            and bool(value)
            and all(isinstance(item, str) and bool(item) for item in value)
        )
    if expected == "string_or_string_list":
        return (isinstance(value, str) and bool(value)) or (
            isinstance(value, list)
            and bool(value)
            and all(isinstance(item, str) and bool(item) for item in value)
        )
    if expected == "object_list":
        return (
            isinstance(value, list)
            and bool(value)
            and all(isinstance(item, dict) for item in value)
        )
    return False

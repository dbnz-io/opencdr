"""Pure release-manifest validation, hashing and convergence planning."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from typing import Any

from .rule_management import RULE_CONTRACT_VERSION, validate_candidate

OBSERVATION_FIELDS = {"rev", "timestamp", "created_by", "updated_by", "expected_rev", "catalog_generation"}


def canonical(value: Any) -> Any:
    if isinstance(value, list):
        return [canonical(item) for item in value]
    if isinstance(value, dict):
        return {key: canonical(value[key]) for key in sorted(value) if key not in OBSERVATION_FIELDS and value[key] is not None}
    return value


def manifest_digest(manifest: dict[str, Any]) -> str:
    content = {key: value for key, value in manifest.items() if key != "manifest_digest"}
    return hashlib.sha256(json.dumps(canonical(content), sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def validate_manifest(manifest: Any) -> dict[str, Any]:
    errors: list[dict[str, str]] = []
    if not isinstance(manifest, dict):
        return {"valid": False, "errors": [{"code": "invalid_manifest", "path": "manifest", "message": "manifest must be an object"}]}
    for field in ("release_id", "release_version", "contract_version", "rules"):
        if field not in manifest:
            errors.append({"code": "missing_field", "path": field, "message": f"{field} is required"})
    if manifest.get("contract_version") != RULE_CONTRACT_VERSION:
        errors.append({"code": "contract_mismatch", "path": "contract_version", "message": f"contract_version must be {RULE_CONTRACT_VERSION}"})
    rules = manifest.get("rules")
    if not isinstance(rules, list) or not rules:
        errors.append({"code": "invalid_rules", "path": "rules", "message": "rules must be a non-empty list"})
        rules = []
    keys: set[tuple[str, str]] = set()
    list_ids = {str(rule.get("rule_id")) for rule in rules if isinstance(rule, dict) and rule.get("rule_kind") == "list"}
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            errors.append({"code": "invalid_rule", "path": f"rules[{index}]", "message": "rule must be an object"})
            continue
        key = (str(rule.get("rule_kind")), str(rule.get("rule_id")))
        if key in keys:
            errors.append({"code": "duplicate_rule", "path": f"rules[{index}]", "message": f"duplicate rule {key[0]}:{key[1]}"})
        keys.add(key)
        result = validate_candidate(rule, available_lists=list_ids)
        errors.extend({**item, "path": f"rules[{index}].{item['path']}"} for item in result["errors"])
    supplied = manifest.get("manifest_digest")
    if supplied and supplied != manifest_digest(manifest):
        errors.append({"code": "digest_mismatch", "path": "manifest_digest", "message": "manifest digest does not match its content"})
    if manifest.get("removal_policy", "disable") not in {"ignore", "disable", "delete"}:
        errors.append({"code": "invalid_removal_policy", "path": "removal_policy", "message": "removal_policy must be ignore, disable, or delete"})
    return {"valid": not errors, "errors": errors, "manifest_digest": manifest_digest(manifest)}


def release_payload(rule: dict[str, Any], manifest: dict[str, Any]) -> dict[str, Any]:
    payload = deepcopy(rule)
    payload.update({
        "release_id": manifest["release_id"],
        "release_version": manifest["release_version"],
        "contract_version": manifest["contract_version"],
        "content_fingerprint": hashlib.sha256(json.dumps(canonical(rule), sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest(),
    })
    payload.setdefault("source_type", manifest.get("source_type", "control-plane"))
    if manifest.get("source_commit"):
        payload["source_commit"] = manifest["source_commit"]
    return payload


def plan_release(existing: list[dict[str, Any]], manifest: dict[str, Any]) -> list[dict[str, Any]]:
    desired = {(rule["rule_kind"], rule["rule_id"]): release_payload(rule, manifest) for rule in manifest["rules"]}
    current = {(rule.get("rule_kind"), rule.get("rule_id")): rule for rule in existing}
    operations: list[dict[str, Any]] = []
    for key, payload in desired.items():
        present = current.get(key)
        action = "create" if present is None else "unchanged" if canonical(present) == canonical(payload) else "update"
        operations.append({"action": action, "rule_kind": key[0], "rule_id": key[1], "expected_rev": present.get("rev") if present else None, "payload": payload})
    policy = manifest.get("removal_policy", "disable")
    if policy != "ignore":
        for key, present in current.items():
            if key in desired or not present.get("release_id"):
                continue
            action = "disable" if policy == "disable" else "delete"
            payload = {**present, "enabled": False} if action == "disable" else None
            operations.append({"action": action, "rule_kind": key[0], "rule_id": key[1], "expected_rev": present.get("rev"), "payload": payload})
    order = {"disable": 0, "delete": 0, "create": 1, "update": 1, "unchanged": 2}
    return sorted(operations, key=lambda item: (order[item["action"]], 0 if item["rule_kind"] == "list" and item["action"] in {"create", "update"} else 1, item["rule_kind"], item["rule_id"]))

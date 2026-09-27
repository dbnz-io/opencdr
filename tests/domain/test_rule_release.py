from src.domain.rule_management import RULE_CONTRACT_VERSION
from src.domain.rule_release import manifest_digest, plan_release, validate_manifest


def rule(rule_id, *, kind="signal", enabled=True):
    base = {"rule_id": rule_id, "rule_kind": kind, "description": rule_id, "enabled": enabled, "notify": False, "severity": "HIGH", "response_module": ""}
    if kind == "list":
        return {"rule_id": rule_id, "rule_kind": kind, "values": ["admin"]}
    return {**base, "conditions": [{"field": "activity_name", "op": "equals", "value": "ConsoleLogin"}]}


def manifest(rules, **overrides):
    return {"release_id": "release-1", "release_version": 2, "contract_version": RULE_CONTRACT_VERSION, "removal_policy": "disable", "rules": rules, **overrides}


def test_manifest_digest_is_stable_and_verified():
    value = manifest([rule("one")])
    digest = manifest_digest(value)
    assert validate_manifest({**value, "manifest_digest": digest})["valid"] is True
    assert validate_manifest({**value, "manifest_digest": "wrong"})["errors"][-1]["code"] == "digest_mismatch"


def test_plan_is_exact_and_disables_removed_managed_rule():
    value = manifest([rule("kept")])
    existing = [
        {**rule("kept"), "release_id": "old", "release_version": 1, "contract_version": RULE_CONTRACT_VERSION, "content_fingerprint": "old", "rev": 3},
        {**rule("removed"), "release_id": "old", "rev": 2},
        {**rule("manual"), "rev": 1},
    ]
    operations = plan_release(existing, value)
    assert [(item["rule_id"], item["action"]) for item in operations] == [("removed", "disable"), ("kept", "update")]


def test_manifest_requires_list_dependency():
    dependent = rule("dependent")
    dependent["conditions"] = [{"field": "actor.user_name", "op": "in_list", "list_id": "admins"}]
    assert validate_manifest(manifest([dependent]))["errors"][-1]["code"] == "missing_list"
    assert validate_manifest(manifest([rule("admins", kind="list"), dependent]))["valid"] is True

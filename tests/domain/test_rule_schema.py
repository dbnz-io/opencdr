from __future__ import annotations

import pytest

from src.domain.rule_schema import validate_rule_document


def signal_rule(**changes):
    rule = {
        "rule_id": "console-login",
        "rule_kind": "signal",
        "enabled": True,
        "notify": True,
        "severity": "HIGH",
        "response_module": "",
        "conditions": [{"field": "activity_name", "op": "equals", "value": "ConsoleLogin"}],
    }
    rule.update(changes)
    return rule


def correlation_rule(**changes):
    rule = {
        "rule_id": "login-burst",
        "rule_kind": "correlation",
        "enabled": True,
        "notify": True,
        "severity": "HIGH",
        "response_module": "",
        "group_by": "actor.user_name",
        "threshold": 5,
        "time_window_seconds": 900,
        "signal_conditions": [{"field": "rule_id", "op": "equals", "value": "console-login"}],
    }
    rule.update(changes)
    return rule


@pytest.mark.parametrize("rule", [signal_rule(), correlation_rule(), {
    "rule_id": "automation-identities",
    "rule_kind": "list",
    "values": ["ci-role"],
}])
def test_accepts_each_rule_kind(rule):
    validate_rule_document(rule)


@pytest.mark.parametrize(
    ("rule", "message"),
    [
        (signal_rule(enabled="true"), "enabled must be boolean"),
        (signal_rule(severity="urgent"), "severity must be one of"),
        (signal_rule(conditions=[]), "conditions must be a list and must not be empty"),
        (signal_rule(conditions=[{"field": "activity_name", "op": "unknown", "value": "x"}]), "op must be one of"),
        (signal_rule(conditions=[{"field": "activity_name", "op": "matches", "value": "["}]), "not a valid regex"),
        (signal_rule(response_module="typo"), "response_module must be one of"),
        (signal_rule(notify="yes"), "notify must be boolean"),
        (signal_rule(response_module="disable_user", conditions=[{"field": "source", "op": "equals", "value": "falco"}]), "not supported for Falco/custom"),
        (correlation_rule(threshold=0), "threshold must be between"),
        (correlation_rule(group_by="unknown.value"), "group_by root"),
        (correlation_rule(time_window_seconds=True), "time_window_seconds must be an integer"),
        ({"rule_id": "empty-list", "rule_kind": "list", "values": []}, "values must be a non-empty list"),
    ],
)
def test_rejects_invalid_complete_documents(rule, message):
    with pytest.raises(ValueError, match=message):
        validate_rule_document(rule)

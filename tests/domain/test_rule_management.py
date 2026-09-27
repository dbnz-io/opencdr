import json
from pathlib import Path

from src.domain.rule_management import RULE_CONTRACT_VERSION, evaluate_candidate, rule_contract, validate_candidate


ROOT = Path(__file__).parents[2]


def signal_rule(**overrides):
    return {
        "rule_id": "console_login",
        "rule_kind": "signal",
        "description": "Console login",
        "enabled": False,
        "notify": False,
        "severity": "HIGH",
        "response_module": "",
        "conditions": [{"field": "activity_name", "op": "equals", "value": "ConsoleLogin"}],
        **overrides,
    }


def test_contract_exposes_authoritative_bounds_and_catalogs():
    contract = rule_contract()
    assert contract["contract_version"] == RULE_CONTRACT_VERSION
    assert contract["bounds"]["threshold"]["maximum"] == 1000
    assert "in_list" in contract["condition_operators"]
    assert "actor" in contract["field_roots"]


def test_validation_returns_structured_missing_list_error():
    rule = signal_rule(conditions=[{"field": "actor.user_name", "op": "in_list", "list_id": "admins"}])
    result = validate_candidate(rule, available_lists=set())
    assert result["valid"] is False
    assert result["errors"] == [{"code": "missing_list", "path": "conditions", "message": "Referenced list 'admins' is unavailable"}]


def test_signal_candidate_evaluation_is_side_effect_free_and_matches_fixture():
    fixture = json.loads((ROOT / "support_files/test_events/001_console_login_no_mfa.json").read_text())
    result = evaluate_candidate(signal_rule(), [fixture])
    assert result["valid"] is True
    assert result["evaluated"] == 1
    assert result["matches"][0]["rule_id"] == "console_login"


def test_correlation_candidate_evaluates_ordered_signal_sequence():
    rule = {
        "rule_id": "role_burst",
        "rule_kind": "correlation",
        "description": "Role burst",
        "enabled": False,
        "notify": False,
        "severity": "HIGH",
        "response_module": "",
        "group_by": "actor.user_name",
        "threshold": 2,
        "time_window_seconds": 300,
        "signal_conditions": [{"field": "activity_name", "op": "equals", "value": "AssumeRole"}],
    }
    signals = [
        {"event_id": "one", "timestamp": "2026-01-01T00:00:00+00:00", "activity_name": "AssumeRole", "actor": {"user_name": "santi"}},
        {"event_id": "two", "timestamp": "2026-01-01T00:00:01+00:00", "activity_name": "AssumeRole", "actor": {"user_name": "santi"}},
    ]
    result = evaluate_candidate(rule, signals)
    assert result["valid"] is True
    assert result["matches"][-1]["match_count"] == 2

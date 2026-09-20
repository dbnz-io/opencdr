"""Write-time ReDoS advisory for regex conditions (item 1, api.py).

The runtime timeout in detection_engine is the hard guarantee; api.py adds an
early, best-effort nested-quantifier warning that mirrors STRICT_RULE_VALIDATION
(warn-and-allow by default, reject under STRICT). Also validates with the same
`regex` engine the detection engine runs, and guards that no shipped rule trips
the heuristic.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

from src.handlers import api

_RULES_DIR = Path(__file__).resolve().parents[2] / "support_files" / "detection_rules"


def _rule(value: str, op: str = "matches") -> dict:
    return {
        "rule_kind": "signal",
        "rule_id": "r1",
        "severity": "HIGH",
        "conditions": [{"field": "activity_name", "op": op, "value": value}],
    }


class TestNestedQuantifierAdvisory:
    def test_nested_quantifier_warns_and_allows_by_default(self, monkeypatch):
        monkeypatch.delenv("STRICT_RULE_VALIDATION", raising=False)
        out = api._normalize_rule_payload(_rule("(a+)+$"), force_rule_id="r1")
        assert out["conditions"][0]["value"] == "(a+)+$"

    def test_nested_quantifier_rejected_under_strict(self, monkeypatch):
        monkeypatch.setenv("STRICT_RULE_VALIDATION", "true")
        with pytest.raises(ValueError, match="nested quantifier"):
            api._normalize_rule_payload(_rule("(a+)+$"), force_rule_id="r1")

    def test_simple_pattern_allowed_under_strict(self, monkeypatch):
        monkeypatch.setenv("STRICT_RULE_VALIDATION", "true")
        out = api._normalize_rule_payload(_rule("^Create(User|Role)$"), force_rule_id="r1")
        assert out["conditions"][0]["value"] == "^Create(User|Role)$"

    def test_not_matches_also_advised(self, monkeypatch):
        monkeypatch.setenv("STRICT_RULE_VALIDATION", "1")
        with pytest.raises(ValueError, match="nested quantifier"):
            api._normalize_rule_payload(_rule("(x*)*", op="not_matches"), force_rule_id="r1")


class TestRegexEngineValidation:
    def test_invalid_regex_rejected(self):
        with pytest.raises(ValueError, match="not a valid regex"):
            api._normalize_rule_payload(_rule("(unbalanced"), force_rule_id="r1")


class TestHeuristicShape:
    @pytest.mark.parametrize("bad", ["(a+)+", "(a*)*", "(x+x+)+y", "(.+)+$"])
    def test_flags_known_nested_quantifiers(self, bad):
        assert api._NESTED_QUANTIFIER_RE.search(bad)

    @pytest.mark.parametrize("ok", ["^Create", "ConsoleLogin", "(User|Role)", "a+b+c+", "\\d{3}"])
    def test_does_not_flag_safe_patterns(self, ok):
        assert not api._NESTED_QUANTIFIER_RE.search(ok)


class TestShippedRulesAreSafe:
    def test_no_shipped_regex_rule_trips_the_heuristic(self):
        offenders = []
        for path in _RULES_DIR.rglob("*.json"):
            rule = json.loads(path.read_text())
            for cond in _iter_conditions(rule):
                if cond.get("op") in ("matches", "not_matches"):
                    value = cond.get("value")
                    if isinstance(value, str) and api._NESTED_QUANTIFIER_RE.search(value):
                        offenders.append((path.name, value))
        assert offenders == [], f"shipped regex rules trip the ReDoS heuristic: {offenders}"


def _iter_conditions(obj):
    if isinstance(obj, dict):
        if "field" in obj and "op" in obj:
            yield obj
        for v in obj.values():
            yield from _iter_conditions(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _iter_conditions(v)

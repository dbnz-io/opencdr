"""Write-time field-root validation for rule conditions (item 2, api.py).

Complements the runtime guard in detection_engine.get_field. A condition
`field` whose first dot-segment is outside ALLOWED_FIELD_ROOTS is warn-and-allow
by default (so a customer's existing rule is never silently rejected) and a
hard reject only under STRICT_RULE_VALIDATION. Also guards that no *shipped*
rule uses an off-allowlist root, and that the roots are published via /help.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

from src.domain.ocsf_min_parser import NormalizedEvent
from src.handlers import api

_REPO_ROOT = Path(__file__).resolve().parents[2]
_RULES_DIR = _REPO_ROOT / "support_files" / "detection_rules"


def _signal_rule(field: str) -> dict:
    return {
        "rule_kind": "signal",
        "rule_id": "r1",
        "severity": "HIGH",
        "conditions": [{"field": field, "op": "equals", "value": "x"}],
    }


class TestFieldRootValidation:
    def test_allowed_root_passes(self, monkeypatch):
        monkeypatch.delenv("STRICT_RULE_VALIDATION", raising=False)
        out = api._normalize_rule_payload(_signal_rule("actor.user_name"), force_rule_id="r1")
        assert out["conditions"][0]["field"] == "actor.user_name"

    def test_offroot_warns_and_allows_by_default(self, monkeypatch):
        monkeypatch.delenv("STRICT_RULE_VALIDATION", raising=False)
        # Not rejected -- returns normally with the condition intact.
        out = api._normalize_rule_payload(_signal_rule("nope.something"), force_rule_id="r1")
        assert out["conditions"][0]["field"] == "nope.something"

    def test_offroot_rejected_under_strict(self, monkeypatch):
        monkeypatch.setenv("STRICT_RULE_VALIDATION", "true")
        with pytest.raises(ValueError, match="not an allowed field root"):
            api._normalize_rule_payload(_signal_rule("nope.something"), force_rule_id="r1")

    def test_dunder_root_rejected_under_strict(self, monkeypatch):
        monkeypatch.setenv("STRICT_RULE_VALIDATION", "1")
        with pytest.raises(ValueError, match="not an allowed field root"):
            api._normalize_rule_payload(
                _signal_rule("__class__.__init__.__globals__"), force_rule_id="r1"
            )

    def test_allowed_root_passes_even_under_strict(self, monkeypatch):
        monkeypatch.setenv("STRICT_RULE_VALIDATION", "true")
        out = api._normalize_rule_payload(_signal_rule("raw_event.eventName"), force_rule_id="r1")
        assert out["conditions"][0]["field"] == "raw_event.eventName"

    @pytest.mark.parametrize("val", ["", "0", "false", "no", "off"])
    def test_strict_flag_off_values(self, monkeypatch, val):
        monkeypatch.setenv("STRICT_RULE_VALIDATION", val)
        assert api._strict_rule_validation() is False


class TestAllowlistCoversShippedRules:
    def test_allowlist_matches_normalized_event_fields_plus_rule_id(self):
        # Drift guard: the allowlist is NormalizedEvent's public fields, plus
        # rule_id (referenced by correlation rules, not a NormalizedEvent field).
        event_fields = set(NormalizedEvent.__dataclass_fields__)
        assert event_fields <= api.ALLOWED_FIELD_ROOTS
        assert api.ALLOWED_FIELD_ROOTS - event_fields == {"rule_id"}

    def test_no_shipped_rule_uses_an_offlist_root(self):
        offenders: list[tuple[str, str]] = []
        for path in _RULES_DIR.rglob("*.json"):
            rule = json.loads(path.read_text())
            for cond in _iter_conditions(rule):
                field = cond.get("field")
                if not isinstance(field, str) or not field.strip():
                    continue
                root = field.strip().split(".", 1)[0]
                if root not in api.ALLOWED_FIELD_ROOTS:
                    offenders.append((path.name, field))
        assert offenders == [], f"shipped rules use off-allowlist roots: {offenders}"


class TestHelpPublishesRoots:
    def test_help_lists_condition_field_roots(self):
        help_rules = api._help_payload()["endpoints"]["/rules"]
        assert help_rules["condition_field_roots"] == sorted(api.ALLOWED_FIELD_ROOTS)


def _iter_conditions(obj):
    """Yield every condition-shaped dict (has 'field' + 'op') anywhere in a rule."""
    if isinstance(obj, dict):
        if "field" in obj and "op" in obj:
            yield obj
        for v in obj.values():
            yield from _iter_conditions(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _iter_conditions(v)

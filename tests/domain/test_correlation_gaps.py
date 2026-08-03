"""
Additional tests to cover gaps in correlation_engine.py:
  - _get_field with object attributes
  - _as_list with None / non-list scalars
  - _parse_iso edge cases
  - _evaluate_condition with all operators (via signal_conditions)
  - parse_correlation_rule invalid inputs
  - _build_alert exception branches
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from src.domain.correlation_engine import (
    CorrelationEngine,
    _as_list,
    _evaluate_condition,
    _get_field,
    _parse_iso,
    parse_correlation_rule,
)

# ─────────────────────────────────────────────────────────────────────────────
# Re-use signal/rule factories from test_correlation_engine.py shape
# ─────────────────────────────────────────────────────────────────────────────

NOW = datetime(2026, 3, 1, 12, 0, 0, tzinfo=UTC)


def ts(offset: int = 0) -> str:
    return (NOW + timedelta(seconds=offset)).isoformat()


def make_signal(**overrides):
    base = {
        "detection_id": "det-1",
        "event_id": "evt-1",
        "rule_id": "r1",
        "timestamp": ts(),
        "severity": "HIGH",
        "activity_name": "ConsoleLogin",
        "actor": {"user_name": "alice"},
        "api": {"service": "iam.amazonaws.com", "error_code": None},
        "network": {"source_ip": "1.2.3.4"},
        "category": "authn",
    }
    base.update(overrides)
    return base


class FakeRepo:
    def __init__(self, signals):
        self._signals = signals

    def query_signals(self, *, since, group_by_field, group_value, limit=200):
        return [
            s for s in self._signals
            if str(self._get(s, group_by_field)) == group_value
        ][:limit]

    @staticmethod
    def _get(obj, path):
        cur = obj
        for part in path.split("."):
            if isinstance(cur, dict):
                cur = cur.get(part)
            else:
                return None
        return cur


def engine_with(signals):
    return CorrelationEngine(repo=FakeRepo(signals))


def make_rule(**overrides):
    base = {
        "rule_id": "corr-001",
        "rule_kind": "correlation",
        "enabled": True,
        "severity": "CRITICAL",
        "group_by": "actor.user_name",
        "time_window_seconds": 300,
        "threshold": 3,
        "signal_conditions": [],
        "notify": True,
        "response_module": "",
        "playbook": "",
    }
    base.update(overrides)
    return base


# ─────────────────────────────────────────────────────────────────────────────
# _get_field
# ─────────────────────────────────────────────────────────────────────────────


class TestGetField:
    def test_dict_access(self):
        assert _get_field({"a": {"b": "c"}}, "a.b") == "c"

    def test_missing_key_returns_none(self):
        assert _get_field({"a": {}}, "a.b") is None

    def test_object_attribute_access(self):
        class Obj:
            name = "alice"

        assert _get_field(Obj(), "name") == "alice"

    def test_object_missing_attribute_returns_none(self):
        class Obj:
            pass

        assert _get_field(Obj(), "missing") is None

    def test_nested_object_path_stops_at_none(self):
        assert _get_field({"a": None}, "a.b") is None


# ─────────────────────────────────────────────────────────────────────────────
# _as_list
# ─────────────────────────────────────────────────────────────────────────────


class TestAsList:
    def test_none_returns_empty(self):
        assert _as_list(None) == []

    def test_list_returned_as_is(self):
        assert _as_list([1, 2]) == [1, 2]

    def test_scalar_wrapped_in_list(self):
        assert _as_list("single") == ["single"]

    def test_int_wrapped(self):
        assert _as_list(42) == [42]


# ─────────────────────────────────────────────────────────────────────────────
# _parse_iso
# ─────────────────────────────────────────────────────────────────────────────


class TestParseIso:
    def test_valid_iso(self):
        dt = _parse_iso("2026-03-01T12:00:00+00:00")
        assert dt is not None
        assert dt.year == 2026

    def test_zulu_notation(self):
        dt = _parse_iso("2026-03-01T12:00:00Z")
        assert dt is not None

    def test_none_returns_none(self):
        assert _parse_iso(None) is None

    def test_empty_string_returns_none(self):
        assert _parse_iso("") is None

    def test_non_string_returns_none(self):
        assert _parse_iso(12345) is None

    def test_invalid_format_returns_none(self):
        assert _parse_iso("not-a-date") is None


# ─────────────────────────────────────────────────────────────────────────────
# _evaluate_condition — all operators
# ─────────────────────────────────────────────────────────────────────────────


class TestEvaluateConditionAllOps:
    def _sig(self, **overrides):
        return make_signal(**overrides)

    def test_exists_present(self):
        assert _evaluate_condition(self._sig(), {"field": "actor.user_name", "op": "exists"})

    def test_exists_absent(self):
        assert not _evaluate_condition(
            self._sig(actor={}), {"field": "actor.user_name", "op": "exists"}
        )

    def test_not_exists_absent(self):
        assert _evaluate_condition(
            self._sig(actor={}), {"field": "actor.user_name", "op": "not_exists"}
        )

    def test_not_exists_present(self):
        assert not _evaluate_condition(
            self._sig(), {"field": "actor.user_name", "op": "not_exists"}
        )

    def test_equals_match(self):
        assert _evaluate_condition(
            self._sig(), {"field": "actor.user_name", "op": "equals", "value": "alice"}
        )

    def test_not_equals_match(self):
        assert _evaluate_condition(
            self._sig(), {"field": "actor.user_name", "op": "not_equals", "value": "bob"}
        )

    def test_in_match(self):
        assert _evaluate_condition(
            self._sig(),
            {"field": "actor.user_name", "op": "in", "value": ["alice", "bob"]},
        )

    def test_in_no_match(self):
        assert not _evaluate_condition(
            self._sig(),
            {"field": "actor.user_name", "op": "in", "value": ["bob", "charlie"]},
        )

    def test_in_scalar_value_treated_as_list(self):
        assert _evaluate_condition(
            self._sig(),
            {"field": "actor.user_name", "op": "in", "value": "alice"},
        )

    def test_not_in_match(self):
        assert _evaluate_condition(
            self._sig(),
            {"field": "actor.user_name", "op": "not_in", "value": ["bob"]},
        )

    def test_not_in_no_match(self):
        assert not _evaluate_condition(
            self._sig(),
            {"field": "actor.user_name", "op": "not_in", "value": ["alice"]},
        )

    def test_contains_match(self):
        assert _evaluate_condition(
            self._sig(), {"field": "actor.user_name", "op": "contains", "value": "ali"}
        )

    def test_contains_no_match(self):
        assert not _evaluate_condition(
            self._sig(), {"field": "actor.user_name", "op": "contains", "value": "bob"}
        )

    def test_prefix_match(self):
        assert _evaluate_condition(
            self._sig(), {"field": "actor.user_name", "op": "prefix", "value": "ali"}
        )

    def test_prefix_no_match(self):
        assert not _evaluate_condition(
            self._sig(), {"field": "actor.user_name", "op": "prefix", "value": "bob"}
        )

    def test_suffix_match(self):
        assert _evaluate_condition(
            self._sig(), {"field": "actor.user_name", "op": "suffix", "value": "ice"}
        )

    def test_suffix_no_match(self):
        assert not _evaluate_condition(
            self._sig(), {"field": "actor.user_name", "op": "suffix", "value": "xyz"}
        )

    def test_matches_regex(self):
        assert _evaluate_condition(
            self._sig(), {"field": "actor.user_name", "op": "matches", "value": r"^al.*"}
        )

    def test_matches_invalid_regex_returns_false(self):
        assert not _evaluate_condition(
            self._sig(), {"field": "actor.user_name", "op": "matches", "value": "[invalid"}
        )

    def test_unknown_op_returns_false(self):
        assert not _evaluate_condition(
            self._sig(), {"field": "actor.user_name", "op": "gte", "value": "5"}
        )

    def test_none_field_with_value_op_returns_false(self):
        assert not _evaluate_condition(
            self._sig(actor={}), {"field": "actor.user_name", "op": "equals", "value": "alice"}
        )

    def test_no_field_key_defaults_to_exists(self):
        # field=None → observed=None → op="exists" → False
        assert not _evaluate_condition(self._sig(), {"op": "exists"})


# ─────────────────────────────────────────────────────────────────────────────
# Signal conditions used in correlate()
# ─────────────────────────────────────────────────────────────────────────────


class TestSignalConditionOperatorsViaEngine:
    """Verify operator coverage through the engine's signal_conditions path."""

    def _fire(self, rule, signals, new_signal=None):
        if new_signal is None:
            new_signal = signals[-1]
        return engine_with(signals).correlate(new_signal=new_signal, rules=[rule], now=NOW)

    def test_contains_condition_in_signal_conditions(self):
        signals = [make_signal(timestamp=ts(-i)) for i in range(3)]
        rule = make_rule(
            threshold=3,
            signal_conditions=[{"field": "actor.user_name", "op": "contains", "value": "ali"}],
        )
        alerts = self._fire(rule, signals)
        assert len(alerts) == 1

    def test_prefix_condition_in_signal_conditions(self):
        signals = [make_signal(timestamp=ts(-i)) for i in range(3)]
        rule = make_rule(
            threshold=3,
            signal_conditions=[{"field": "actor.user_name", "op": "prefix", "value": "al"}],
        )
        alerts = self._fire(rule, signals)
        assert len(alerts) == 1

    def test_suffix_condition_in_signal_conditions(self):
        signals = [make_signal(timestamp=ts(-i)) for i in range(3)]
        rule = make_rule(
            threshold=3,
            signal_conditions=[{"field": "actor.user_name", "op": "suffix", "value": "ce"}],
        )
        alerts = self._fire(rule, signals)
        assert len(alerts) == 1

    def test_matches_condition_in_signal_conditions(self):
        signals = [make_signal(timestamp=ts(-i)) for i in range(3)]
        rule = make_rule(
            threshold=3,
            signal_conditions=[
                {"field": "actor.user_name", "op": "matches", "value": r"^alice$"}
            ],
        )
        alerts = self._fire(rule, signals)
        assert len(alerts) == 1

    def test_in_condition_in_signal_conditions(self):
        signals = [make_signal(timestamp=ts(-i)) for i in range(3)]
        rule = make_rule(
            threshold=3,
            signal_conditions=[
                {"field": "actor.user_name", "op": "in", "value": ["alice", "root"]}
            ],
        )
        alerts = self._fire(rule, signals)
        assert len(alerts) == 1

    def test_not_in_condition_in_signal_conditions(self):
        signals = [make_signal(timestamp=ts(-i)) for i in range(3)]
        rule = make_rule(
            threshold=3,
            signal_conditions=[
                {"field": "actor.user_name", "op": "not_in", "value": ["root", "admin"]}
            ],
        )
        alerts = self._fire(rule, signals)
        assert len(alerts) == 1

    def test_exists_condition_in_signal_conditions(self):
        signals = [make_signal(timestamp=ts(-i)) for i in range(3)]
        rule = make_rule(
            threshold=3,
            signal_conditions=[{"field": "actor.user_name", "op": "exists"}],
        )
        alerts = self._fire(rule, signals)
        assert len(alerts) == 1

    def test_not_exists_skips_rule_when_field_present(self):
        signals = [make_signal(timestamp=ts(-i)) for i in range(5)]
        rule = make_rule(
            threshold=3,
            signal_conditions=[{"field": "actor.user_name", "op": "not_exists"}],
        )
        alerts = self._fire(rule, signals)
        assert alerts == []


# ─────────────────────────────────────────────────────────────────────────────
# parse_correlation_rule — invalid inputs
# ─────────────────────────────────────────────────────────────────────────────


class TestParseCorrelationRule:
    def test_non_dict_returns_none(self):
        assert parse_correlation_rule("not-a-dict") is None
        assert parse_correlation_rule(42) is None
        assert parse_correlation_rule(None) is None

    def test_missing_rule_id_returns_none(self):
        assert parse_correlation_rule({"enabled": True}) is None

    def test_non_string_rule_id_returns_none(self):
        assert parse_correlation_rule({"rule_id": 123}) is None

    def test_valid_rule_parses(self):
        rule = parse_correlation_rule({"rule_id": "r1", "threshold": 5})
        assert rule is not None
        assert rule.rule_id == "r1"
        assert rule.threshold == 5

    def test_disabled_rule_skipped_by_engine(self):
        signals = [make_signal(timestamp=ts(-i)) for i in range(5)]
        rule_dict = make_rule(enabled=False)
        rule_dict["rule_id"] = "non-dict-invalid"
        # Engine skips disabled rules
        alerts = engine_with(signals).correlate(
            new_signal=signals[0], rules=[make_rule(enabled=False)], now=NOW
        )
        assert alerts == []

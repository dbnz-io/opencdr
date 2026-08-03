"""Tests for the "not_matches" evaluator branch (src/domain/detection_engine.py
evaluate_condition). It's a valid op in api.py's ALLOWED_CONDITION_OPS and
passes rule-creation validation, but had no evaluator branch at all --
falling through to the function's final `return False` regardless of the
actual regex result. Found while adding regex-compile validation for the
sibling "matches" op; fixed alongside it.
"""
from src.domain.detection_engine import evaluate_condition
from src.domain.ocsf_min_parser import Actor, ApiCall, Network, NormalizedEvent


def make_event(**overrides) -> NormalizedEvent:
    kwargs = dict(
        event_id="test-event-id",
        source="cloudtrail",
        time="2026-01-01T00:00:00Z",
        category="iam",
        class_name="api_activity",
        activity_name="CreateUser",
        actor=Actor(user_name="alice"),
        api=ApiCall(service="iam.amazonaws.com", operation="CreateUser", error_code=None),
        network=Network(source_ip="1.2.3.4"),
    )
    kwargs.update(overrides)
    return NormalizedEvent(**kwargs)


class TestNotMatches:
    def test_returns_true_when_pattern_does_not_match(self):
        assert evaluate_condition(
            make_event(), {"field": "activity_name", "op": "not_matches", "value": r"^Delete.*"}
        )

    def test_returns_false_when_pattern_matches(self):
        assert not evaluate_condition(
            make_event(), {"field": "activity_name", "op": "not_matches", "value": r"^Create.*"}
        )

    def test_bad_regex_returns_false_not_raises(self):
        # Same fail-safe shape as the "matches" branch -- a malformed
        # pattern (shouldn't happen given api.py now validates at rule
        # creation, but defense in depth for rules written directly to
        # the table) degrades to False, doesn't crash detection.
        assert not evaluate_condition(
            make_event(), {"field": "activity_name", "op": "not_matches", "value": "[invalid"}
        )

    def test_missing_field_returns_false(self):
        assert not evaluate_condition(
            make_event(), {"field": "nonexistent.field", "op": "not_matches", "value": ".*"}
        )

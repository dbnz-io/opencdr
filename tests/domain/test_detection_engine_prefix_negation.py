"""Tests for "not_prefix"/"not_suffix" (src/domain/detection_engine.py
evaluate_condition) and the unknown-operator warning. Both ops were valid
in api.py's ALLOWED_CONDITION_OPS and passed rule-creation validation, but
had no evaluator branch at all -- falling through to the function's final
`return False` regardless of the actual result, with no warning either
(INFORME-AUTOR-ES.md §3.1). Same class of gap as the pre-existing
"not_matches" fix (test_detection_engine_not_matches.py), fixed the same
way.
"""
import logging

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


class TestNotPrefix:
    def test_returns_true_when_prefix_does_not_match(self):
        assert evaluate_condition(
            make_event(), {"field": "activity_name", "op": "not_prefix", "value": "Delete"}
        )

    def test_returns_false_when_prefix_matches(self):
        assert not evaluate_condition(
            make_event(), {"field": "activity_name", "op": "not_prefix", "value": "Create"}
        )


class TestNotSuffix:
    def test_returns_true_when_suffix_does_not_match(self):
        assert evaluate_condition(
            make_event(), {"field": "api.service", "op": "not_suffix", "value": ".net"}
        )

    def test_returns_false_when_suffix_matches(self):
        assert not evaluate_condition(
            make_event(), {"field": "api.service", "op": "not_suffix", "value": ".amazonaws.com"}
        )


class TestUnknownOperator:
    def test_unknown_operator_returns_false(self):
        assert not evaluate_condition(
            make_event(), {"field": "activity_name", "op": "definitely_not_a_real_op"}
        )

    def test_unknown_operator_logs_a_warning(self, caplog):
        with caplog.at_level(logging.WARNING, logger="src.domain.detection_engine"):
            evaluate_condition(
                make_event(), {"field": "activity_name", "op": "definitely_not_a_real_op"}
            )
        assert any(
            "unknown condition operator" in r.message and "definitely_not_a_real_op" in r.message
            for r in caplog.records
        )

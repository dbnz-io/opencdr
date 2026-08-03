"""Tests for the regex-compile-failure logging added to evaluate_condition
(src/domain/detection_engine.py). Previously `except re.error: return False`
silently and permanently stopped a condition (and its rule) from ever
firing again, with no signal anywhere. Fixed with stdlib `logging` --
kept deliberately decoupled from the custom infra Logger class, since
this is pure domain logic with no infra dependency today.
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


class TestRegexFailureLogging:
    def test_matches_bad_regex_logs_warning(self, caplog):
        with caplog.at_level(logging.WARNING, logger="src.domain.detection_engine"):
            result = evaluate_condition(
                make_event(), {"field": "activity_name", "op": "matches", "value": "[invalid"}
            )

        assert result is False
        assert len(caplog.records) == 1
        assert caplog.records[0].levelname == "WARNING"
        assert "matches" in caplog.records[0].message
        assert "activity_name" in caplog.records[0].message

    def test_not_matches_bad_regex_logs_warning(self, caplog):
        with caplog.at_level(logging.WARNING, logger="src.domain.detection_engine"):
            result = evaluate_condition(
                make_event(), {"field": "activity_name", "op": "not_matches", "value": "(unclosed["}
            )

        assert result is False
        assert len(caplog.records) == 1
        assert "not_matches" in caplog.records[0].message

    def test_valid_regex_does_not_log(self, caplog):
        with caplog.at_level(logging.WARNING, logger="src.domain.detection_engine"):
            evaluate_condition(make_event(), {"field": "activity_name", "op": "matches", "value": "^Create.*"})

        assert len(caplog.records) == 0

"""Tests for build_detection_event's actor_user_name mirror
(src/domain/detection_engine.py).

A flat, top-level denormalization of actor.user_name -- added to back
gsi_signal_actor_user_name (serverless.yml), the GSI that lets the
correlation engine Query recent signals for an actor instead of scanning
the whole signals table (src/handlers/alerter.py DynamoSignalsRepository).
GSI keys must be top-level scalars, not nested inside a map, hence the
mirror; only set when present so the GSI stays sparse.
"""
from src.domain.detection_engine import build_detection_event
from src.domain.ocsf_min_parser import Actor, ApiCall, Network, NormalizedEvent


def make_event(**overrides) -> NormalizedEvent:
    kwargs = dict(
        event_id="test-event-id",
        source="cloudtrail",
        time="2026-01-01T00:00:00Z",
        category="iam",
        class_name="api_activity",
        activity_name="CreateUser",
        actor=Actor(user_name="alice", account_id="123456789012"),
        api=ApiCall(service="iam.amazonaws.com", operation="CreateUser", error_code=None),
        network=Network(source_ip="1.2.3.4"),
    )
    kwargs.update(overrides)
    return NormalizedEvent(**kwargs)


def make_rule(**overrides) -> dict:
    rule = {"rule_id": "r1", "severity": "HIGH"}
    rule.update(overrides)
    return rule


class TestActorUserNameMirror:
    def test_present_when_actor_has_user_name(self):
        detection = build_detection_event(make_event(actor=Actor(user_name="alice")), make_rule())
        assert detection["actor_user_name"] == "alice"

    def test_absent_when_actor_user_name_is_none(self):
        detection = build_detection_event(make_event(actor=Actor(user_name=None)), make_rule())
        assert "actor_user_name" not in detection

    def test_absent_when_actor_user_name_is_empty_string(self):
        detection = build_detection_event(make_event(actor=Actor(user_name="")), make_rule())
        assert "actor_user_name" not in detection

    def test_still_carries_the_nested_actor_dict_unchanged(self):
        # The flat mirror is additive -- correlation_engine._get_field still
        # walks the nested actor.user_name path, unaffected by this.
        detection = build_detection_event(make_event(actor=Actor(user_name="alice")), make_rule())
        assert detection["actor"]["user_name"] == "alice"

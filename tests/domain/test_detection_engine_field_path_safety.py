"""Field-path safety in detection_engine.get_field (item 2).

A rule `field` is a dotted path resolved by dict-lookup or getattr. Without a
guard, `field: "__class__.__init__.__globals__"` walks off the NormalizedEvent
object into Python internals, turning "can author a rule" into a memory-read
primitive. get_field now refuses underscore-prefixed segments on the getattr
path (dict-key access is untouched, so raw_event.* still works).
"""

from src.domain.detection_engine import evaluate_condition, get_field
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
        api=ApiCall(service="iam.amazonaws.com", operation="CreateUser"),
        network=Network(source_ip="1.2.3.4"),
        raw_event={"eventName": "CreateUser", "_weird": "kept", "nested": {"k": "v"}},
    )
    kwargs.update(overrides)
    return NormalizedEvent(**kwargs)


class TestGetFieldStillWorks:
    def test_resolves_top_level_field(self):
        assert get_field(make_event(), "activity_name") == "CreateUser"

    def test_resolves_nested_dataclass_field(self):
        assert get_field(make_event(), "actor.user_name") == "alice"

    def test_resolves_api_operation(self):
        assert get_field(make_event(), "api.operation") == "CreateUser"

    def test_resolves_raw_event_dict_key(self):
        assert get_field(make_event(), "raw_event.eventName") == "CreateUser"

    def test_resolves_deep_raw_event_dict_key(self):
        assert get_field(make_event(), "raw_event.nested.k") == "v"

    def test_dict_key_access_is_not_blocked_for_underscore_keys(self):
        # Underscore keys inside a dict are safe (no code access) and must
        # still resolve -- the guard only applies to getattr traversal.
        assert get_field(make_event(), "raw_event._weird") == "kept"


class TestGetFieldBlocksAttributeWalk:
    def test_dunder_globals_walk_returns_none(self):
        assert get_field(make_event(), "__class__.__init__.__globals__") is None

    def test_single_dunder_segment_returns_none(self):
        assert get_field(make_event(), "__class__") is None

    def test_underscore_prefixed_attr_on_dataclass_returns_none(self):
        # e.g. trying to reach a private attribute off the actor object
        assert get_field(make_event(), "actor.__dict__") is None

    def test_walk_via_string_method_to_globals_is_severed(self):
        # activity_name is a str; ".upper" is a bound method, but the chain
        # to __globals__ is cut at the underscore-prefixed segment.
        assert get_field(make_event(), "activity_name.upper.__globals__") is None

    def test_exploit_condition_does_not_match(self):
        cond = {"field": "__class__.__init__.__globals__", "op": "exists"}
        assert evaluate_condition(make_event(), cond) is False

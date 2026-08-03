from src.domain.detection_engine import evaluate_condition, rule_matches, run_detection
from src.domain.ocsf_min_parser import Actor, ApiCall, Network, NormalizedEvent

# ----------------------------
# Helpers
# ----------------------------


def make_event(**overrides) -> NormalizedEvent:
    kwargs = dict(
        event_id="test-event-id",
        source="cloudtrail",
        time="2026-01-01T00:00:00Z",
        category="iam",
        class_name="api_activity",
        activity_name="CreateUser",
        actor=Actor(
            user_name="alice", account_id="123456789012", arn="arn:aws:iam::123456789012:user/alice"
        ),
        api=ApiCall(service="iam.amazonaws.com", operation="CreateUser", error_code=None),
        network=Network(source_ip="1.2.3.4"),
    )
    kwargs.update(overrides)
    return NormalizedEvent(**kwargs)


def make_rule(conditions, *, rule_id="r1", severity="HIGH", enabled=True, **kwargs) -> dict:
    return {
        "rule_id": rule_id,
        "enabled": enabled,
        "severity": severity,
        "conditions": conditions,
        **kwargs,
    }


# ----------------------------
# evaluate_condition — operators
# ----------------------------


class TestConditionOperators:
    def test_equals_match(self):
        assert evaluate_condition(
            make_event(), {"field": "activity_name", "op": "equals", "value": "CreateUser"}
        )

    def test_equals_no_match(self):
        assert not evaluate_condition(
            make_event(), {"field": "activity_name", "op": "equals", "value": "DeleteUser"}
        )

    def test_not_equals_match(self):
        assert evaluate_condition(
            make_event(), {"field": "activity_name", "op": "not_equals", "value": "DeleteUser"}
        )

    def test_not_equals_no_match(self):
        assert not evaluate_condition(
            make_event(), {"field": "activity_name", "op": "not_equals", "value": "CreateUser"}
        )

    def test_exists_field_present(self):
        assert evaluate_condition(make_event(), {"field": "actor.user_name", "op": "exists"})

    def test_exists_field_absent(self):
        event = make_event(actor=Actor(user_name=None))
        assert not evaluate_condition(event, {"field": "actor.user_name", "op": "exists"})

    def test_not_exists_field_absent(self):
        event = make_event(actor=Actor(user_name=None))
        assert evaluate_condition(event, {"field": "actor.user_name", "op": "not_exists"})

    def test_not_exists_field_present(self):
        assert not evaluate_condition(
            make_event(), {"field": "actor.user_name", "op": "not_exists"}
        )

    def test_in_match(self):
        cond = {"field": "activity_name", "op": "in", "value": ["CreateUser", "DeleteUser"]}
        assert evaluate_condition(make_event(), cond)

    def test_in_no_match(self):
        cond = {"field": "activity_name", "op": "in", "value": ["DeleteUser", "ListUsers"]}
        assert not evaluate_condition(make_event(), cond)

    def test_not_in_match(self):
        cond = {"field": "activity_name", "op": "not_in", "value": ["DeleteUser"]}
        assert evaluate_condition(make_event(), cond)

    def test_not_in_no_match(self):
        cond = {"field": "activity_name", "op": "not_in", "value": ["CreateUser"]}
        assert not evaluate_condition(make_event(), cond)

    def test_contains_match(self):
        assert evaluate_condition(
            make_event(), {"field": "activity_name", "op": "contains", "value": "Create"}
        )

    def test_contains_no_match(self):
        assert not evaluate_condition(
            make_event(), {"field": "activity_name", "op": "contains", "value": "Delete"}
        )

    def test_prefix_match(self):
        assert evaluate_condition(
            make_event(), {"field": "activity_name", "op": "prefix", "value": "Create"}
        )

    def test_prefix_no_match(self):
        assert not evaluate_condition(
            make_event(), {"field": "activity_name", "op": "prefix", "value": "Delete"}
        )

    def test_suffix_match(self):
        assert evaluate_condition(
            make_event(), {"field": "activity_name", "op": "suffix", "value": "User"}
        )

    def test_suffix_no_match(self):
        assert not evaluate_condition(
            make_event(), {"field": "activity_name", "op": "suffix", "value": "Role"}
        )

    def test_matches_regex_match(self):
        assert evaluate_condition(
            make_event(), {"field": "activity_name", "op": "matches", "value": r"^Create.*"}
        )

    def test_matches_regex_no_match(self):
        assert not evaluate_condition(
            make_event(activity_name="DeleteUser"),
            {"field": "activity_name", "op": "matches", "value": r"^Create.*"},
        )

    def test_nested_field_actor_user_name(self):
        assert evaluate_condition(
            make_event(), {"field": "actor.user_name", "op": "equals", "value": "alice"}
        )

    def test_nested_field_api_service(self):
        assert evaluate_condition(
            make_event(), {"field": "api.service", "op": "equals", "value": "iam.amazonaws.com"}
        )

    def test_nested_field_network_source_ip(self):
        assert evaluate_condition(
            make_event(), {"field": "network.source_ip", "op": "equals", "value": "1.2.3.4"}
        )

    def test_field_is_none_with_value_op_returns_false(self):
        event = make_event(actor=Actor(user_name=None))
        assert not evaluate_condition(
            event, {"field": "actor.user_name", "op": "equals", "value": "alice"}
        )

    def test_not_contains_match(self):
        assert evaluate_condition(
            make_event(), {"field": "activity_name", "op": "not_contains", "value": "Delete"}
        )

    def test_not_contains_no_match(self):
        assert not evaluate_condition(
            make_event(), {"field": "activity_name", "op": "not_contains", "value": "Create"}
        )

    def test_matches_bad_regex_returns_false(self):
        result = evaluate_condition(
            make_event(), {"field": "activity_name", "op": "matches", "value": "[invalid"}
        )
        assert result is False

    def test_wildcard_always_matches(self):
        assert evaluate_condition(make_event(), {"op": "wildcard"})

    def test_wildcard_matches_regardless_of_field_value(self):
        event = make_event(actor=Actor(user_name=None))
        assert evaluate_condition(event, {"op": "wildcard"})

    def test_unknown_operator_returns_false(self):
        assert not evaluate_condition(
            make_event(), {"field": "activity_name", "op": "gte", "value": "5"}
        )


# ----------------------------
# rule_matches
# ----------------------------


class TestRuleMatches:
    def test_all_conditions_match(self):
        rule = make_rule(
            [
                {"field": "activity_name", "op": "equals", "value": "CreateUser"},
                {"field": "actor.user_name", "op": "equals", "value": "alice"},
            ]
        )
        assert rule_matches(make_event(), rule)

    def test_one_condition_fails(self):
        rule = make_rule(
            [
                {"field": "activity_name", "op": "equals", "value": "CreateUser"},
                {"field": "actor.user_name", "op": "equals", "value": "bob"},  # alice != bob
            ]
        )
        assert not rule_matches(make_event(), rule)

    def test_empty_conditions_does_not_match(self):
        assert not rule_matches(make_event(), make_rule([]))

    def test_missing_conditions_key_does_not_match(self):
        assert not rule_matches(make_event(), {"rule_id": "r1", "enabled": True})

    def test_wildcard_condition_matches_everything(self):
        assert rule_matches(make_event(), make_rule([{"op": "wildcard"}]))


# ----------------------------
# run_detection
# ----------------------------


class TestRunDetection:
    def test_disabled_rule_is_skipped(self):
        rule = make_rule([{"field": "activity_name", "op": "exists"}], enabled=False)
        assert run_detection(make_event(), [rule]) == []

    def test_matching_rule_produces_detection(self):
        rule = make_rule([{"field": "activity_name", "op": "equals", "value": "CreateUser"}])
        detections = run_detection(make_event(), [rule])
        assert len(detections) == 1
        assert detections[0]["rule_id"] == "r1"
        assert detections[0]["severity"] == "HIGH"

    def test_non_matching_rule_produces_no_detection(self):
        rule = make_rule([{"field": "activity_name", "op": "equals", "value": "DeleteUser"}])
        assert run_detection(make_event(), [rule]) == []

    def test_multiple_matching_rules(self):
        rules = [
            make_rule([{"field": "activity_name", "op": "exists"}], rule_id="r1"),
            make_rule([{"field": "activity_name", "op": "exists"}], rule_id="r2"),
        ]
        detections = run_detection(make_event(), rules)
        assert len(detections) == 2
        assert {d["rule_id"] for d in detections} == {"r1", "r2"}

    def test_mixed_matching_and_non_matching_rules(self):
        rules = [
            make_rule(
                [{"field": "activity_name", "op": "equals", "value": "CreateUser"}], rule_id="r1"
            ),
            make_rule(
                [{"field": "activity_name", "op": "equals", "value": "DeleteUser"}], rule_id="r2"
            ),
        ]
        detections = run_detection(make_event(), rules)
        assert len(detections) == 1
        assert detections[0]["rule_id"] == "r1"

    def test_empty_rules_list(self):
        assert run_detection(make_event(), []) == []

    def test_detection_contains_event_context(self):
        rule = make_rule([{"field": "activity_name", "op": "exists"}])
        event = make_event()
        detection = run_detection(event, [rule])[0]

        assert detection["event_id"] == event.event_id
        assert detection["activity_name"] == "CreateUser"
        assert detection["category"] == "iam"
        assert detection["actor"]["user_name"] == "alice"
        assert "detection_id" in detection
        assert "timestamp" in detection

    def test_each_detection_has_unique_detection_id(self):
        rules = [
            make_rule([{"field": "activity_name", "op": "exists"}], rule_id="r1"),
            make_rule([{"field": "activity_name", "op": "exists"}], rule_id="r2"),
        ]
        detections = run_detection(make_event(), rules)
        ids = [d["detection_id"] for d in detections]
        assert len(set(ids)) == 2

from __future__ import annotations

import pytest

from src.domain.detection_engine import build_detection_event
from src.domain.ocsf_min_parser import Actor, ApiCall, Network, NormalizedEvent
from src.domain.response_actions import resolve_response_actions, validate_response_actions


def test_resolves_multiple_actions_to_fixed_target_keys():
    event = {
        "detection_id": "det-1",
        "actor": {"user_name": "creator"},
        "raw_event": {
            "detail": {
                "responseElements": {
                    "accessKey": {"userName": "target-user", "accessKeyId": "AKIA123"}
                }
            }
        },
    }
    actions = [
        {
            "module": "disable_access_key",
            "target": {
                "user_name": "raw_event.detail.responseElements.accessKey.userName",
                "access_key_id": "raw_event.detail.responseElements.accessKey.accessKeyId",
            },
        },
        {"module": "disable_user", "target": {"user_name": "actor.user_name"}},
    ]

    assert resolve_response_actions(event, actions) == [
        {
            "action_id": "det-1--r1",
            "module": "disable_access_key",
            "target": {"user_name": "target-user", "access_key_id": "AKIA123"},
        },
        {
            "action_id": "det-1--r2",
            "module": "disable_user",
            "target": {"user_name": "creator"},
        },
    ]


def test_unresolved_target_is_retained_as_fail_closed_error():
    resolved = resolve_response_actions(
        {"detection_id": "det-1", "actor": {}},
        [{"module": "disable_user", "target": {"user_name": "actor.user_name"}}],
    )

    assert resolved[0]["target"] == {}
    assert "was not found" in resolved[0]["resolution_error"]


def test_detection_builder_freezes_resolved_targets():
    normalized = NormalizedEvent(
        event_id="event-1",
        source="cloudtrail",
        time="2026-01-01T00:00:00Z",
        category="iam",
        class_name="api_activity",
        activity_name="CreateAccessKey",
        actor=Actor(user_name="creator"),
        api=ApiCall(service="iam.amazonaws.com", operation="CreateAccessKey"),
        network=Network(source_ip="192.0.2.1"),
        raw_event={
            "detail": {
                "responseElements": {
                    "accessKey": {"userName": "target-user", "accessKeyId": "AKIA123"}
                }
            }
        },
    )
    rule = {
        "rule_id": "new-key",
        "response_actions": [
            {
                "module": "disable_access_key",
                "target": {
                    "user_name": "raw_event.detail.responseElements.accessKey.userName",
                    "access_key_id": "raw_event.detail.responseElements.accessKey.accessKeyId",
                },
            },
            {"module": "disable_user", "target": {"user_name": "actor.user_name"}},
        ],
    }

    detection = build_detection_event(normalized, rule)

    assert detection["resolved_response_actions"][0]["target"] == {
        "user_name": "target-user",
        "access_key_id": "AKIA123",
    }
    assert detection["resolved_response_actions"][1]["target"] == {"user_name": "creator"}


def test_module_target_keys_are_fixed():
    with pytest.raises(ValueError, match="missing required keys|unsupported keys"):
        validate_response_actions(
            [{"module": "disable_user", "target": {"invented": "actor.user_name"}}]
        )


def test_inline_policy_requires_exactly_one_principal_kind():
    with pytest.raises(ValueError, match="exactly one"):
        validate_response_actions(
            [
                {
                    "module": "delete_inline_policy",
                    "target": {
                        "policy_name": "raw_event.detail.requestParameters.policyName",
                        "user_name": "raw_event.detail.requestParameters.userName",
                        "role_name": "raw_event.detail.requestParameters.roleName",
                    },
                }
            ]
        )


def test_ec2_isolation_accepts_one_normalized_instance_id():
    resolved = resolve_response_actions(
        {"detection_id": "det-1", "resources": [{"id": "i-0123456789"}]},
        [
            {
                "module": "isolate_ec2_instances",
                "target": {"instance_ids": "resources.0.id"},
            }
        ],
    )

    assert resolved[0]["target"] == {"instance_ids": "i-0123456789"}


def test_legacy_and_multiple_actions_are_mutually_exclusive_in_rule_schema():
    from src.domain.rule_schema import validate_rule_document

    rule = {
        "rule_kind": "signal",
        "rule_id": "r1",
        "enabled": True,
        "notify": True,
        "severity": "HIGH",
        "conditions": [{"field": "activity_name", "op": "equals", "value": "CreateAccessKey"}],
        "response_module": "disable_user",
        "response_actions": [
            {"module": "disable_user", "target": {"user_name": "actor.user_name"}}
        ],
    }

    with pytest.raises(ValueError, match="cannot both"):
        validate_rule_document(rule)

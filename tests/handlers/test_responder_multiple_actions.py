from __future__ import annotations

import json
from unittest.mock import MagicMock

from dredge.aws_ir.models import OperationResult

from src.handlers import responder


def _result(operation: str, target: str) -> OperationResult:
    return OperationResult(operation=operation, target=target, success=True, details={}, errors=[])


def test_executes_each_resolved_action_with_its_own_target_and_action_id(monkeypatch):
    dredge = MagicMock()
    dredge.aws_ir.response.disable_access_key.return_value = _result(
        "disable_access_key", "AKIA123"
    )
    dredge.aws_ir.response.disable_user.return_value = _result("disable_user", "creator")
    monkeypatch.setattr(responder, "_resolve_role_arn", lambda account_id: "arn:role")
    monkeypatch.setattr(responder, "_get_dredge", lambda role_arn: dredge)
    monkeypatch.setattr(responder, "_recent_action_count", lambda: 0)
    monkeypatch.setattr(responder, "_outbox_table", None)
    actions_table = MagicMock()
    monkeypatch.setattr(responder, "_ir_actions_table", actions_table)
    logger = MagicMock()
    event = {
        "detection_id": "det-1",
        "cloud_account_id": "123456789012",
        "resolved_response_actions": [
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
        ],
    }

    responder._process_record({"body": json.dumps(event)}, "req-1", "rh-1", logger)

    dredge.aws_ir.response.disable_access_key.assert_called_once_with(
        user_name="target-user", access_key_id="AKIA123"
    )
    dredge.aws_ir.response.disable_user.assert_called_once_with(user_name="creator")
    action_ids = [
        call.kwargs["details"]["detection_id"]
        for call in logger.info.call_args_list
        if call.kwargs.get("event_name") == "IR_ACTION_SUCCESS"
    ]
    assert action_ids == ["det-1--r1", "det-1--r2"]
    stored = [call.kwargs["Item"] for call in actions_table.put_item.call_args_list]
    assert [item["detection_id"] for item in stored] == ["det-1--r1", "det-1--r2"]
    assert [item["source_detection_id"] for item in stored] == ["det-1", "det-1"]


def test_resolution_error_skips_only_the_invalid_action(monkeypatch):
    process = MagicMock()
    monkeypatch.setattr(responder, "_get_dredge", process)
    logger = MagicMock()
    event = {
        "detection_id": "det-1",
        "resolved_response_actions": [
            {
                "action_id": "det-1--r1",
                "module": "disable_user",
                "target": {},
                "resolution_error": "user_name missing",
            }
        ],
    }

    responder._process_record({"body": json.dumps(event)}, "req-1", "rh-1", logger)

    process.assert_not_called()
    assert logger.error.call_args.kwargs["event_name"] == "IR_TARGET_RESOLUTION_FAILED"


def test_explicit_security_group_rules_are_translated_and_routed_by_activity():
    event = {
        "activity_name": "AuthorizeSecurityGroupIngress",
        "resolved_response_target": {
            "group_id": "sg-123",
            "rules": [
                {
                    "ipProtocol": "tcp",
                    "fromPort": 22,
                    "toPort": 22,
                    "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]},
                }
            ],
        },
    }

    group_id, ingress, egress = responder._extract_security_group_rule_change(event)

    assert group_id == "sg-123"
    assert ingress == [
        {
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }
    ]
    assert egress == []


def test_explicit_single_instance_id_is_wrapped_for_dredge():
    assert responder._extract_instance_ids(
        {"resolved_response_target": {"instance_ids": "i-0123456789"}}
    ) == ["i-0123456789"]


def test_explicit_inline_policy_principal_uses_activity_kind():
    event = {
        "activity_name": "PutRolePolicy",
        "resolved_response_target": {
            "principal_name": "backdoor-role",
            "policy_name": "FullAccess",
        },
    }

    assert responder._extract_inline_policy_principal(event) == (
        None,
        "backdoor-role",
        "FullAccess",
    )

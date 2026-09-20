"""
Backend hardening tests (src/handlers/api.py):

  * IR-role writes reject a role_arn whose embedded account does not match
    aws_account_id (no arbitrary cross-account role mappings).
  * Rollback records server-side audit metadata (actor from the API key id,
    plus client-supplied interface/reason) without trusting caller identity.

External AWS is mocked; no live infra.
"""

from __future__ import annotations

import json
import os
from unittest.mock import MagicMock, patch

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

from src.handlers import api


def make_event(method, path, *, qs=None, path_params=None, body=None, api_key_id=None) -> dict:
    event = {
        "httpMethod": method,
        "path": path,
        "queryStringParameters": qs,
        "pathParameters": path_params,
        "body": json.dumps(body) if body is not None else None,
        "isBase64Encoded": False,
    }
    if api_key_id:
        event["requestContext"] = {"identity": {"apiKeyId": api_key_id}}
    return event


def make_context():
    ctx = MagicMock()
    ctx.aws_request_id = "test-req-id"
    return ctx


def body_of(resp):
    return json.loads(resp["body"])


ACCT = "222222222222"
OTHER = "999999999999"


# ---------------------------------------------------------------------------
# IR-role ARN / account matching
# ---------------------------------------------------------------------------


class TestIrRoleArnAccountMatch:
    def test_put_rejects_cross_account_arn(self):
        with patch.object(api, "ir_account_roles_table") as mock_table:
            resp = api.lambda_handler(
                make_event(
                    "PUT",
                    f"/ir-roles/{ACCT}",
                    path_params={"aws_account_id": ACCT},
                    body={"role_arn": f"arn:aws:iam::{OTHER}:role/opencdr-ir-role"},
                ),
                make_context(),
            )
        assert resp["statusCode"] == 400
        assert "cross-account" in body_of(resp)["message"]
        mock_table.put_item.assert_not_called()

    def test_post_rejects_cross_account_arn(self):
        with patch.object(api, "ir_account_roles_table") as mock_table:
            resp = api.lambda_handler(
                make_event(
                    "POST",
                    "/ir-roles",
                    body={"aws_account_id": ACCT, "role_arn": f"arn:aws:iam::{OTHER}:role/x"},
                ),
                make_context(),
            )
        assert resp["statusCode"] == 400
        assert "cross-account" in body_of(resp)["message"]
        mock_table.put_item.assert_not_called()

    def test_put_accepts_matching_arn(self):
        with patch.object(api, "ir_account_roles_table") as mock_table:
            mock_table.put_item.return_value = {}
            resp = api.lambda_handler(
                make_event(
                    "PUT",
                    f"/ir-roles/{ACCT}",
                    path_params={"aws_account_id": ACCT},
                    body={"role_arn": f"arn:aws:iam::{ACCT}:role/opencdr-ir-role"},
                ),
                make_context(),
            )
        assert resp["statusCode"] == 200
        mock_table.put_item.assert_called_once()
        assert body_of(resp)["aws_account_id"] == ACCT

    def test_put_rejects_non_iam_arn(self):
        with patch.object(api, "ir_account_roles_table") as mock_table:
            resp = api.lambda_handler(
                make_event(
                    "PUT",
                    f"/ir-roles/{ACCT}",
                    path_params={"aws_account_id": ACCT},
                    body={"role_arn": f"arn:aws:s3:::{ACCT}-bucket"},
                ),
                make_context(),
            )
        assert resp["statusCode"] == 400
        mock_table.put_item.assert_not_called()


# ---------------------------------------------------------------------------
# Rollback audit metadata
# ---------------------------------------------------------------------------


def _rollback_action_item():
    return {
        "detection_id": "d-1",
        "rollback_supported": True,
        "response_module": "disable_access_key",
    }


class TestRollbackAudit:
    def test_records_actor_interface_and_reason(self):
        captured = {}

        def _update(**kwargs):
            captured.update(kwargs)
            return {}

        with (
            patch.object(api, "ir_actions_table") as mock_table,
            patch.object(api, "sqs") as mock_sqs,
            patch.object(api, "IR_ROLLBACK_QUEUE_URL", "https://queue"),
        ):
            mock_table.get_item.return_value = {"Item": _rollback_action_item()}
            mock_table.update_item.side_effect = _update
            resp = api.lambda_handler(
                make_event(
                    "POST",
                    "/ir-actions/d-1/rollback",
                    path_params={"detection_id": "d-1"},
                    body={"interface": "mcp", "reason": "false positive"},
                    api_key_id="key-abc",
                ),
                make_context(),
            )
        assert resp["statusCode"] == 202
        mock_sqs.send_message.assert_called_once()
        vals = captured["ExpressionAttributeValues"]
        # actor comes from the authenticated key id, NOT the request body
        assert vals[":actor"] == "key-abc"
        assert vals[":iface"] == "mcp"
        assert vals[":reason"] == "false positive"

    def test_actor_not_forgeable_via_body(self):
        captured = {}

        def _update(**kwargs):
            captured.update(kwargs)
            return {}

        with (
            patch.object(api, "ir_actions_table") as mock_table,
            patch.object(api, "sqs"),
            patch.object(api, "IR_ROLLBACK_QUEUE_URL", "https://queue"),
        ):
            mock_table.get_item.return_value = {"Item": _rollback_action_item()}
            mock_table.update_item.side_effect = _update
            api.lambda_handler(
                make_event(
                    "POST",
                    "/ir-actions/d-1/rollback",
                    path_params={"detection_id": "d-1"},
                    body={"rollback_requested_by": "attacker", "actor": "attacker"},
                    api_key_id="key-real",
                ),
                make_context(),
            )
        vals = captured["ExpressionAttributeValues"]
        assert vals[":actor"] == "key-real"
        # nothing from the body forged the actor
        assert "attacker" not in vals.values()

    def test_reason_is_length_capped(self):
        captured = {}

        def _update(**kwargs):
            captured.update(kwargs)
            return {}

        with (
            patch.object(api, "ir_actions_table") as mock_table,
            patch.object(api, "sqs"),
            patch.object(api, "IR_ROLLBACK_QUEUE_URL", "https://queue"),
        ):
            mock_table.get_item.return_value = {"Item": _rollback_action_item()}
            mock_table.update_item.side_effect = _update
            api.lambda_handler(
                make_event(
                    "POST",
                    "/ir-actions/d-1/rollback",
                    path_params={"detection_id": "d-1"},
                    body={"reason": "x" * 5000},
                    api_key_id="key-real",
                ),
                make_context(),
            )
        assert len(captured["ExpressionAttributeValues"][":reason"]) == 1024

    def test_no_body_still_enqueues(self):
        with (
            patch.object(api, "ir_actions_table") as mock_table,
            patch.object(api, "sqs") as mock_sqs,
            patch.object(api, "IR_ROLLBACK_QUEUE_URL", "https://queue"),
        ):
            mock_table.get_item.return_value = {"Item": _rollback_action_item()}
            mock_table.update_item.return_value = {}
            resp = api.lambda_handler(
                make_event("POST", "/ir-actions/d-1/rollback", path_params={"detection_id": "d-1"}),
                make_context(),
            )
        assert resp["statusCode"] == 202
        mock_sqs.send_message.assert_called_once()

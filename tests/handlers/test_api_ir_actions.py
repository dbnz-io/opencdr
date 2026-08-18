"""Tests for the /ir-actions endpoints (src/handlers/api.py).

One row per executed, rollback-eligible IR action (written by
src/handlers/responder.py); GET lists/fetches them, POST .../rollback
enqueues the actual undo onto ir-rollback-queue for rollbackHandler
(src/handlers/ir_rollback.py) to execute asynchronously.
"""
from __future__ import annotations

import json
import os
from unittest.mock import MagicMock, patch

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

from src.handlers import api


def make_event(method: str, path: str, *, qs=None, path_params=None, body=None) -> dict:
    return {
        "httpMethod": method,
        "path": path,
        "queryStringParameters": qs,
        "pathParameters": path_params,
        "body": body,
        "isBase64Encoded": False,
    }


def make_context():
    ctx = MagicMock()
    ctx.aws_request_id = "test-req-id"
    return ctx


def body_of(resp: dict) -> dict:
    return json.loads(resp["body"])


SUPPORTED_ITEM = {
    "detection_id": "d-1",
    "rule_id": "r-1",
    "response_module": "disable_access_key",
    "undo_module": "enable_access_key",
    "rollback_supported": True,
    "rolled_back": False,
}


class TestListIrActions:
    def test_list_returns_items(self):
        with patch.object(api, "ir_actions_table") as mock_table:
            mock_table.scan.return_value = {"Items": [SUPPORTED_ITEM]}
            resp = api.lambda_handler(make_event("GET", "/ir-actions"), make_context())
        assert resp["statusCode"] == 200
        body = body_of(resp)
        assert body["items"] == [SUPPORTED_ITEM]
        assert body["has_next"] is False

    def test_list_paginates_via_next_token(self):
        with patch.object(api, "ir_actions_table") as mock_table:
            mock_table.scan.return_value = {
                "Items": [SUPPORTED_ITEM],
                "LastEvaluatedKey": {"detection_id": "d-1"},
            }
            resp = api.lambda_handler(make_event("GET", "/ir-actions"), make_context())
        assert resp["statusCode"] == 200
        body = body_of(resp)
        assert body["has_next"] is True
        assert body["next_token"]


class TestGetIrAction:
    def test_get_existing(self):
        with patch.object(api, "ir_actions_table") as mock_table:
            mock_table.get_item.return_value = {"Item": SUPPORTED_ITEM}
            resp = api.lambda_handler(
                make_event("GET", "/ir-actions/d-1", path_params={"detection_id": "d-1"}),
                make_context(),
            )
        assert resp["statusCode"] == 200
        assert body_of(resp)["response_module"] == "disable_access_key"

    def test_get_missing_returns_404(self):
        with patch.object(api, "ir_actions_table") as mock_table:
            mock_table.get_item.return_value = {}
            resp = api.lambda_handler(
                make_event("GET", "/ir-actions/d-404", path_params={"detection_id": "d-404"}),
                make_context(),
            )
        assert resp["statusCode"] == 404


class TestRollbackIrAction:
    def test_missing_detection_returns_404(self):
        with patch.object(api, "ir_actions_table") as mock_table:
            mock_table.get_item.return_value = {}
            resp = api.lambda_handler(
                make_event(
                    "POST", "/ir-actions/d-404/rollback", path_params={"detection_id": "d-404"}
                ),
                make_context(),
            )
        assert resp["statusCode"] == 404

    def test_unsupported_rollback_returns_400(self):
        with patch.object(api, "ir_actions_table") as mock_table:
            mock_table.get_item.return_value = {"Item": {**SUPPORTED_ITEM, "rollback_supported": False}}
            resp = api.lambda_handler(
                make_event("POST", "/ir-actions/d-1/rollback", path_params={"detection_id": "d-1"}),
                make_context(),
            )
        assert resp["statusCode"] == 400

    def test_already_rolled_back_returns_409(self):
        with patch.object(api, "ir_actions_table") as mock_table:
            mock_table.get_item.return_value = {"Item": {**SUPPORTED_ITEM, "rolled_back": True}}
            resp = api.lambda_handler(
                make_event("POST", "/ir-actions/d-1/rollback", path_params={"detection_id": "d-1"}),
                make_context(),
            )
        assert resp["statusCode"] == 409

    def test_already_pending_returns_409(self):
        with patch.object(api, "ir_actions_table") as mock_table:
            mock_table.get_item.return_value = {"Item": {**SUPPORTED_ITEM, "rollback_status": "pending"}}
            resp = api.lambda_handler(
                make_event("POST", "/ir-actions/d-1/rollback", path_params={"detection_id": "d-1"}),
                make_context(),
            )
        assert resp["statusCode"] == 409
        assert "already in progress" in body_of(resp)["message"].lower()

    def test_previously_failed_rollback_can_be_retried(self):
        # rollback_status="failed" is not terminal, unlike rolled_back --
        # a prior failed attempt shouldn't block trying again.
        with (
            patch.object(api, "ir_actions_table") as mock_table,
            patch.object(api, "sqs") as mock_sqs,
            patch.object(api, "IR_ROLLBACK_QUEUE_URL", "https://sqs.example/queue/ir-rollback"),
        ):
            mock_table.get_item.return_value = {
                "Item": {**SUPPORTED_ITEM, "rollback_status": "failed", "rollback_error": "AccessDenied"}
            }
            resp = api.lambda_handler(
                make_event("POST", "/ir-actions/d-1/rollback", path_params={"detection_id": "d-1"}),
                make_context(),
            )
        assert resp["statusCode"] == 202
        mock_sqs.send_message.assert_called_once()

    def test_happy_path_enqueues_returns_202_and_marks_pending(self):
        with (
            patch.object(api, "ir_actions_table") as mock_table,
            patch.object(api, "sqs") as mock_sqs,
            patch.object(api, "IR_ROLLBACK_QUEUE_URL", "https://sqs.example/queue/ir-rollback"),
        ):
            mock_table.get_item.return_value = {"Item": SUPPORTED_ITEM}
            resp = api.lambda_handler(
                make_event("POST", "/ir-actions/d-1/rollback", path_params={"detection_id": "d-1"}),
                make_context(),
            )
        assert resp["statusCode"] == 202
        assert body_of(resp)["detection_id"] == "d-1"
        mock_sqs.send_message.assert_called_once()
        call_kwargs = mock_sqs.send_message.call_args.kwargs
        assert call_kwargs["QueueUrl"] == "https://sqs.example/queue/ir-rollback"
        assert json.loads(call_kwargs["MessageBody"]) == {"detection_id": "d-1"}

        mock_table.update_item.assert_called_once()
        update_kwargs = mock_table.update_item.call_args.kwargs
        assert update_kwargs["Key"] == {"detection_id": "d-1"}
        assert update_kwargs["ExpressionAttributeValues"][":status"] == "pending"

    def test_pending_status_write_failure_does_not_block_the_202(self):
        # The rollback is already enqueued and will run regardless -- a
        # failure to write "pending" is cosmetic, not something that
        # should turn an already-successful enqueue into an error response.
        with (
            patch.object(api, "ir_actions_table") as mock_table,
            patch.object(api, "sqs") as mock_sqs,
            patch.object(api, "IR_ROLLBACK_QUEUE_URL", "https://sqs.example/queue/ir-rollback"),
        ):
            mock_table.get_item.return_value = {"Item": SUPPORTED_ITEM}
            mock_table.update_item.side_effect = RuntimeError("dynamo down")
            resp = api.lambda_handler(
                make_event("POST", "/ir-actions/d-1/rollback", path_params={"detection_id": "d-1"}),
                make_context(),
            )
        assert resp["statusCode"] == 202
        mock_sqs.send_message.assert_called_once()

    def test_no_queue_url_configured_returns_500(self):
        with (
            patch.object(api, "ir_actions_table") as mock_table,
            patch.object(api, "IR_ROLLBACK_QUEUE_URL", ""),
        ):
            mock_table.get_item.return_value = {"Item": SUPPORTED_ITEM}
            resp = api.lambda_handler(
                make_event("POST", "/ir-actions/d-1/rollback", path_params={"detection_id": "d-1"}),
                make_context(),
            )
        assert resp["statusCode"] == 500


class TestIrActionsPathRouting:
    def test_trailing_slash_without_id_returns_400(self):
        resp = api.lambda_handler(make_event("GET", "/ir-actions/"), make_context())
        assert resp["statusCode"] == 400

    def test_get_on_rollback_path_is_not_routed(self):
        # GET .../rollback isn't a defined route -- only POST is.
        resp = api.lambda_handler(
            make_event("GET", "/ir-actions/d-1/rollback", path_params={"detection_id": "d-1"}),
            make_context(),
        )
        assert resp["statusCode"] == 404

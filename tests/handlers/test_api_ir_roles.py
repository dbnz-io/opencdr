"""Tests for the /ir-roles CRUD endpoints (src/handlers/api.py).

Maps an AWS account to the IAM role responder assumes for detections from
that account (src/handlers/responder.py _resolve_role_arn) -- how
additional (non-home) accounts get onboarded for multi-account incident
response.
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


VALID_BODY = {"aws_account_id": "222222222222", "role_arn": "arn:aws:iam::222222222222:role/opencdr-ir-role"}


class TestListIrRoles:
    def test_list_returns_items(self):
        with patch.object(api, "ir_account_roles_table") as mock_table:
            mock_table.scan.return_value = {"Items": [VALID_BODY]}
            resp = api.lambda_handler(make_event("GET", "/ir-roles"), make_context())
        assert resp["statusCode"] == 200
        body = body_of(resp)
        assert body["items"] == [VALID_BODY]
        assert body["has_next"] is False

    def test_list_paginates_via_next_token(self):
        with patch.object(api, "ir_account_roles_table") as mock_table:
            mock_table.scan.return_value = {
                "Items": [VALID_BODY],
                "LastEvaluatedKey": {"aws_account_id": "222222222222"},
            }
            resp = api.lambda_handler(make_event("GET", "/ir-roles"), make_context())
        assert resp["statusCode"] == 200
        body = body_of(resp)
        assert body["has_next"] is True
        assert body["next_token"]


class TestGetIrRole:
    def test_get_existing(self):
        with patch.object(api, "ir_account_roles_table") as mock_table:
            mock_table.get_item.return_value = {"Item": VALID_BODY}
            resp = api.lambda_handler(
                make_event("GET", "/ir-roles/222222222222", path_params={"aws_account_id": "222222222222"}),
                make_context(),
            )
        assert resp["statusCode"] == 200
        assert body_of(resp)["role_arn"] == VALID_BODY["role_arn"]

    def test_get_missing_returns_404(self):
        with patch.object(api, "ir_account_roles_table") as mock_table:
            mock_table.get_item.return_value = {}
            resp = api.lambda_handler(
                make_event("GET", "/ir-roles/999999999999", path_params={"aws_account_id": "999999999999"}),
                make_context(),
            )
        assert resp["statusCode"] == 404


class TestCreateIrRole:
    def test_create_happy_path(self):
        with patch.object(api, "ir_account_roles_table") as mock_table:
            resp = api.lambda_handler(
                make_event("POST", "/ir-roles", body=json.dumps(VALID_BODY)), make_context()
            )
        assert resp["statusCode"] == 201
        body = body_of(resp)
        assert body["aws_account_id"] == "222222222222"
        assert body["enabled"] is True
        assert "updated_at" in body
        mock_table.put_item.assert_called_once()

    def test_create_conflict_returns_409(self):
        with patch.object(api, "ir_account_roles_table") as mock_table:
            from botocore.exceptions import ClientError

            mock_table.put_item.side_effect = ClientError(
                {"Error": {"Code": "ConditionalCheckFailedException", "Message": "condition failed"}},
                "PutItem",
            )
            resp = api.lambda_handler(
                make_event("POST", "/ir-roles", body=json.dumps(VALID_BODY)), make_context()
            )
        assert resp["statusCode"] == 409

    def test_create_missing_account_id_returns_400(self):
        resp = api.lambda_handler(
            make_event("POST", "/ir-roles", body=json.dumps({"role_arn": VALID_BODY["role_arn"]})),
            make_context(),
        )
        assert resp["statusCode"] == 400

    def test_create_non_12_digit_account_id_returns_400(self):
        resp = api.lambda_handler(
            make_event(
                "POST",
                "/ir-roles",
                body=json.dumps({"aws_account_id": "not-an-account-id", "role_arn": VALID_BODY["role_arn"]}),
            ),
            make_context(),
        )
        assert resp["statusCode"] == 400

    def test_create_missing_role_arn_returns_400(self):
        resp = api.lambda_handler(
            make_event("POST", "/ir-roles", body=json.dumps({"aws_account_id": "222222222222"})),
            make_context(),
        )
        assert resp["statusCode"] == 400

    def test_create_malformed_role_arn_returns_400(self):
        resp = api.lambda_handler(
            make_event(
                "POST",
                "/ir-roles",
                body=json.dumps({"aws_account_id": "222222222222", "role_arn": "not-an-arn"}),
            ),
            make_context(),
        )
        assert resp["statusCode"] == 400

    def test_create_defaults_enabled_to_true(self):
        with patch.object(api, "ir_account_roles_table"):
            resp = api.lambda_handler(
                make_event("POST", "/ir-roles", body=json.dumps(VALID_BODY)), make_context()
            )
        assert body_of(resp)["enabled"] is True

    def test_create_non_boolean_enabled_returns_400(self):
        resp = api.lambda_handler(
            make_event(
                "POST",
                "/ir-roles",
                body=json.dumps({**VALID_BODY, "enabled": "yes"}),
            ),
            make_context(),
        )
        assert resp["statusCode"] == 400


class TestUpsertIrRole:
    def test_put_upserts_and_keeps_path_account_id(self):
        with patch.object(api, "ir_account_roles_table") as mock_table:
            resp = api.lambda_handler(
                make_event(
                    "PUT",
                    "/ir-roles/222222222222",
                    path_params={"aws_account_id": "222222222222"},
                    body=json.dumps({"role_arn": VALID_BODY["role_arn"], "enabled": False}),
                ),
                make_context(),
            )
        assert resp["statusCode"] == 200
        body = body_of(resp)
        assert body["aws_account_id"] == "222222222222"
        assert body["enabled"] is False
        mock_table.put_item.assert_called_once()

    def test_put_ignores_mismatched_account_id_in_body(self):
        with patch.object(api, "ir_account_roles_table"):
            resp = api.lambda_handler(
                make_event(
                    "PUT",
                    "/ir-roles/222222222222",
                    path_params={"aws_account_id": "222222222222"},
                    body=json.dumps({"aws_account_id": "999999999999", "role_arn": VALID_BODY["role_arn"]}),
                ),
                make_context(),
            )
        assert body_of(resp)["aws_account_id"] == "222222222222"


class TestDeleteIrRole:
    def test_delete_existing(self):
        with patch.object(api, "ir_account_roles_table") as mock_table:
            mock_table.get_item.return_value = {"Item": VALID_BODY}
            resp = api.lambda_handler(
                make_event("DELETE", "/ir-roles/222222222222", path_params={"aws_account_id": "222222222222"}),
                make_context(),
            )
        assert resp["statusCode"] == 200
        mock_table.delete_item.assert_called_once_with(Key={"aws_account_id": "222222222222"})

    def test_delete_missing_returns_404(self):
        with patch.object(api, "ir_account_roles_table") as mock_table:
            mock_table.get_item.return_value = {}
            resp = api.lambda_handler(
                make_event("DELETE", "/ir-roles/999999999999", path_params={"aws_account_id": "999999999999"}),
                make_context(),
            )
        assert resp["statusCode"] == 404


class TestIrRolesPathWithoutAccountId:
    def test_trailing_slash_without_id_returns_400(self):
        resp = api.lambda_handler(make_event("GET", "/ir-roles/"), make_context())
        assert resp["statusCode"] == 400

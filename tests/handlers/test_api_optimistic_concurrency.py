"""
Backend optimistic-concurrency + actor-attribution tests (src/handlers/api.py):

  * Rules/settings writes honor `expected_rev`: a guarded put is conditional
    on the stored rev, bumps it, and 409s on a mismatch. Unguarded writes stay
    unconditional (backward compatible).
  * `updated_by` is stamped from the server-authenticated API key id, never
    from a client-supplied body value.

DynamoDB is mocked; the ConditionExpression semantics are asserted at the
table.put_item call boundary.
"""

from __future__ import annotations

import json
import os
from unittest.mock import MagicMock, patch

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

from src.handlers import api


def make_event(method, path, *, qs=None, path_params=None, body=None, api_key_id=None):
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
    ctx.aws_request_id = "req"
    return ctx


def body_of(resp):
    return json.loads(resp["body"])


class _Conflict(Exception):
    """Stand-in for botocore ConditionalCheckFailedException (repr matched by handler)."""

    def __repr__(self):
        return "ConditionalCheckFailedException(...)"


# ---------------------------------------------------------------------------
# _pop_expected_rev / _put_with_rev units
# ---------------------------------------------------------------------------


def test_pop_expected_rev_removes_field():
    body = {"a": 1, "expected_rev": 3}
    assert api._pop_expected_rev(body) == 3
    assert "expected_rev" not in body


def test_pop_expected_rev_absent_is_none():
    assert api._pop_expected_rev({"a": 1}) is None


def test_pop_expected_rev_rejects_non_int():
    import pytest

    with pytest.raises(ValueError):
        api._pop_expected_rev({"expected_rev": "nope"})


def test_put_with_rev_unguarded_is_unconditional():
    table = MagicMock()
    item = {"rule_id": "x"}
    out = api._put_with_rev(table, item, None)
    table.put_item.assert_called_once_with(Item=item)
    assert "rev" not in out


def test_put_with_rev_zero_requires_absent_rev():
    table = MagicMock()
    out = api._put_with_rev(table, {"rule_id": "x"}, 0)
    kwargs = table.put_item.call_args.kwargs
    assert kwargs["Item"]["rev"] == 1
    assert "ConditionExpression" in kwargs
    assert out["rev"] == 1


def test_put_with_rev_bumps_and_conditions_on_prev():
    table = MagicMock()
    out = api._put_with_rev(table, {"rule_id": "x"}, 5)
    assert table.put_item.call_args.kwargs["Item"]["rev"] == 6
    assert out["rev"] == 6


def test_put_with_rev_conflict_raises_optimistic_lock():
    import pytest

    table = MagicMock()
    table.put_item.side_effect = _Conflict()
    with pytest.raises(api.OptimisticLockError):
        api._put_with_rev(table, {"rule_id": "x"}, 5)


# ---------------------------------------------------------------------------
# Rule update via the handler
# ---------------------------------------------------------------------------


def test_rule_update_guarded_conflict_returns_409():
    with patch.object(api, "detection_rules_table") as table:
        table.put_item.side_effect = _Conflict()
        resp = api.lambda_handler(
            make_event(
                "PUT",
                "/rules/r1",
                qs={"rule_kind": "signal"},
                path_params={"rule_id": "r1"},
                body={"rule_kind": "signal", "expected_rev": 2, "conditions": []},
            ),
            make_context(),
        )
    assert resp["statusCode"] == 409
    assert "concurrently" in body_of(resp)["message"]


def test_rule_update_guarded_success_bumps_rev():
    with patch.object(api, "detection_rules_table") as table:
        table.put_item.return_value = {}
        resp = api.lambda_handler(
            make_event(
                "PUT",
                "/rules/r1",
                qs={"rule_kind": "signal"},
                path_params={"rule_id": "r1"},
                body={"rule_kind": "signal", "expected_rev": 4, "conditions": []},
            ),
            make_context(),
        )
    assert resp["statusCode"] == 200
    assert body_of(resp)["rev"] == 5
    # expected_rev must never be persisted as a document field
    assert "expected_rev" not in table.put_item.call_args.kwargs["Item"]


def test_rule_update_unguarded_is_unconditional():
    with patch.object(api, "detection_rules_table") as table:
        table.put_item.return_value = {}
        api.lambda_handler(
            make_event(
                "PUT",
                "/rules/r1",
                qs={"rule_kind": "signal"},
                path_params={"rule_id": "r1"},
                body={"rule_kind": "signal", "conditions": []},
            ),
            make_context(),
        )
    assert "ConditionExpression" not in table.put_item.call_args.kwargs


# ---------------------------------------------------------------------------
# Actor attribution: updated_by comes from the key id, not the body
# ---------------------------------------------------------------------------


def test_rule_updated_by_from_key_not_body():
    with patch.object(api, "detection_rules_table") as table:
        table.put_item.return_value = {}
        resp = api.lambda_handler(
            make_event(
                "PUT",
                "/rules/r1",
                qs={"rule_kind": "signal"},
                path_params={"rule_id": "r1"},
                body={"rule_kind": "signal", "conditions": [], "updated_by": "attacker"},
                api_key_id="key-real",
            ),
            make_context(),
        )
    item = body_of(resp)
    assert item["updated_by"] == "key-real"
    assert item["updated_by"] != "attacker"


def test_rule_updated_by_defaults_to_api_without_key():
    with patch.object(api, "detection_rules_table") as table:
        table.put_item.return_value = {}
        resp = api.lambda_handler(
            make_event(
                "PUT",
                "/rules/r1",
                qs={"rule_kind": "signal"},
                path_params={"rule_id": "r1"},
                body={"rule_kind": "signal", "conditions": []},
            ),
            make_context(),
        )
    assert body_of(resp)["updated_by"] == "api"


def test_settings_updated_by_from_key_not_body():
    with (
        patch.object(api, "settings_table") as table,
        patch.object(api, "_resolve_redacted_secrets"),
        patch.object(api, "_externalize_secrets"),
    ):
        table.put_item.return_value = {}
        resp = api.lambda_handler(
            make_event(
                "PUT",
                "/settings/global",
                path_params={"setting_id": "global"},
                body={"updated_by": "attacker", "notifications_enabled": True},
                api_key_id="key-xyz",
            ),
            make_context(),
        )
    assert body_of(resp)["updated_by"] == "key-xyz"


def test_settings_guarded_conflict_returns_409():
    with (
        patch.object(api, "settings_table") as table,
        patch.object(api, "_resolve_redacted_secrets"),
        patch.object(api, "_externalize_secrets"),
    ):
        table.put_item.side_effect = _Conflict()
        resp = api.lambda_handler(
            make_event(
                "PUT",
                "/settings/global",
                path_params={"setting_id": "global"},
                body={"expected_rev": 1, "notifications_enabled": True},
            ),
            make_context(),
        )
    assert resp["statusCode"] == 409


def test_ir_role_updated_by_from_key_not_body():
    acct = "222222222222"
    with patch.object(api, "ir_account_roles_table") as table:
        table.put_item.return_value = {}
        resp = api.lambda_handler(
            make_event(
                "PUT",
                f"/ir-roles/{acct}",
                path_params={"aws_account_id": acct},
                body={"role_arn": f"arn:aws:iam::{acct}:role/IR", "updated_by": "attacker"},
                api_key_id="key-ir",
            ),
            make_context(),
        )
    assert body_of(resp)["updated_by"] == "key-ir"

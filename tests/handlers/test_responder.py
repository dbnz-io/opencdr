"""Tests for the incident-response (responder) Lambda handler.

This locks in *current* behavior as a regression safety net, including one
pre-existing bug in `_extract_user_and_access_key` (see TestExtractUserAndAccessKeyBug
below): `user_name`/`access_key_id` are only assigned inside a deeply nested
`isinstance` chain but read unconditionally afterwards, so several realistic
event shapes raise UnboundLocalError. That is characterized here as-is, not
fixed — a future fix should turn these into "returns (None, None)" tests.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

import os

os.environ.setdefault("LOGS_TABLE_NAME", "test-logs-table")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

from dredge.aws_ir.models import OperationResult
from src.handlers import responder


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_context():
    ctx = MagicMock()
    ctx.aws_request_id = "test-req-id"
    return ctx


def make_record(body_obj) -> dict:
    return {"body": json.dumps(body_obj), "receiptHandle": "rh-1"}


def ok_result(operation="op", target="t") -> OperationResult:
    return OperationResult(operation=operation, target=target, success=True, details={"ok": True})


@pytest.fixture()
def mock_dredge(monkeypatch):
    dredge = MagicMock()
    monkeypatch.setattr(responder, "_get_dredge", lambda role_arn=None: dredge)
    return dredge


# ---------------------------------------------------------------------------
# Extractors — happy paths and fallbacks
# ---------------------------------------------------------------------------


class TestExtractUserAndAccessKey:
    def test_happy_path_from_response_elements(self):
        event = {
            "raw_event": {
                "detail": {
                    "responseElements": {
                        "accessKey": {"userName": "alice", "accessKeyId": "AKIAABC123"}
                    }
                }
            }
        }
        assert responder._extract_user_and_access_key(event) == ("alice", "AKIAABC123")

    def test_fallback_to_user_identity_when_access_key_present_but_no_username(self):
        # accessKey object present (so the assignment branch runs and user_name
        # gets bound, even if None) but with no userName -> fallback kicks in.
        event = {
            "raw_event": {
                "detail": {
                    "responseElements": {"accessKey": {"accessKeyId": "AKIAXYZ"}},
                    "userIdentity": {"userName": "bob"},
                }
            }
        }
        assert responder._extract_user_and_access_key(event) == ("bob", "AKIAXYZ")

    def test_fallback_to_principal_id_when_no_user_name_in_identity(self):
        event = {
            "raw_event": {
                "detail": {
                    "responseElements": {"accessKey": {}},
                    "userIdentity": {"principalId": "AROA123:session"},
                }
            }
        }
        assert responder._extract_user_and_access_key(event) == ("AROA123:session", None)

    def test_missing_response_elements_is_safe_returns_none_none(self):
        # `.get(...) or {}` means an *absent* key degrades to an empty dict,
        # which still satisfies `isinstance(..., dict)` further down the
        # chain -- so a merely-missing field does NOT trip the bug below.
        event = {"raw_event": {"detail": {}}}
        assert responder._extract_user_and_access_key(event) == (None, None)

    def test_missing_raw_event_is_safe_returns_none_none(self):
        event = {}
        assert responder._extract_user_and_access_key(event) == (None, None)


class TestExtractUserAndAccessKeyBug:
    """Characterizes a pre-existing UnboundLocalError risk. Do not fix here.

    `user_name`/`access_key_id` are only assigned inside a nested
    `isinstance(..., dict)` chain but read unconditionally afterwards. Because
    every step in the chain uses `x.get(k) or {}`, a merely *absent* field is
    safe (falls back to `{}`, which still passes `isinstance(..., dict)`).
    The bug only fires when a field is *present* with an explicit non-dict
    value -- a genuine type-confusion / malformed-event case, e.g. a
    `responseElements` or `accessKey` that isn't shaped as expected, or a
    `raw_event` that isn't a dict at all.
    """

    def test_non_dict_raw_event_raises_unbound_local_error(self):
        # isinstance(raw_event, dict) is False entirely -> falls straight
        # through to `return user_name, access_key_id` with neither bound.
        event = {"raw_event": "not-a-dict"}
        with pytest.raises(UnboundLocalError):
            responder._extract_user_and_access_key(event)

    def test_response_elements_present_but_not_a_dict_raises_unbound_local_error(self):
        # responseElements is present (truthy) but not a dict -> the
        # isinstance(resp, dict) branch is skipped entirely, so user_name/
        # access_key_id are never bound, yet still read at the fallback check.
        event = {"raw_event": {"detail": {"responseElements": "not-a-dict"}}}
        with pytest.raises(UnboundLocalError):
            responder._extract_user_and_access_key(event)

    def test_access_key_present_but_not_a_dict_raises_unbound_local_error(self):
        event = {"raw_event": {"detail": {"responseElements": {"accessKey": "not-a-dict"}}}}
        with pytest.raises(UnboundLocalError):
            responder._extract_user_and_access_key(event)

    def test_process_record_degrades_to_logged_skip_not_a_crash(self, mock_dredge):
        """The externally-observable behavior: _handle_disable_access_key is
        invoked as `handler(DREDGE, detection_event)` inside _process_record's
        own try/except (the "IR_ACTION_EXCEPTION" block), which catches the
        bug right there -- it never escapes _process_record, let alone
        lambda_handler. A batch never sees this as a crash."""
        logger = MagicMock()
        record = make_record(
            {
                "response_module": "disable_access_key",
                "detection_id": "d-1",
                "raw_event": "not-a-dict",  # genuinely triggers the bug
            }
        )
        responder._process_record(record, "req-1", "rh-1", logger)
        logger.error.assert_called_once()
        assert logger.error.call_args.kwargs["event_name"] == "IR_ACTION_EXCEPTION"
        assert "UnboundLocalError" in logger.error.call_args.kwargs["details"]["error"]


class TestExtractUserName:
    def test_direct_user_name_field_wins(self):
        assert responder._extract_user_name({"user_name": "carol"}) == "carol"

    def test_fallback_to_user_identity_user_name(self):
        event = {"raw_event": {"detail": {"userIdentity": {"userName": "dave"}}}}
        assert responder._extract_user_name(event) == "dave"

    def test_fallback_to_user_identity_principal_id(self):
        event = {"raw_event": {"detail": {"userIdentity": {"principalId": "AIDA1"}}}}
        assert responder._extract_user_name(event) == "AIDA1"

    def test_fallback_to_request_parameters_user_name(self):
        event = {"raw_event": {"detail": {"requestParameters": {"userName": "erin"}}}}
        assert responder._extract_user_name(event) == "erin"

    def test_missing_everything_returns_none(self):
        assert responder._extract_user_name({}) is None

    def test_non_dict_raw_event_returns_none_not_error(self):
        # Unlike _extract_user_and_access_key, this function initializes
        # user_name up front, so a non-dict raw_event is safe.
        assert responder._extract_user_name({"raw_event": "nope"}) is None


class TestExtractRoleName:
    def test_target_value_used_first(self):
        assert responder._extract_role_name({"target_value": "role-a"}) == "role-a"

    def test_fallback_to_request_parameters_role_name(self):
        event = {"raw_event": {"detail": {"requestParameters": {"roleName": "role-b"}}}}
        assert responder._extract_role_name(event) == "role-b"

    def test_missing_returns_none(self):
        assert responder._extract_role_name({}) is None


class TestExtractAccountId:
    def test_direct_field_wins(self):
        assert responder._extract_account_id({"aws_account_id": "111111111111"}) == "111111111111"

    def test_fallback_to_raw_event_account(self):
        event = {"raw_event": {"account": "222222222222", "detail": {}}}
        assert responder._extract_account_id(event) == "222222222222"

    def test_fallback_to_recipient_account_id(self):
        event = {"raw_event": {"detail": {"recipientAccountId": "333333333333"}}}
        assert responder._extract_account_id(event) == "333333333333"

    def test_missing_returns_none(self):
        assert responder._extract_account_id({}) is None


class TestExtractBucketName:
    def test_target_value_used_first(self):
        assert responder._extract_bucket_name({"target_value": "bucket-a"}) == "bucket-a"

    def test_fallback_to_request_parameters_bucket_name(self):
        event = {"raw_event": {"detail": {"requestParameters": {"bucketName": "bucket-b"}}}}
        assert responder._extract_bucket_name(event) == "bucket-b"

    def test_missing_returns_none(self):
        assert responder._extract_bucket_name({}) is None


class TestExtractBucketAndKey:
    def test_happy_path(self):
        event = {
            "target_value": "bucket-a",
            "raw_event": {"detail": {"requestParameters": {"key": "path/to/object.txt"}}},
        }
        assert responder._extract_bucket_and_key(event) == ("bucket-a", "path/to/object.txt")

    def test_key_name_fallback(self):
        event = {
            "target_value": "bucket-a",
            "raw_event": {"detail": {"requestParameters": {"keyName": "alt.txt"}}},
        }
        assert responder._extract_bucket_and_key(event) == ("bucket-a", "alt.txt")

    def test_missing_key_returns_none_key(self):
        assert responder._extract_bucket_and_key({"target_value": "bucket-a"}) == ("bucket-a", None)


class TestExtractInstanceIds:
    def test_target_value_single_instance(self):
        assert responder._extract_instance_ids({"target_value": "i-0123"}) == ["i-0123"]

    def test_instances_set_of_dicts(self):
        event = {
            "raw_event": {
                "detail": {"requestParameters": {"instancesSet": [{"instanceId": "i-a"}, {"instanceId": "i-b"}]}}
            }
        }
        assert responder._extract_instance_ids(event) == ["i-a", "i-b"]

    def test_instance_ids_list_of_strings(self):
        event = {"raw_event": {"detail": {"requestParameters": {"instanceIds": ["i-c", "i-d"]}}}}
        assert responder._extract_instance_ids(event) == ["i-c", "i-d"]

    def test_single_instance_id_fallback(self):
        event = {"raw_event": {"detail": {"requestParameters": {"instanceId": "i-e"}}}}
        assert responder._extract_instance_ids(event) == ["i-e"]

    def test_deduplicates_and_sorts(self):
        event = {
            "target_value": "i-b",
            "raw_event": {"detail": {"requestParameters": {"instanceIds": ["i-b", "i-a"]}}},
        }
        assert responder._extract_instance_ids(event) == ["i-a", "i-b"]

    def test_no_instances_returns_empty_list(self):
        assert responder._extract_instance_ids({}) == []


# ---------------------------------------------------------------------------
# Individual response handlers — missing-field branches (no dredge call)
# ---------------------------------------------------------------------------


class TestHandlerMissingFieldBranches:
    def test_disable_access_key_missing_fields(self, mock_dredge):
        result = responder._handle_disable_access_key(mock_dredge, {})
        assert result.success is False
        assert "Missing" in result.errors[0]
        mock_dredge.aws_ir.response.disable_access_key.assert_not_called()

    def test_disable_user_missing_user_name(self, mock_dredge):
        result = responder._handle_disable_user(mock_dredge, {})
        assert result.success is False
        mock_dredge.aws_ir.response.disable_user.assert_not_called()

    def test_delete_user_missing_user_name(self, mock_dredge):
        result = responder._handle_delete_user(mock_dredge, {})
        assert result.success is False
        mock_dredge.aws_ir.response.delete_user.assert_not_called()

    def test_disable_role_missing_role_name(self, mock_dredge):
        result = responder._handle_disable_role(mock_dredge, {})
        assert result.success is False
        mock_dredge.aws_ir.response.disable_role.assert_not_called()

    def test_block_s3_public_access_missing_account(self, mock_dredge):
        result = responder._handle_block_s3_public_access(mock_dredge, {})
        assert result.success is False
        mock_dredge.aws_ir.response.block_s3_public_access.assert_not_called()

    def test_block_s3_bucket_public_access_missing_bucket(self, mock_dredge):
        result = responder._handle_block_s3_bucket_public_access(mock_dredge, {})
        assert result.success is False
        mock_dredge.aws_ir.response.block_s3_bucket_public_access.assert_not_called()

    def test_block_s3_object_public_access_missing_bucket_or_key(self, mock_dredge):
        result = responder._handle_block_s3_object_public_access(mock_dredge, {"target_value": "bucket-a"})
        assert result.success is False
        mock_dredge.aws_ir.response.block_s3_object_public_access.assert_not_called()

    def test_isolate_ec2_instances_missing_instances(self, mock_dredge):
        result = responder._handle_isolate_ec2_instances(mock_dredge, {})
        assert result.success is False
        mock_dredge.aws_ir.response.isolate_ec2_instances.assert_not_called()


# ---------------------------------------------------------------------------
# Individual response handlers — happy paths call the right dredge method
# ---------------------------------------------------------------------------


class TestHandlerHappyPaths:
    def test_disable_access_key_calls_dredge(self, mock_dredge):
        mock_dredge.aws_ir.response.disable_access_key.return_value = ok_result()
        event = {
            "raw_event": {
                "detail": {"responseElements": {"accessKey": {"userName": "alice", "accessKeyId": "AKIA1"}}}
            }
        }
        result = responder._handle_disable_access_key(mock_dredge, event)
        mock_dredge.aws_ir.response.disable_access_key.assert_called_once_with(
            user_name="alice", access_key_id="AKIA1"
        )
        assert result.success is True

    def test_disable_user_calls_dredge(self, mock_dredge):
        mock_dredge.aws_ir.response.disable_user.return_value = ok_result()
        result = responder._handle_disable_user(mock_dredge, {"user_name": "bob"})
        mock_dredge.aws_ir.response.disable_user.assert_called_once_with(user_name="bob")
        assert result.success is True

    def test_delete_user_calls_dredge(self, mock_dredge):
        mock_dredge.aws_ir.response.delete_user.return_value = ok_result()
        responder._handle_delete_user(mock_dredge, {"user_name": "carol"})
        mock_dredge.aws_ir.response.delete_user.assert_called_once_with(user_name="carol")

    def test_disable_role_calls_dredge(self, mock_dredge):
        mock_dredge.aws_ir.response.disable_role.return_value = ok_result()
        responder._handle_disable_role(mock_dredge, {"target_value": "role-x"})
        mock_dredge.aws_ir.response.disable_role.assert_called_once_with(role_name="role-x")

    def test_block_s3_public_access_calls_dredge(self, mock_dredge):
        mock_dredge.aws_ir.response.block_s3_public_access.return_value = ok_result()
        responder._handle_block_s3_public_access(mock_dredge, {"aws_account_id": "123456789012"})
        mock_dredge.aws_ir.response.block_s3_public_access.assert_called_once_with(account_id="123456789012")

    def test_block_s3_bucket_public_access_calls_dredge(self, mock_dredge):
        mock_dredge.aws_ir.response.block_s3_bucket_public_access.return_value = ok_result()
        responder._handle_block_s3_bucket_public_access(mock_dredge, {"target_value": "my-bucket"})
        mock_dredge.aws_ir.response.block_s3_bucket_public_access.assert_called_once_with(
            bucket_name="my-bucket"
        )

    def test_block_s3_object_public_access_calls_dredge(self, mock_dredge):
        mock_dredge.aws_ir.response.block_s3_object_public_access.return_value = ok_result()
        event = {
            "target_value": "my-bucket",
            "raw_event": {"detail": {"requestParameters": {"key": "obj.txt"}}},
        }
        responder._handle_block_s3_object_public_access(mock_dredge, event)
        mock_dredge.aws_ir.response.block_s3_object_public_access.assert_called_once_with(
            bucket_name="my-bucket", key="obj.txt"
        )

    def test_isolate_ec2_instances_calls_dredge(self, mock_dredge):
        mock_dredge.aws_ir.response.isolate_ec2_instances.return_value = ok_result()
        responder._handle_isolate_ec2_instances(mock_dredge, {"target_value": "i-0123"})
        mock_dredge.aws_ir.response.isolate_ec2_instances.assert_called_once_with(instance_ids=["i-0123"])


# ---------------------------------------------------------------------------
# _operation_result_to_dict
# ---------------------------------------------------------------------------


class TestOperationResultToDict:
    def test_serializes_all_fields(self):
        result = OperationResult(
            operation="disable_user", target="user=bob", success=True, details={"k": "v"}, errors=[]
        )
        assert responder._operation_result_to_dict(result) == {
            "operation": "disable_user",
            "target": "user=bob",
            "success": True,
            "details": {"k": "v"},
            "errors": [],
        }


# ---------------------------------------------------------------------------
# _process_record — dispatch behavior
# ---------------------------------------------------------------------------


class TestProcessRecordDispatch:
    def test_missing_response_module_logged_and_skipped(self, mock_dredge):
        logger = MagicMock()
        record = make_record({"detection_id": "d-1"})
        responder._process_record(record, "req-1", "rh-1", logger)
        logger.info.assert_called_once()
        assert logger.info.call_args.kwargs["event_name"] == "IR_NO_RESPONSE_MODULE"
        mock_dredge.aws_ir.response.disable_user.assert_not_called()

    def test_unknown_response_module_logged_and_skipped(self, mock_dredge):
        logger = MagicMock()
        record = make_record({"response_module": "nonexistent_module", "detection_id": "d-1"})
        responder._process_record(record, "req-1", "rh-1", logger)
        logger.info.assert_called_once()
        assert logger.info.call_args.kwargs["event_name"] == "IR_UNKNOWN_RESPONSE_MODULE"

    def test_invalid_json_body_logged_and_skipped(self, mock_dredge):
        logger = MagicMock()
        record = {"body": "{not-json", "receiptHandle": "rh-1"}
        responder._process_record(record, "req-1", "rh-1", logger)
        logger.error.assert_called_once()
        assert logger.error.call_args.kwargs["event_name"] == "IR_INVALID_JSON"
        mock_dredge.aws_ir.response.disable_user.assert_not_called()

    def test_empty_body_treated_as_empty_payload(self, mock_dredge):
        logger = MagicMock()
        record = {"body": "", "receiptHandle": "rh-1"}
        responder._process_record(record, "req-1", "rh-1", logger)
        # empty payload -> no response_module -> logged skip, no crash
        assert logger.info.call_args.kwargs["event_name"] == "IR_NO_RESPONSE_MODULE"

    def test_wrapped_detection_event_unwraps(self, mock_dredge):
        mock_dredge.aws_ir.response.disable_user.return_value = ok_result()
        logger = MagicMock()
        record = make_record({"detection_event": {"response_module": "disable_user", "user_name": "wrapped-bob"}})
        responder._process_record(record, "req-1", "rh-1", logger)
        mock_dredge.aws_ir.response.disable_user.assert_called_once_with(user_name="wrapped-bob")

    def test_flat_detection_event_used_directly(self, mock_dredge):
        mock_dredge.aws_ir.response.disable_user.return_value = ok_result()
        logger = MagicMock()
        record = make_record({"response_module": "disable_user", "user_name": "flat-bob"})
        responder._process_record(record, "req-1", "rh-1", logger)
        mock_dredge.aws_ir.response.disable_user.assert_called_once_with(user_name="flat-bob")

    def test_successful_action_logs_success(self, mock_dredge):
        mock_dredge.aws_ir.response.disable_user.return_value = ok_result("disable_user", "user=bob")
        logger = MagicMock()
        record = make_record({"response_module": "disable_user", "user_name": "bob", "detection_id": "d-1"})
        responder._process_record(record, "req-1", "rh-1", logger)
        logger.info.assert_called_once()
        assert logger.info.call_args.kwargs["event_name"] == "IR_ACTION_SUCCESS"

    def test_failed_action_logs_error(self, mock_dredge):
        mock_dredge.aws_ir.response.disable_user.return_value = OperationResult(
            operation="disable_user", target="user=bob", success=False, errors=["boom"]
        )
        logger = MagicMock()
        record = make_record({"response_module": "disable_user", "user_name": "bob", "detection_id": "d-1"})
        responder._process_record(record, "req-1", "rh-1", logger)
        logger.error.assert_called_once()
        assert logger.error.call_args.kwargs["event_name"] == "IR_ACTION_FAILED"

    def test_dredge_call_raising_is_caught_and_logged(self, mock_dredge):
        mock_dredge.aws_ir.response.disable_user.side_effect = RuntimeError("AccessDenied")
        logger = MagicMock()
        record = make_record({"response_module": "disable_user", "user_name": "bob", "detection_id": "d-1"})
        responder._process_record(record, "req-1", "rh-1", logger)
        logger.error.assert_called_once()
        assert logger.error.call_args.kwargs["event_name"] == "IR_ACTION_EXCEPTION"


# ---------------------------------------------------------------------------
# lambda_handler — batch behavior
# ---------------------------------------------------------------------------


class TestLambdaHandler:
    def test_returns_200_with_no_records(self, mock_dredge):
        result = responder.lambda_handler({"Records": []}, make_context())
        assert result["statusCode"] == 200

    def test_processes_multiple_records(self, mock_dredge):
        mock_dredge.aws_ir.response.disable_user.return_value = ok_result()
        event = {
            "Records": [
                make_record({"response_module": "disable_user", "user_name": "alice"}),
                make_record({"response_module": "disable_user", "user_name": "bob"}),
            ]
        }
        result = responder.lambda_handler(event, make_context())
        assert result["statusCode"] == 200
        assert mock_dredge.aws_ir.response.disable_user.call_count == 2

    def test_one_record_raising_does_not_stop_the_batch(self, mock_dredge):
        """The documented design: log but don't re-raise, so the whole batch
        is acknowledged and later records still get processed. Here the first
        record's own internal exception handling already catches its bug
        (see TestExtractUserAndAccessKeyBug), and lambda_handler's outer
        try/except is the safety net for anything that isn't."""
        mock_dredge.aws_ir.response.disable_user.return_value = ok_result()
        event = {
            "Records": [
                # This body triggers the UnboundLocalError bug via disable_access_key.
                make_record({"response_module": "disable_access_key", "raw_event": "not-a-dict"}),
                make_record({"response_module": "disable_user", "user_name": "bob"}),
            ]
        }
        result = responder.lambda_handler(event, make_context())
        assert result["statusCode"] == 200
        assert json.loads(result["body"])["message"] == "Incident response processing complete"
        # second record still got processed despite the first one raising
        mock_dredge.aws_ir.response.disable_user.assert_called_once_with(user_name="bob")

    def test_malformed_record_is_logged_and_skipped_batch_continues(self, mock_dredge):
        """Fixed: `receipt_handle` is now resolved defensively (None for a
        non-dict record) inside the per-record try/except, so a malformed
        record shape (not a dict at all) is logged and skipped instead of
        raising AttributeError straight out of lambda_handler and failing
        the entire batch."""
        mock_dredge.aws_ir.response.disable_user.return_value = ok_result()
        event = {
            "Records": [
                "not-a-dict-record",
                make_record({"response_module": "disable_user", "user_name": "bob"}),
            ]
        }
        result = responder.lambda_handler(event, make_context())
        assert result["statusCode"] == 200
        # second, well-formed record still got processed despite the first
        # record being malformed
        mock_dredge.aws_ir.response.disable_user.assert_called_once_with(user_name="bob")

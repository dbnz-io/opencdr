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
# _resource_by_type — GuardDuty-shaped fallback source
# ---------------------------------------------------------------------------


class TestResourceByType:
    def test_returns_first_matching_type(self):
        event = {
            "resources": [
                {"type": "AWS::S3::Bucket", "id": "b1", "name": "b1"},
                {"type": "AWS::IAM::User", "id": "alice", "name": "alice"},
            ]
        }
        assert responder._resource_by_type(event, "AWS::IAM::User") == {
            "type": "AWS::IAM::User",
            "id": "alice",
            "name": "alice",
        }

    def test_accepts_multiple_candidate_types(self):
        event = {"resources": [{"type": "AWS::IAM::AccessKey", "id": "AKIA1", "name": "AKIA1"}]}
        assert responder._resource_by_type(event, "AWS::IAM::User", "AWS::IAM::AccessKey") is not None

    def test_no_match_returns_none(self):
        event = {"resources": [{"type": "AWS::EC2::Instance", "id": "i-1", "name": "i-1"}]}
        assert responder._resource_by_type(event, "AWS::IAM::User") is None

    def test_missing_resources_returns_none(self):
        assert responder._resource_by_type({}, "AWS::IAM::User") is None

    def test_non_dict_entries_are_skipped_not_error(self):
        event = {"resources": ["not-a-dict", {"type": "AWS::IAM::User", "id": "bob", "name": "bob"}]}
        assert responder._resource_by_type(event, "AWS::IAM::User") == {
            "type": "AWS::IAM::User",
            "id": "bob",
            "name": "bob",
        }


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

    def test_falls_back_to_resources_list_when_no_raw_event(self):
        # GuardDuty-shaped alert_item: no CloudTrail raw_event, but the
        # normalized resources list carries the IAM user/access key.
        event = {
            "resources": [
                {"type": "AWS::IAM::User", "id": "suspicious-user", "name": "suspicious-user"},
                {"type": "AWS::IAM::AccessKey", "id": "AKIAIOSFODNN7EXAMPLE", "name": "AKIAIOSFODNN7EXAMPLE"},
            ]
        }
        assert responder._extract_user_and_access_key(event) == (
            "suspicious-user",
            "AKIAIOSFODNN7EXAMPLE",
        )

    def test_missing_raw_event_is_safe_returns_none_none(self):
        event = {}
        assert responder._extract_user_and_access_key(event) == (None, None)


class TestExtractUserAndAccessKeyBug:
    """Was a pre-existing UnboundLocalError risk -- fixed (INFORME-AUTOR-ES.md
    §3.2): user_name/access_key_id are now initialized before the nested
    isinstance(..., dict) chain, so a field that's present but the wrong
    shape (or a raw_event that isn't a dict at all) degrades to (None, None)
    instead of raising. Class name/location kept so this stays discoverable
    from the same place the original bug report lived.
    """

    def test_non_dict_raw_event_returns_none_none(self):
        event = {"raw_event": "not-a-dict"}
        assert responder._extract_user_and_access_key(event) == (None, None)

    def test_response_elements_present_but_not_a_dict_returns_none_none(self):
        event = {"raw_event": {"detail": {"responseElements": "not-a-dict"}}}
        assert responder._extract_user_and_access_key(event) == (None, None)

    def test_access_key_present_but_not_a_dict_returns_none_none(self):
        event = {"raw_event": {"detail": {"responseElements": {"accessKey": "not-a-dict"}}}}
        assert responder._extract_user_and_access_key(event) == (None, None)

    def test_process_record_degrades_to_logged_skip_not_a_crash(self, mock_dredge):
        """The externally-observable behavior: with the extraction bug fixed,
        _handle_disable_access_key's own "Missing user_name or access_key_id"
        business-logic path handles this cleanly -- no exception is raised at
        all, so this now logs the same IR_ACTION_FAILED path any legitimately
        unresolvable detection would."""
        logger = MagicMock()
        record = make_record(
            {
                "response_module": "disable_access_key",
                "detection_id": "d-1",
                "raw_event": "not-a-dict",  # previously triggered the bug
            }
        )
        responder._process_record(record, "req-1", "rh-1", logger)
        logger.error.assert_called_once()
        assert logger.error.call_args.kwargs["event_name"] == "IR_ACTION_FAILED"
        result = logger.error.call_args.kwargs["details"]["operation_result"]
        assert result["success"] is False
        assert "Missing user_name or access_key_id" in result["errors"]


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

    def test_falls_back_to_resources_list_when_no_raw_event(self):
        event = {"resources": [{"type": "AWS::IAM::User", "id": "frank", "name": "frank"}]}
        assert responder._extract_user_name(event) == "frank"

    def test_direct_field_wins_over_resources_list(self):
        event = {
            "user_name": "grace",
            "resources": [{"type": "AWS::IAM::User", "id": "frank", "name": "frank"}],
        }
        assert responder._extract_user_name(event) == "grace"


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

    def test_falls_back_to_resources_list_when_no_raw_event(self):
        event = {"resources": [{"type": "AWS::S3::Bucket", "id": "demo-public-bucket", "name": "demo-public-bucket"}]}
        assert responder._extract_bucket_name(event) == "demo-public-bucket"


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

    def test_collects_all_matches_from_resources_list(self):
        event = {
            "resources": [
                {"type": "AWS::EC2::Instance", "id": "i-aaa", "name": "i-aaa"},
                {"type": "AWS::EC2::Instance", "id": "i-bbb", "name": "i-bbb"},
                {"type": "AWS::S3::Bucket", "id": "not-an-instance", "name": "not-an-instance"},
            ]
        }
        assert responder._extract_instance_ids(event) == ["i-aaa", "i-bbb"]

    def test_resources_list_merged_and_deduped_with_cloudtrail_shape(self):
        event = {
            "target_value": "i-aaa",
            "resources": [{"type": "AWS::EC2::Instance", "id": "i-aaa", "name": "i-aaa"}],
        }
        assert responder._extract_instance_ids(event) == ["i-aaa"]


class TestExtractRdsSnapshot:
    def test_instance_snapshot(self):
        event = {"raw_event": {"detail": {"requestParameters": {"dBSnapshotIdentifier": "snap-1"}}}}
        assert responder._extract_rds_snapshot(event) == ("snap-1", "instance")

    def test_cluster_snapshot(self):
        event = {"raw_event": {"detail": {"requestParameters": {"dBClusterSnapshotIdentifier": "csnap-1"}}}}
        assert responder._extract_rds_snapshot(event) == ("csnap-1", "cluster")

    def test_instance_takes_priority_when_both_present(self):
        event = {
            "raw_event": {
                "detail": {
                    "requestParameters": {
                        "dBSnapshotIdentifier": "snap-1",
                        "dBClusterSnapshotIdentifier": "csnap-1",
                    }
                }
            }
        }
        assert responder._extract_rds_snapshot(event) == ("snap-1", "instance")

    def test_missing_returns_none_id_cluster_type(self):
        assert responder._extract_rds_snapshot({}) == (None, "cluster")


class TestExtractInlinePolicyPrincipal:
    def test_user_policy(self):
        event = {"raw_event": {"detail": {"requestParameters": {"userName": "alice", "policyName": "WildcardPolicy"}}}}
        assert responder._extract_inline_policy_principal(event) == ("alice", None, "WildcardPolicy")

    def test_role_policy(self):
        event = {"raw_event": {"detail": {"requestParameters": {"roleName": "my-role", "policyName": "p"}}}}
        assert responder._extract_inline_policy_principal(event) == (None, "my-role", "p")

    def test_group_policy_has_no_user_or_role(self):
        event = {"raw_event": {"detail": {"requestParameters": {"groupName": "my-group", "policyName": "p"}}}}
        assert responder._extract_inline_policy_principal(event) == (None, None, "p")

    def test_missing_returns_all_none(self):
        assert responder._extract_inline_policy_principal({}) == (None, None, None)


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

    def test_revoke_active_sessions_missing_user_name(self, mock_dredge):
        result = responder._handle_revoke_active_sessions(mock_dredge, {})
        assert result.success is False
        mock_dredge.aws_ir.response.revoke_active_sessions.assert_not_called()

    def test_quarantine_s3_bucket_missing_bucket(self, mock_dredge):
        result = responder._handle_quarantine_s3_bucket(mock_dredge, {})
        assert result.success is False
        mock_dredge.aws_ir.response.quarantine_s3_bucket.assert_not_called()

    def test_deauthorize_security_group_rules_missing_group_id(self, mock_dredge):
        event = {
            "activity_name": "AuthorizeSecurityGroupIngress",
            "raw_event": {"detail": {"requestParameters": {"ipPermissions": {"items": []}}}},
        }
        result = responder._handle_deauthorize_security_group_rules(mock_dredge, event)
        assert result.success is False
        mock_dredge.aws_ir.response.deauthorize_security_group_rules.assert_not_called()

    def test_deauthorize_security_group_rules_missing_translatable_rule(self, mock_dredge):
        # group_id present, but no CIDR-based rule to translate (e.g. only
        # a security-group-reference source, out of scope for this pass).
        event = {
            "activity_name": "AuthorizeSecurityGroupIngress",
            "raw_event": {"detail": {"requestParameters": {"groupId": "sg-0abc123"}}},
        }
        result = responder._handle_deauthorize_security_group_rules(mock_dredge, event)
        assert result.success is False
        mock_dredge.aws_ir.response.deauthorize_security_group_rules.assert_not_called()

    def test_disable_lambda_function_missing_function_name(self, mock_dredge):
        result = responder._handle_disable_lambda_function(mock_dredge, {})
        assert result.success is False
        mock_dredge.aws_ir.response.disable_lambda_function.assert_not_called()

    def test_disable_secrets_manager_secret_missing_secret_id(self, mock_dredge):
        result = responder._handle_disable_secrets_manager_secret(mock_dredge, {})
        assert result.success is False
        mock_dredge.aws_ir.response.disable_secrets_manager_secret.assert_not_called()

    def test_enable_cloudtrail_logging_missing_trail_name(self, mock_dredge):
        result = responder._handle_enable_cloudtrail_logging(mock_dredge, {})
        assert result.success is False
        mock_dredge.aws_ir.response.enable_cloudtrail_logging.assert_not_called()

    def test_enable_guardduty_detector_missing_detector_id(self, mock_dredge):
        result = responder._handle_enable_guardduty_detector(mock_dredge, {})
        assert result.success is False
        mock_dredge.aws_ir.response.enable_guardduty_detector.assert_not_called()

    def test_start_config_recorder_missing_recorder_name(self, mock_dredge):
        result = responder._handle_start_config_recorder(mock_dredge, {})
        assert result.success is False
        mock_dredge.aws_ir.response.start_config_recorder.assert_not_called()

    def test_revoke_rds_snapshot_public_access_missing_snapshot_id(self, mock_dredge):
        result = responder._handle_revoke_rds_snapshot_public_access(mock_dredge, {})
        assert result.success is False
        mock_dredge.aws_ir.response.revoke_rds_snapshot_public_access.assert_not_called()

    def test_delete_inline_policy_missing_principal(self, mock_dredge):
        event = {"raw_event": {"detail": {"requestParameters": {"policyName": "p"}}}}
        result = responder._handle_delete_inline_policy(mock_dredge, event)
        assert result.success is False
        mock_dredge.aws_ir.response.delete_inline_policy.assert_not_called()

    def test_delete_inline_policy_missing_policy_name(self, mock_dredge):
        event = {"raw_event": {"detail": {"requestParameters": {"userName": "alice"}}}}
        result = responder._handle_delete_inline_policy(mock_dredge, event)
        assert result.success is False
        mock_dredge.aws_ir.response.delete_inline_policy.assert_not_called()

    def test_delete_inline_policy_group_policy_is_unsupported(self, mock_dredge):
        event = {"raw_event": {"detail": {"requestParameters": {"groupName": "my-group", "policyName": "p"}}}}
        result = responder._handle_delete_inline_policy(mock_dredge, event)
        assert result.success is False
        assert "group" in result.details["reason"].lower()
        mock_dredge.aws_ir.response.delete_inline_policy.assert_not_called()


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

    def test_revoke_active_sessions_calls_dredge(self, mock_dredge):
        mock_dredge.aws_ir.response.revoke_active_sessions.return_value = ok_result()
        event = {"resources": [{"type": "AWS::IAM::User", "id": "suspicious-user", "name": "suspicious-user"}]}
        result = responder._handle_revoke_active_sessions(mock_dredge, event)
        mock_dredge.aws_ir.response.revoke_active_sessions.assert_called_once_with(user_name="suspicious-user")
        assert result.success is True

    def test_quarantine_s3_bucket_calls_dredge(self, mock_dredge):
        mock_dredge.aws_ir.response.quarantine_s3_bucket.return_value = ok_result()
        event = {
            "cloud_account_id": "123456789012",
            "resources": [{"type": "AWS::S3::Bucket", "id": "demo-public-bucket", "name": "demo-public-bucket"}],
        }
        result = responder._handle_quarantine_s3_bucket(mock_dredge, event)
        mock_dredge.aws_ir.response.quarantine_s3_bucket.assert_called_once_with(
            bucket_name="demo-public-bucket", account_id="123456789012"
        )
        assert result.success is True

    def test_deauthorize_security_group_rules_ingress_calls_dredge(self, mock_dredge):
        mock_dredge.aws_ir.response.deauthorize_security_group_rules.return_value = ok_result()
        event = {
            "activity_name": "AuthorizeSecurityGroupIngress",
            "raw_event": {
                "detail": {
                    "requestParameters": {
                        "groupId": "sg-0abc123",
                        "ipPermissions": {
                            "items": [
                                {
                                    "ipProtocol": "tcp",
                                    "fromPort": 22,
                                    "toPort": 22,
                                    "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]},
                                }
                            ]
                        },
                    }
                }
            },
        }
        result = responder._handle_deauthorize_security_group_rules(mock_dredge, event)
        mock_dredge.aws_ir.response.deauthorize_security_group_rules.assert_called_once_with(
            group_id="sg-0abc123",
            ingress_rules=[{"IpProtocol": "tcp", "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "FromPort": 22, "ToPort": 22}],
            egress_rules=None,
        )
        assert result.success is True

    def test_disable_lambda_function_calls_dredge(self, mock_dredge):
        mock_dredge.aws_ir.response.disable_lambda_function.return_value = ok_result()
        event = {"raw_event": {"detail": {"requestParameters": {"functionName": "backdoor-function"}}}}
        result = responder._handle_disable_lambda_function(mock_dredge, event)
        mock_dredge.aws_ir.response.disable_lambda_function.assert_called_once_with(
            function_name="backdoor-function"
        )
        assert result.success is True

    def test_disable_secrets_manager_secret_calls_dredge(self, mock_dredge):
        mock_dredge.aws_ir.response.disable_secrets_manager_secret.return_value = ok_result()
        event = {"raw_event": {"detail": {"requestParameters": {"secretId": "prod/database/password"}}}}
        result = responder._handle_disable_secrets_manager_secret(mock_dredge, event)
        mock_dredge.aws_ir.response.disable_secrets_manager_secret.assert_called_once_with(
            secret_id="prod/database/password"
        )
        assert result.success is True

    def test_enable_cloudtrail_logging_calls_dredge(self, mock_dredge):
        mock_dredge.aws_ir.response.enable_cloudtrail_logging.return_value = ok_result()
        event = {"raw_event": {"detail": {"requestParameters": {"name": "org-trail"}}}}
        result = responder._handle_enable_cloudtrail_logging(mock_dredge, event)
        mock_dredge.aws_ir.response.enable_cloudtrail_logging.assert_called_once_with(trail_name="org-trail")
        assert result.success is True

    def test_enable_guardduty_detector_calls_dredge(self, mock_dredge):
        mock_dredge.aws_ir.response.enable_guardduty_detector.return_value = ok_result()
        event = {"raw_event": {"detail": {"requestParameters": {"detectorId": "det-1"}}}}
        result = responder._handle_enable_guardduty_detector(mock_dredge, event)
        mock_dredge.aws_ir.response.enable_guardduty_detector.assert_called_once_with(detector_id="det-1")
        assert result.success is True

    def test_start_config_recorder_calls_dredge(self, mock_dredge):
        mock_dredge.aws_ir.response.start_config_recorder.return_value = ok_result()
        event = {"raw_event": {"detail": {"requestParameters": {"configurationRecorderName": "default"}}}}
        result = responder._handle_start_config_recorder(mock_dredge, event)
        mock_dredge.aws_ir.response.start_config_recorder.assert_called_once_with(recorder_name="default")
        assert result.success is True

    def test_enable_security_hub_calls_dredge_with_no_args(self, mock_dredge):
        mock_dredge.aws_ir.response.enable_security_hub.return_value = ok_result()
        result = responder._handle_enable_security_hub(mock_dredge, {})
        mock_dredge.aws_ir.response.enable_security_hub.assert_called_once_with()
        assert result.success is True

    def test_revoke_rds_snapshot_public_access_calls_dredge(self, mock_dredge):
        mock_dredge.aws_ir.response.revoke_rds_snapshot_public_access.return_value = ok_result()
        event = {"raw_event": {"detail": {"requestParameters": {"dBSnapshotIdentifier": "snap-1"}}}}
        result = responder._handle_revoke_rds_snapshot_public_access(mock_dredge, event)
        mock_dredge.aws_ir.response.revoke_rds_snapshot_public_access.assert_called_once_with(
            snapshot_id="snap-1", snapshot_type="instance"
        )
        assert result.success is True

    def test_revoke_rds_snapshot_public_access_cluster_calls_dredge(self, mock_dredge):
        mock_dredge.aws_ir.response.revoke_rds_snapshot_public_access.return_value = ok_result()
        event = {"raw_event": {"detail": {"requestParameters": {"dBClusterSnapshotIdentifier": "csnap-1"}}}}
        result = responder._handle_revoke_rds_snapshot_public_access(mock_dredge, event)
        mock_dredge.aws_ir.response.revoke_rds_snapshot_public_access.assert_called_once_with(
            snapshot_id="csnap-1", snapshot_type="cluster"
        )
        assert result.success is True

    def test_delete_inline_policy_user_calls_dredge(self, mock_dredge):
        mock_dredge.aws_ir.response.delete_inline_policy.return_value = ok_result()
        event = {"raw_event": {"detail": {"requestParameters": {"userName": "alice", "policyName": "WildcardPolicy"}}}}
        result = responder._handle_delete_inline_policy(mock_dredge, event)
        mock_dredge.aws_ir.response.delete_inline_policy.assert_called_once_with(
            user_name="alice", role_name=None, policy_name="WildcardPolicy"
        )
        assert result.success is True

    def test_delete_inline_policy_role_calls_dredge(self, mock_dredge):
        mock_dredge.aws_ir.response.delete_inline_policy.return_value = ok_result()
        event = {"raw_event": {"detail": {"requestParameters": {"roleName": "my-role", "policyName": "p"}}}}
        result = responder._handle_delete_inline_policy(mock_dredge, event)
        mock_dredge.aws_ir.response.delete_inline_policy.assert_called_once_with(
            user_name=None, role_name="my-role", policy_name="p"
        )
        assert result.success is True


# ---------------------------------------------------------------------------
# _extract_security_group_rule_change
# ---------------------------------------------------------------------------


class TestExtractSecurityGroupRuleChange:
    def test_translates_ingress_cidr_rule(self):
        event = {
            "activity_name": "AuthorizeSecurityGroupIngress",
            "raw_event": {
                "detail": {
                    "requestParameters": {
                        "groupId": "sg-0abc123",
                        "ipPermissions": {
                            "items": [
                                {
                                    "ipProtocol": "tcp",
                                    "fromPort": 22,
                                    "toPort": 22,
                                    "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]},
                                }
                            ]
                        },
                    }
                }
            },
        }
        group_id, ingress, egress = responder._extract_security_group_rule_change(event)
        assert group_id == "sg-0abc123"
        assert ingress == [{"IpProtocol": "tcp", "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "FromPort": 22, "ToPort": 22}]
        assert egress == []

    def test_translates_egress_cidr_rule(self):
        event = {
            "activity_name": "AuthorizeSecurityGroupEgress",
            "raw_event": {
                "detail": {
                    "requestParameters": {
                        "groupId": "sg-0abc123",
                        "ipPermissions": {
                            "items": [
                                {
                                    "ipProtocol": "-1",
                                    "ipRanges": {"items": [{"cidrIp": "10.0.0.0/8"}]},
                                }
                            ]
                        },
                    }
                }
            },
        }
        group_id, ingress, egress = responder._extract_security_group_rule_change(event)
        assert group_id == "sg-0abc123"
        assert ingress == []
        # IpProtocol "-1" (all traffic) has no FromPort/ToPort in the real event either.
        assert egress == [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}]

    def test_multiple_permissions_and_multiple_cidrs_translated(self):
        event = {
            "activity_name": "AuthorizeSecurityGroupIngress",
            "raw_event": {
                "detail": {
                    "requestParameters": {
                        "groupId": "sg-0abc123",
                        "ipPermissions": {
                            "items": [
                                {
                                    "ipProtocol": "tcp",
                                    "fromPort": 443,
                                    "toPort": 443,
                                    "ipRanges": {"items": [{"cidrIp": "1.1.1.1/32"}, {"cidrIp": "2.2.2.2/32"}]},
                                },
                                {
                                    "ipProtocol": "tcp",
                                    "fromPort": 3389,
                                    "toPort": 3389,
                                    "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]},
                                },
                            ]
                        },
                    }
                }
            },
        }
        _, ingress, _ = responder._extract_security_group_rule_change(event)
        assert len(ingress) == 2
        assert ingress[0]["IpRanges"] == [{"CidrIp": "1.1.1.1/32"}, {"CidrIp": "2.2.2.2/32"}]
        assert ingress[1]["FromPort"] == 3389

    def test_non_cidr_source_skipped_not_guessed(self):
        # A security-group-reference source (UserIdGroupPairs) has no
        # ipRanges at all -- deliberately out of scope, must not raise.
        event = {
            "activity_name": "AuthorizeSecurityGroupIngress",
            "raw_event": {
                "detail": {
                    "requestParameters": {
                        "groupId": "sg-0abc123",
                        "ipPermissions": {
                            "items": [{"ipProtocol": "tcp", "fromPort": 22, "toPort": 22, "groups": {"items": []}}]
                        },
                    }
                }
            },
        }
        group_id, ingress, egress = responder._extract_security_group_rule_change(event)
        assert group_id == "sg-0abc123"
        assert ingress == []
        assert egress == []

    def test_missing_group_id_returns_none(self):
        event = {"activity_name": "AuthorizeSecurityGroupIngress", "raw_event": {"detail": {"requestParameters": {}}}}
        group_id, ingress, egress = responder._extract_security_group_rule_change(event)
        assert group_id is None
        assert ingress == []
        assert egress == []

    def test_unrecognized_activity_name_extracts_neither(self):
        # Rule 011 gates on both Ingress/Egress activity_name -- this
        # guards against a future new activity_name being wired without a
        # matching translation branch, silently extracting nothing rather
        # than erroring.
        event = {
            "activity_name": "SomethingElse",
            "raw_event": {
                "detail": {
                    "requestParameters": {
                        "groupId": "sg-0abc123",
                        "ipPermissions": {"items": [{"ipProtocol": "tcp", "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}}]},
                    }
                }
            },
        }
        _, ingress, egress = responder._extract_security_group_rule_change(event)
        assert ingress == []
        assert egress == []


# ---------------------------------------------------------------------------
# RESPONSE_MODULE_HANDLERS registry
# ---------------------------------------------------------------------------


class TestResponseModuleHandlersRegistry:
    def test_has_exactly_nineteen_entries(self):
        assert len(responder.RESPONSE_MODULE_HANDLERS) == 19

    def test_guardduty_handlers_registered(self):
        assert responder.RESPONSE_MODULE_HANDLERS["revoke_active_sessions"] is responder._handle_revoke_active_sessions
        assert responder.RESPONSE_MODULE_HANDLERS["quarantine_s3_bucket"] is responder._handle_quarantine_s3_bucket

    def test_response_module_coverage_handlers_registered(self):
        assert (
            responder.RESPONSE_MODULE_HANDLERS["deauthorize_security_group_rules"]
            is responder._handle_deauthorize_security_group_rules
        )
        assert responder.RESPONSE_MODULE_HANDLERS["disable_lambda_function"] is responder._handle_disable_lambda_function
        assert (
            responder.RESPONSE_MODULE_HANDLERS["disable_secrets_manager_secret"]
            is responder._handle_disable_secrets_manager_secret
        )

    def test_security_tooling_and_rds_and_inline_policy_handlers_registered(self):
        assert (
            responder.RESPONSE_MODULE_HANDLERS["enable_cloudtrail_logging"]
            is responder._handle_enable_cloudtrail_logging
        )
        assert (
            responder.RESPONSE_MODULE_HANDLERS["enable_guardduty_detector"]
            is responder._handle_enable_guardduty_detector
        )
        assert responder.RESPONSE_MODULE_HANDLERS["start_config_recorder"] is responder._handle_start_config_recorder
        assert responder.RESPONSE_MODULE_HANDLERS["enable_security_hub"] is responder._handle_enable_security_hub
        assert (
            responder.RESPONSE_MODULE_HANDLERS["revoke_rds_snapshot_public_access"]
            is responder._handle_revoke_rds_snapshot_public_access
        )
        assert responder.RESPONSE_MODULE_HANDLERS["delete_inline_policy"] is responder._handle_delete_inline_policy


# ---------------------------------------------------------------------------
# Rollback: ROLLBACK_UNDO_MODULE / _build_rollback_kwargs / _write_ir_action_record
# ---------------------------------------------------------------------------


class TestRollbackUndoModuleRegistry:
    def test_has_exactly_fourteen_entries(self):
        assert len(responder.ROLLBACK_UNDO_MODULE) == 14

    def test_maps_to_dredge_undo_function_names(self):
        assert responder.ROLLBACK_UNDO_MODULE["disable_access_key"] == "enable_access_key"
        assert responder.ROLLBACK_UNDO_MODULE["revoke_active_sessions"] == "revoke_deny_all_session_policy"
        assert responder.ROLLBACK_UNDO_MODULE["deauthorize_security_group_rules"] == "authorize_security_group_rules"
        assert responder.ROLLBACK_UNDO_MODULE["block_s3_public_access"] == "restore_s3_account_public_access_block"
        assert (
            responder.ROLLBACK_UNDO_MODULE["block_s3_bucket_public_access"]
            == "restore_s3_bucket_public_access_block_and_acl"
        )
        assert responder.ROLLBACK_UNDO_MODULE["block_s3_object_public_access"] == "restore_s3_object_acl"
        assert responder.ROLLBACK_UNDO_MODULE["disable_lambda_function"] == "restore_lambda_concurrency"
        assert responder.ROLLBACK_UNDO_MODULE["disable_secrets_manager_secret"] == "restore_secrets_manager_secret"
        assert responder.ROLLBACK_UNDO_MODULE["disable_user"] == "restore_user"
        assert responder.ROLLBACK_UNDO_MODULE["disable_role"] == "restore_role"
        assert responder.ROLLBACK_UNDO_MODULE["quarantine_s3_bucket"] == "restore_s3_bucket_quarantine"
        assert (
            responder.ROLLBACK_UNDO_MODULE["isolate_ec2_instances"]
            == "restore_ec2_instance_security_groups"
        )
        assert (
            responder.ROLLBACK_UNDO_MODULE["revoke_rds_snapshot_public_access"]
            == "restore_rds_snapshot_public_access"
        )
        assert responder.ROLLBACK_UNDO_MODULE["delete_inline_policy"] == "restore_inline_policy"


class TestBuildRollbackKwargs:
    def test_disable_access_key(self):
        event = {
            "raw_event": {"detail": {"responseElements": {"accessKey": {"userName": "alice", "accessKeyId": "AKIA1"}}}}
        }
        kwargs = responder._build_rollback_kwargs("disable_access_key", event, ok_result())
        assert kwargs == {"user_name": "alice", "access_key_id": "AKIA1"}

    def test_revoke_active_sessions(self):
        event = {"resources": [{"type": "AWS::IAM::User", "id": "suspicious-user", "name": "suspicious-user"}]}
        kwargs = responder._build_rollback_kwargs("revoke_active_sessions", event, ok_result())
        assert kwargs == {"user_name": "suspicious-user"}

    def test_deauthorize_security_group_rules(self):
        event = {
            "activity_name": "AuthorizeSecurityGroupIngress",
            "raw_event": {
                "detail": {
                    "requestParameters": {
                        "groupId": "sg-0abc123",
                        "ipPermissions": {
                            "items": [
                                {
                                    "ipProtocol": "tcp",
                                    "fromPort": 22,
                                    "toPort": 22,
                                    "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]},
                                }
                            ]
                        },
                    }
                }
            },
        }
        kwargs = responder._build_rollback_kwargs("deauthorize_security_group_rules", event, ok_result())
        assert kwargs == {
            "group_id": "sg-0abc123",
            "ingress_rules": [
                {"IpProtocol": "tcp", "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "FromPort": 22, "ToPort": 22}
            ],
            "egress_rules": None,
        }

    def test_disable_secrets_manager_secret(self):
        event = {"raw_event": {"detail": {"requestParameters": {"secretId": "prod/database/password"}}}}
        kwargs = responder._build_rollback_kwargs("disable_secrets_manager_secret", event, ok_result())
        assert kwargs == {"secret_id": "prod/database/password"}

    def test_block_s3_public_access_uses_rollback_state(self):
        event = {"aws_account_id": "123456789012"}
        result = OperationResult(
            operation="block_s3_public_access",
            target="account=123456789012",
            success=True,
            details={"rollback_state": {"public_access_block_configuration": {"BlockPublicAcls": False}}},
        )
        kwargs = responder._build_rollback_kwargs("block_s3_public_access", event, result)
        assert kwargs == {
            "account_id": "123456789012",
            "public_access_block_configuration": {"BlockPublicAcls": False},
        }

    def test_block_s3_public_access_none_when_capture_failed(self):
        event = {"aws_account_id": "123456789012"}
        result = OperationResult(operation="block_s3_public_access", target="t", success=True, details={})
        assert responder._build_rollback_kwargs("block_s3_public_access", event, result) is None

    def test_block_s3_bucket_public_access_uses_rollback_state(self):
        event = {"target_value": "my-bucket"}
        result = OperationResult(
            operation="block_s3_bucket_public_access",
            target="t",
            success=True,
            details={
                "rollback_state": {
                    "public_access_block_configuration": None,
                    "access_control_policy": {"Owner": {"ID": "o"}, "Grants": []},
                }
            },
        )
        kwargs = responder._build_rollback_kwargs("block_s3_bucket_public_access", event, result)
        assert kwargs == {
            "bucket_name": "my-bucket",
            "public_access_block_configuration": None,
            "access_control_policy": {"Owner": {"ID": "o"}, "Grants": []},
        }

    def test_block_s3_object_public_access_uses_rollback_state(self):
        event = {"target_value": "my-bucket", "raw_event": {"detail": {"requestParameters": {"key": "obj.txt"}}}}
        result = OperationResult(
            operation="block_s3_object_public_access",
            target="t",
            success=True,
            details={"rollback_state": {"access_control_policy": {"Owner": {"ID": "o"}, "Grants": []}}},
        )
        kwargs = responder._build_rollback_kwargs("block_s3_object_public_access", event, result)
        assert kwargs == {
            "bucket_name": "my-bucket",
            "key": "obj.txt",
            "access_control_policy": {"Owner": {"ID": "o"}, "Grants": []},
        }

    def test_block_s3_object_public_access_none_when_acl_capture_failed(self):
        event = {"target_value": "my-bucket", "raw_event": {"detail": {"requestParameters": {"key": "obj.txt"}}}}
        result = OperationResult(
            operation="block_s3_object_public_access", target="t", success=True, details={"rollback_state": {}}
        )
        assert responder._build_rollback_kwargs("block_s3_object_public_access", event, result) is None

    def test_disable_lambda_function_uses_rollback_state(self):
        event = {"raw_event": {"detail": {"requestParameters": {"functionName": "backdoor-function"}}}}
        result = OperationResult(
            operation="disable_lambda_function",
            target="t",
            success=True,
            details={"rollback_state": {"reserved_concurrent_executions": 5}},
        )
        kwargs = responder._build_rollback_kwargs("disable_lambda_function", event, result)
        assert kwargs == {"function_name": "backdoor-function", "reserved_concurrent_executions": 5}

    def test_disable_lambda_function_none_when_capture_failed(self):
        event = {"raw_event": {"detail": {"requestParameters": {"functionName": "backdoor-function"}}}}
        result = OperationResult(operation="disable_lambda_function", target="t", success=True, details={})
        assert responder._build_rollback_kwargs("disable_lambda_function", event, result) is None

    def test_non_rollback_module_returns_none(self):
        assert responder._build_rollback_kwargs("delete_user", {}, ok_result()) is None

    def test_disable_user(self):
        event = {"resources": [{"type": "AWS::IAM::User", "id": "alice", "name": "alice"}]}
        result = OperationResult(
            operation="disable_user",
            target="user=alice",
            success=True,
            details={
                "access_keys_disabled": ["K1"],
                "groups_removed": ["admins"],
                "managed_policies_detached": ["arn:aws:iam::policy/P1"],
                "inline_policies": {"inline1": {"Version": "2012-10-17", "Statement": []}},
            },
        )
        kwargs = responder._build_rollback_kwargs("disable_user", event, result)
        assert kwargs == {
            "user_name": "alice",
            "access_keys_disabled": ["K1"],
            "groups_removed": ["admins"],
            "managed_policies_detached": ["arn:aws:iam::policy/P1"],
            "inline_policies": {"inline1": {"Version": "2012-10-17", "Statement": []}},
        }

    def test_disable_user_still_buildable_when_inline_policies_capture_failed(self):
        event = {"resources": [{"type": "AWS::IAM::User", "id": "alice", "name": "alice"}]}
        result = OperationResult(
            operation="disable_user",
            target="user=alice",
            success=True,
            details={"access_keys_disabled": ["K1"], "groups_removed": [], "managed_policies_detached": []},
        )
        kwargs = responder._build_rollback_kwargs("disable_user", event, result)
        assert kwargs["inline_policies"] is None
        assert kwargs["access_keys_disabled"] == ["K1"]

    def test_disable_role(self):
        event = {"target_value": "my-role"}
        result = OperationResult(
            operation="disable_role",
            target="role=my-role",
            success=True,
            details={
                "managed_policies_detached": ["arn:aws:iam::policy/P1"],
                "inline_policies": {"inline1": {"Version": "2012-10-17", "Statement": []}},
            },
        )
        kwargs = responder._build_rollback_kwargs("disable_role", event, result)
        assert kwargs == {
            "role_name": "my-role",
            "managed_policies_detached": ["arn:aws:iam::policy/P1"],
            "inline_policies": {"inline1": {"Version": "2012-10-17", "Statement": []}},
        }

    def test_quarantine_s3_bucket_uses_rollback_state(self):
        event = {"target_value": "my-bucket"}
        result = OperationResult(
            operation="quarantine_s3_bucket",
            target="bucket=my-bucket",
            success=True,
            details={
                "rollback_state": {
                    "public_access_block_configuration": None,
                    "bucket_policy": '{"Version":"2012-10-17","Statement":[]}',
                }
            },
        )
        kwargs = responder._build_rollback_kwargs("quarantine_s3_bucket", event, result)
        assert kwargs == {
            "bucket_name": "my-bucket",
            "public_access_block_configuration": None,
            "bucket_policy": '{"Version":"2012-10-17","Statement":[]}',
        }

    def test_quarantine_s3_bucket_none_when_capture_failed(self):
        event = {"target_value": "my-bucket"}
        result = OperationResult(operation="quarantine_s3_bucket", target="t", success=True, details={})
        assert responder._build_rollback_kwargs("quarantine_s3_bucket", event, result) is None

    def test_isolate_ec2_instances_uses_rollback_state(self):
        result = OperationResult(
            operation="isolate_ec2_instances",
            target="i-001",
            success=True,
            details={"rollback_state": {"instance_security_groups": {"i-001": ["sg-orig-1", "sg-orig-2"]}}},
        )
        kwargs = responder._build_rollback_kwargs("isolate_ec2_instances", {}, result)
        assert kwargs == {"instance_security_groups": {"i-001": ["sg-orig-1", "sg-orig-2"]}}

    def test_isolate_ec2_instances_none_when_capture_failed(self):
        result = OperationResult(
            operation="isolate_ec2_instances", target="t", success=True, details={"rollback_state": {}}
        )
        assert responder._build_rollback_kwargs("isolate_ec2_instances", {}, result) is None

    def test_revoke_rds_snapshot_public_access_uses_rollback_state(self):
        event = {"raw_event": {"detail": {"requestParameters": {"dBSnapshotIdentifier": "snap-1"}}}}
        result = OperationResult(
            operation="revoke_rds_snapshot_public_access",
            target="t",
            success=True,
            details={"rollback_state": {"restore_values": ["all", "999999999999"]}},
        )
        kwargs = responder._build_rollback_kwargs("revoke_rds_snapshot_public_access", event, result)
        assert kwargs == {
            "snapshot_id": "snap-1",
            "snapshot_type": "instance",
            "restore_values": ["all", "999999999999"],
        }

    def test_revoke_rds_snapshot_public_access_empty_restore_values_still_rollback_eligible(self):
        # An empty capture (nothing was public before this action) is a
        # real, valid prior state -- rollback should still be offered, it
        # just restores to "no explicit public access" (a no-op on the
        # dredge side, not a failure).
        event = {"raw_event": {"detail": {"requestParameters": {"dBSnapshotIdentifier": "snap-1"}}}}
        result = OperationResult(
            operation="revoke_rds_snapshot_public_access",
            target="t",
            success=True,
            details={"rollback_state": {"restore_values": []}},
        )
        kwargs = responder._build_rollback_kwargs("revoke_rds_snapshot_public_access", event, result)
        assert kwargs == {"snapshot_id": "snap-1", "snapshot_type": "instance", "restore_values": []}

    def test_revoke_rds_snapshot_public_access_none_when_capture_failed(self):
        event = {"raw_event": {"detail": {"requestParameters": {"dBSnapshotIdentifier": "snap-1"}}}}
        result = OperationResult(operation="revoke_rds_snapshot_public_access", target="t", success=True, details={})
        assert responder._build_rollback_kwargs("revoke_rds_snapshot_public_access", event, result) is None

    def test_delete_inline_policy_uses_rollback_state(self):
        event = {"raw_event": {"detail": {"requestParameters": {"userName": "alice", "policyName": "WildcardPolicy"}}}}
        result = OperationResult(
            operation="delete_inline_policy",
            target="t",
            success=True,
            details={"rollback_state": {"policy_document": {"Version": "2012-10-17", "Statement": []}}},
        )
        kwargs = responder._build_rollback_kwargs("delete_inline_policy", event, result)
        assert kwargs == {
            "user_name": "alice",
            "role_name": None,
            "policy_name": "WildcardPolicy",
            "policy_document": {"Version": "2012-10-17", "Statement": []},
        }

    def test_delete_inline_policy_none_when_capture_failed(self):
        event = {"raw_event": {"detail": {"requestParameters": {"userName": "alice", "policyName": "p"}}}}
        result = OperationResult(operation="delete_inline_policy", target="t", success=True, details={})
        assert responder._build_rollback_kwargs("delete_inline_policy", event, result) is None


class TestWriteIrActionRecord:
    def test_no_table_configured_is_a_noop(self):
        logger = MagicMock()
        responder._write_ir_action_record(
            detection_event={},
            detection_id="d-1",
            rule_id="r-1",
            response_module="disable_access_key",
            result=ok_result(),
            account_id="123456789012",
            role_arn="arn:aws:iam::123456789012:role/ir-role",
            logger=logger,
        )
        logger.error.assert_not_called()

    def test_missing_detection_id_is_a_noop(self, monkeypatch):
        table = MagicMock()
        monkeypatch.setattr(responder, "_ir_actions_table", table)
        logger = MagicMock()
        responder._write_ir_action_record(
            detection_event={},
            detection_id=None,
            rule_id="r-1",
            response_module="disable_access_key",
            result=ok_result(),
            account_id="123456789012",
            role_arn="arn:aws:iam::123456789012:role/ir-role",
            logger=logger,
        )
        table.put_item.assert_not_called()

    def test_writes_row_with_rollback_kwargs_when_supported(self, monkeypatch):
        table = MagicMock()
        monkeypatch.setattr(responder, "_ir_actions_table", table)
        event = {
            "raw_event": {"detail": {"responseElements": {"accessKey": {"userName": "alice", "accessKeyId": "AKIA1"}}}}
        }
        result = OperationResult(
            operation="disable_access_key", target="user=alice,access_key_id=AKIA1", success=True, details={}
        )
        responder._write_ir_action_record(
            detection_event=event,
            detection_id="d-1",
            rule_id="r-1",
            response_module="disable_access_key",
            result=result,
            account_id="123456789012",
            role_arn="arn:aws:iam::123456789012:role/ir-role",
            logger=MagicMock(),
        )
        item = table.put_item.call_args.kwargs["Item"]
        assert item["detection_id"] == "d-1"
        assert item["response_module"] == "disable_access_key"
        assert item["undo_module"] == "enable_access_key"
        assert item["rollback_supported"] is True
        assert item["rolled_back"] is False
        assert json.loads(item["rollback_kwargs"]) == {"user_name": "alice", "access_key_id": "AKIA1"}

    def test_writes_row_with_rollback_unsupported_when_capture_failed(self, monkeypatch):
        table = MagicMock()
        monkeypatch.setattr(responder, "_ir_actions_table", table)
        result = OperationResult(operation="block_s3_public_access", target="account=123456789012", success=True, details={})
        responder._write_ir_action_record(
            detection_event={"aws_account_id": "123456789012"},
            detection_id="d-1",
            rule_id="r-1",
            response_module="block_s3_public_access",
            result=result,
            account_id="123456789012",
            role_arn="arn:aws:iam::123456789012:role/ir-role",
            logger=MagicMock(),
        )
        item = table.put_item.call_args.kwargs["Item"]
        assert item["rollback_supported"] is False
        assert "rollback_kwargs" not in item

    def test_put_item_failure_is_logged_not_raised(self, monkeypatch):
        table = MagicMock()
        table.put_item.side_effect = RuntimeError("boom")
        monkeypatch.setattr(responder, "_ir_actions_table", table)
        logger = MagicMock()
        responder._write_ir_action_record(
            detection_event={},
            detection_id="d-1",
            rule_id="r-1",
            response_module="revoke_active_sessions",
            result=ok_result(),
            account_id="123456789012",
            role_arn="arn:aws:iam::123456789012:role/ir-role",
            logger=logger,
        )
        logger.error.assert_called_once()
        assert logger.error.call_args.kwargs["event_name"] == "IR_ACTION_RECORD_WRITE_FAILED"


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

    def test_rollback_eligible_success_writes_ir_action_record(self, mock_dredge, monkeypatch):
        table = MagicMock()
        monkeypatch.setattr(responder, "_ir_actions_table", table)
        mock_dredge.aws_ir.response.revoke_active_sessions.return_value = ok_result(
            "revoke_active_sessions", "user=bob"
        )
        record = make_record(
            {"response_module": "revoke_active_sessions", "user_name": "bob", "detection_id": "d-1"}
        )
        responder._process_record(record, "req-1", "rh-1", MagicMock())
        item = table.put_item.call_args.kwargs["Item"]
        assert item["detection_id"] == "d-1"
        assert item["response_module"] == "revoke_active_sessions"
        assert item["undo_module"] == "revoke_deny_all_session_policy"
        assert item["rollback_supported"] is True

    def test_non_rollback_eligible_success_does_not_write_ir_action_record(self, mock_dredge, monkeypatch):
        table = MagicMock()
        monkeypatch.setattr(responder, "_ir_actions_table", table)
        mock_dredge.aws_ir.response.delete_user.return_value = ok_result("delete_user", "user=bob")
        record = make_record({"response_module": "delete_user", "user_name": "bob", "detection_id": "d-1"})
        responder._process_record(record, "req-1", "rh-1", MagicMock())
        table.put_item.assert_not_called()

    def test_failed_rollback_eligible_action_does_not_write_ir_action_record(self, mock_dredge, monkeypatch):
        table = MagicMock()
        monkeypatch.setattr(responder, "_ir_actions_table", table)
        mock_dredge.aws_ir.response.revoke_active_sessions.return_value = OperationResult(
            operation="revoke_active_sessions", target="user=bob", success=False, errors=["boom"]
        )
        record = make_record(
            {"response_module": "revoke_active_sessions", "user_name": "bob", "detection_id": "d-1"}
        )
        responder._process_record(record, "req-1", "rh-1", MagicMock())
        table.put_item.assert_not_called()

    def test_dry_run_rollback_eligible_success_still_writes_ir_action_record(self, mock_dredge, monkeypatch):
        # Dry-run stays simulated end-to-end, including the ability to
        # click through IR Actions / Roll back in the UI -- not just
        # skipped silently. rollback_supported still comes out correctly
        # from _build_rollback_kwargs either way (True here, since
        # revoke_active_sessions re-derives its kwargs from
        # detection_event rather than from a rollback_state capture that
        # dry-run mode never performs).
        table = MagicMock()
        monkeypatch.setattr(responder, "_ir_actions_table", table)
        mock_dredge.aws_ir.response.revoke_active_sessions.return_value = OperationResult(
            operation="revoke_active_sessions", target="user=bob", success=True, details={"dry_run": True}
        )
        record = make_record(
            {"response_module": "revoke_active_sessions", "user_name": "bob", "detection_id": "d-1"}
        )
        responder._process_record(record, "req-1", "rh-1", MagicMock())
        table.put_item.assert_called_once()
        item = table.put_item.call_args.kwargs["Item"]
        assert item["rollback_supported"] is True


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

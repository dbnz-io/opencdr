"""Tests for AwsHandler — AWS infrastructure adapter."""
from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

os.environ.setdefault("LOGS_TABLE_NAME", "test-logs-table")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

from src.infra.aws_handler import AwsHandler, _err_code, _is_conditional_failed


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _client_error(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": code}}, "op")


def make_handler() -> AwsHandler:
    logger = MagicMock()
    logger.request_id = "req-test"
    logger.source = "test"
    aws = AwsHandler(logger=logger)
    aws._ddb = MagicMock()
    aws._sqs = MagicMock()
    aws._s3 = MagicMock()
    aws._sns = MagicMock()
    aws._ddb_resource = MagicMock()
    aws._ssm = MagicMock()
    return aws


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


class TestErrCode:
    def test_client_error_returns_code(self):
        e = _client_error("AccessDenied")
        assert _err_code(e) == "AccessDenied"

    def test_generic_exception_returns_class_name(self):
        assert _err_code(ValueError("oops")) == "ValueError"


class TestIsConditionalFailed:
    def test_true_for_conditional_check_failed(self):
        e = _client_error("ConditionalCheckFailedException")
        assert _is_conditional_failed(e)

    def test_false_for_other_client_error(self):
        assert not _is_conditional_failed(_client_error("AccessDenied"))

    def test_false_for_generic_exception(self):
        assert not _is_conditional_failed(RuntimeError("nope"))


# ---------------------------------------------------------------------------
# ddb_put_item
# ---------------------------------------------------------------------------


class TestDdbPutItem:
    def test_success_calls_put_item(self):
        aws = make_handler()
        aws.ddb_put_item(table_name="t", item={"pk": {"S": "1"}})
        aws._ddb.put_item.assert_called_once_with(TableName="t", Item={"pk": {"S": "1"}})

    def test_failure_logs_and_raises(self):
        aws = make_handler()
        aws._ddb.put_item.side_effect = _client_error("ProvisionedThroughputExceededException")
        with pytest.raises(ClientError):
            aws.ddb_put_item(table_name="t", item={})
        aws.logger.error.assert_called_once()


# ---------------------------------------------------------------------------
# ddb_put_item_if_absent
# ---------------------------------------------------------------------------


class TestDdbPutItemIfAbsent:
    def test_success_returns_true(self):
        aws = make_handler()
        assert aws.ddb_put_item_if_absent(
            table_name="t", item={}, id_attribute="pk", id_value="1"
        ) is True

    def test_duplicate_returns_false(self):
        aws = make_handler()
        aws._ddb.put_item.side_effect = _client_error("ConditionalCheckFailedException")
        assert aws.ddb_put_item_if_absent(
            table_name="t", item={}, id_attribute="pk", id_value="1"
        ) is False

    def test_other_error_raises(self):
        aws = make_handler()
        aws._ddb.put_item.side_effect = _client_error("AccessDenied")
        with pytest.raises(ClientError):
            aws.ddb_put_item_if_absent(table_name="t", item={}, id_attribute="pk", id_value="1")


# ---------------------------------------------------------------------------
# ddb_update_item
# ---------------------------------------------------------------------------


class TestDdbUpdateItem:
    def test_success_returns_true(self):
        aws = make_handler()
        result = aws.ddb_update_item(
            table_name="t",
            key={"pk": {"S": "1"}},
            update_expression="SET #s = :v",
            expr_attr_values={":v": {"S": "done"}},
        )
        assert result is True

    def test_condition_not_met_returns_false(self):
        aws = make_handler()
        aws._ddb.update_item.side_effect = _client_error("ConditionalCheckFailedException")
        result = aws.ddb_update_item(
            table_name="t",
            key={},
            update_expression="SET x = :v",
            expr_attr_values={":v": {"S": "x"}},
        )
        assert result is False

    def test_other_error_raises(self):
        aws = make_handler()
        aws._ddb.update_item.side_effect = _client_error("AccessDenied")
        with pytest.raises(ClientError):
            aws.ddb_update_item(
                table_name="t", key={}, update_expression="SET x = :v", expr_attr_values={}
            )

    def test_passes_expr_attr_names_when_provided(self):
        aws = make_handler()
        aws.ddb_update_item(
            table_name="t",
            key={},
            update_expression="SET #n = :v",
            expr_attr_values={":v": {"S": "x"}},
            expr_attr_names={"#n": "name"},
        )
        call_kwargs = aws._ddb.update_item.call_args[1]
        assert call_kwargs["ExpressionAttributeNames"] == {"#n": "name"}


# ---------------------------------------------------------------------------
# ddb_transact_write
# ---------------------------------------------------------------------------


class TestDdbTransactWrite:
    def test_success(self):
        aws = make_handler()
        aws.ddb_transact_write(transact_items=[{"Put": {}}])
        aws._ddb.transact_write_items.assert_called_once()

    def test_failure_raises(self):
        aws = make_handler()
        aws._ddb.transact_write_items.side_effect = _client_error("TransactionCanceledException")
        with pytest.raises(ClientError):
            aws.ddb_transact_write(transact_items=[])
        aws.logger.error.assert_called_once()


# ---------------------------------------------------------------------------
# ddb_get_item_simple
# ---------------------------------------------------------------------------


class TestDdbGetItemSimple:
    def test_returns_item_when_found(self):
        aws = make_handler()
        aws._ddb.get_item.return_value = {"Item": {"pk": {"S": "1"}}}
        result = aws.ddb_get_item_simple(table_name="t", key={"pk": {"S": "1"}})
        assert result == {"pk": {"S": "1"}}

    def test_returns_none_when_not_found(self):
        aws = make_handler()
        aws._ddb.get_item.return_value = {}
        result = aws.ddb_get_item_simple(table_name="t", key={"pk": {"S": "1"}})
        assert result is None

    def test_returns_none_for_empty_table_name(self):
        aws = make_handler()
        result = aws.ddb_get_item_simple(table_name="", key={"pk": {"S": "1"}})
        assert result is None
        aws._ddb.get_item.assert_not_called()


# ---------------------------------------------------------------------------
# sqs_send
# ---------------------------------------------------------------------------


class TestSqsSend:
    def test_success_returns_message_id(self):
        aws = make_handler()
        aws._sqs.send_message.return_value = {"MessageId": "msg-001"}
        msg_id = aws.sqs_send(queue_url="https://sqs/q", body={"key": "val"})
        assert msg_id == "msg-001"

    def test_failure_raises(self):
        aws = make_handler()
        aws._sqs.send_message.side_effect = _client_error("AccessDenied")
        with pytest.raises(ClientError):
            aws.sqs_send(queue_url="https://sqs/q", body={})
        aws.logger.error.assert_called_once()

    def test_passes_custom_attributes(self):
        aws = make_handler()
        aws._sqs.send_message.return_value = {"MessageId": "x"}
        aws.sqs_send(queue_url="q", body={}, attributes={"env": "test"})
        call_kwargs = aws._sqs.send_message.call_args[1]
        assert call_kwargs["MessageAttributes"]["env"]["StringValue"] == "test"


# ---------------------------------------------------------------------------
# s3_put_json
# ---------------------------------------------------------------------------


class TestS3PutJson:
    def test_success_calls_put_object(self):
        aws = make_handler()
        aws.s3_put_json(bucket="b", key="k", payload={"x": 1})
        aws._s3.put_object.assert_called_once()
        call_kwargs = aws._s3.put_object.call_args[1]
        assert call_kwargs["Bucket"] == "b"
        assert call_kwargs["Key"] == "k"
        assert call_kwargs["ContentType"] == "application/json"

    def test_failure_raises(self):
        aws = make_handler()
        aws._s3.put_object.side_effect = _client_error("NoSuchBucket")
        with pytest.raises(ClientError):
            aws.s3_put_json(bucket="b", key="k", payload={})
        aws.logger.error.assert_called_once()


# ---------------------------------------------------------------------------
# put_outbox_record
# ---------------------------------------------------------------------------


class TestPutOutboxRecord:
    def test_creates_record_and_returns_id(self):
        aws = make_handler()
        outbox_id = aws.put_outbox_record(
            table_name="t",
            payload={"alert_id": "a1"},
            destinations=["notifications"],
        )
        assert isinstance(outbox_id, str)
        aws._ddb.put_item.assert_called_once()

    def test_uses_provided_outbox_id(self):
        aws = make_handler()
        result = aws.put_outbox_record(
            table_name="t",
            payload={},
            destinations=[],
            outbox_id="custom-id",
        )
        assert result == "custom-id"


# ---------------------------------------------------------------------------
# ssm_get_secure_param
# ---------------------------------------------------------------------------


class TestSsmGetSecureParam:
    def test_returns_decrypted_value(self):
        aws = make_handler()
        aws._ssm.get_parameter.return_value = {"Parameter": {"Value": "secret-value"}}
        result = aws.ssm_get_secure_param(name="/opencdr-dev/settings/global/slack/webhook_url")
        assert result == "secret-value"
        aws._ssm.get_parameter.assert_called_once_with(
            Name="/opencdr-dev/settings/global/slack/webhook_url", WithDecryption=True
        )

    def test_missing_parameter_returns_none(self):
        aws = make_handler()
        aws._ssm.get_parameter.side_effect = _client_error("ParameterNotFound")
        assert aws.ssm_get_secure_param(name="/does/not/exist") is None

    def test_other_error_raises(self):
        aws = make_handler()
        aws._ssm.get_parameter.side_effect = _client_error("AccessDenied")
        with pytest.raises(ClientError):
            aws.ssm_get_secure_param(name="/opencdr-dev/settings/global/slack/webhook_url")


# ---------------------------------------------------------------------------
# ddb_put_item_if_absent_resource
# ---------------------------------------------------------------------------


class TestDdbPutItemIfAbsentResource:
    def test_success_returns_true(self):
        aws = make_handler()
        table_mock = MagicMock()
        aws._ddb_resource.Table.return_value = table_mock
        result = aws.ddb_put_item_if_absent_resource(
            table_name="t", item={"pk": "1"}, id_attribute="pk", id_value="1"
        )
        assert result is True
        table_mock.put_item.assert_called_once()

    def test_duplicate_returns_false(self):
        aws = make_handler()
        table_mock = MagicMock()
        table_mock.put_item.side_effect = _client_error("ConditionalCheckFailedException")
        aws._ddb_resource.Table.return_value = table_mock
        result = aws.ddb_put_item_if_absent_resource(
            table_name="t", item={}, id_attribute="pk", id_value="1"
        )
        assert result is False

    def test_other_error_raises(self):
        aws = make_handler()
        table_mock = MagicMock()
        table_mock.put_item.side_effect = _client_error("AccessDenied")
        aws._ddb_resource.Table.return_value = table_mock
        with pytest.raises(ClientError):
            aws.ddb_put_item_if_absent_resource(
                table_name="t", item={}, id_attribute="pk", id_value="1"
            )

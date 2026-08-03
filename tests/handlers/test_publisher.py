"""Tests for the outbox publisher handler (drains outbox table -> SQS)."""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

import os

os.environ.setdefault("LOGS_TABLE_NAME", "test-logs-table")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

from src.handlers.publisher import (
    OutboxPublisher,
    _dynamodb_unmarshal_image,
    _err_code,
    lambda_handler,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _client_error(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": code}}, "update_item")


def make_cfg(**overrides):
    base = {
        "service": "OPENCDR",
        "stage": "test",
        "region": "us-east-1",
        "lambda_name": "test-publisher",
        "logs_table_name": "test-logs-table",
        "outbox_table_name": "test-outbox-table",
        "notifications_queue_url": "https://sqs.us-east-1.amazonaws.com/1/notifications",
        "responses_queue_url": "https://sqs.us-east-1.amazonaws.com/1/responses",
    }
    base.update(overrides)
    return type("Cfg", (), base)()


def make_publisher(aws=None, logger=None) -> OutboxPublisher:
    with patch("src.handlers.publisher.boto3.resource") as mock_resource:
        mock_table = MagicMock()
        mock_resource.return_value.Table.return_value = mock_table
        pub = OutboxPublisher(
            logger=logger or MagicMock(),
            aws=aws or MagicMock(),
            outbox_table_name="test-outbox-table",
        )
    pub.outbox_table = mock_table
    return pub


def ddb_string_image(**fields) -> dict:
    return {k: {"S": v} for k, v in fields.items()}


def make_stream_record(event_name="INSERT", new_image=None) -> dict:
    rec = {"eventName": event_name}
    if new_image is not None:
        rec["dynamodb"] = {"NewImage": new_image}
    return rec


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


class TestErrCode:
    def test_client_error_returns_code(self):
        assert _err_code(_client_error("ConditionalCheckFailedException")) == "ConditionalCheckFailedException"

    def test_generic_exception_returns_class_name(self):
        assert _err_code(ValueError("x")) == "ValueError"


class TestUnmarshal:
    def test_deserializes_ddb_typed_image(self):
        image = ddb_string_image(outbox_id="ob-1", status="PENDING")
        assert _dynamodb_unmarshal_image(image) == {"outbox_id": "ob-1", "status": "PENDING"}


# ---------------------------------------------------------------------------
# _queue_url_for_destination
# ---------------------------------------------------------------------------


class TestQueueUrlForDestination:
    def test_notifications_variants_case_insensitive(self):
        pub = make_publisher()
        cfg = make_cfg()
        for variant in ("notifications", "NOTIFICATIONS", "Notification", " notifications "):
            assert pub._queue_url_for_destination(destination=variant, cfg=cfg) == cfg.notifications_queue_url

    def test_responses_variants(self):
        pub = make_publisher()
        cfg = make_cfg()
        for variant in ("responses", "RESPONSE", "Responses"):
            assert pub._queue_url_for_destination(destination=variant, cfg=cfg) == cfg.responses_queue_url

    def test_missing_notifications_url_raises_runtime_error(self):
        pub = make_publisher()
        cfg = make_cfg(notifications_queue_url="")
        with pytest.raises(RuntimeError):
            pub._queue_url_for_destination(destination="notifications", cfg=cfg)

    def test_unknown_destination_raises_value_error(self):
        pub = make_publisher()
        with pytest.raises(ValueError):
            pub._queue_url_for_destination(destination="carrier-pigeon", cfg=make_cfg())


# ---------------------------------------------------------------------------
# _claim_outbox
# ---------------------------------------------------------------------------


class TestClaimOutbox:
    def test_success_returns_true(self):
        pub = make_publisher()
        assert pub._claim_outbox(outbox_id="ob-1") is True
        pub.outbox_table.update_item.assert_called_once()
        _, kwargs = pub.outbox_table.update_item.call_args
        assert kwargs["Key"] == {"outbox_id": "ob-1"}
        assert kwargs["ConditionExpression"] == "#s = :pending"

    def test_conditional_check_failed_returns_false(self):
        pub = make_publisher()
        pub.outbox_table.update_item.side_effect = _client_error("ConditionalCheckFailedException")
        assert pub._claim_outbox(outbox_id="ob-1") is False

    def test_other_client_error_propagates(self):
        pub = make_publisher()
        pub.outbox_table.update_item.side_effect = _client_error("ProvisionedThroughputExceededException")
        with pytest.raises(ClientError):
            pub._claim_outbox(outbox_id="ob-1")


# ---------------------------------------------------------------------------
# _mark_sent / _mark_failed
# ---------------------------------------------------------------------------


class TestMarkSentAndFailed:
    def test_mark_sent_sets_status_and_message_id(self):
        pub = make_publisher()
        pub._mark_sent(outbox_id="ob-1", sqs_message_id="msg-123")
        _, kwargs = pub.outbox_table.update_item.call_args
        assert kwargs["ExpressionAttributeValues"][":sent"] == "SENT"
        assert kwargs["ExpressionAttributeValues"][":m"] == "msg-123"

    def test_mark_failed_sets_status_and_truncates_message(self):
        pub = make_publisher()
        pub._mark_failed(outbox_id="ob-1", error_code="Boom", error_message="x" * 3000)
        _, kwargs = pub.outbox_table.update_item.call_args
        err = kwargs["ExpressionAttributeValues"][":e"]
        assert err["code"] == "Boom"
        assert len(err["message"]) == 2000


# ---------------------------------------------------------------------------
# _load_payload
# ---------------------------------------------------------------------------


class TestLoadPayload:
    def test_dict_payload_passthrough(self):
        pub = make_publisher()
        assert pub._load_payload({"payload": {"a": 1}}) == {"a": 1}

    def test_json_string_payload_parsed(self):
        pub = make_publisher()
        assert pub._load_payload({"payload": json.dumps({"a": 1})}) == {"a": 1}

    def test_s3_pointer_payload_is_real_and_fetched(self):
        """Confirms the S3-pointer fallback path is live code, not dead/aspirational."""
        pub = make_publisher()
        item = {"payload_s3_bucket": "bkt", "payload_s3_key": "k.json"}
        body_mock = MagicMock()
        body_mock.read.return_value = json.dumps({"from": "s3"}).encode("utf-8")
        s3_mock = MagicMock()
        s3_mock.get_object.return_value = {"Body": body_mock}
        with patch("src.handlers.publisher.boto3.client", return_value=s3_mock) as mock_client:
            result = pub._load_payload(item)
        mock_client.assert_called_once_with("s3")
        s3_mock.get_object.assert_called_once_with(Bucket="bkt", Key="k.json")
        assert result == {"from": "s3"}

    def test_invalid_json_string_with_no_s3_pointer_raises(self):
        pub = make_publisher()
        with pytest.raises(ValueError):
            pub._load_payload({"payload": "{not json"})

    def test_missing_payload_and_pointer_raises(self):
        pub = make_publisher()
        with pytest.raises(ValueError):
            pub._load_payload({})


# ---------------------------------------------------------------------------
# _extract_destinations
# ---------------------------------------------------------------------------


class TestExtractDestinations:
    def test_singular_destination_string(self):
        pub = make_publisher()
        assert pub._extract_destinations({"destination": "notifications"}) == ["notifications"]

    def test_destinations_list(self):
        pub = make_publisher()
        assert pub._extract_destinations({"destinations": ["notifications", "responses"]}) == [
            "notifications",
            "responses",
        ]

    def test_destinations_json_encoded_string(self):
        pub = make_publisher()
        raw = json.dumps(["notifications", "responses"])
        assert pub._extract_destinations({"destinations": raw}) == ["notifications", "responses"]

    def test_destinations_non_json_string_falls_back_to_single_item(self):
        pub = make_publisher()
        assert pub._extract_destinations({"destinations": "notifications"}) == ["notifications"]

    def test_missing_destinations_returns_empty(self):
        pub = make_publisher()
        assert pub._extract_destinations({}) == []


# ---------------------------------------------------------------------------
# process_record
# ---------------------------------------------------------------------------


class TestProcessRecordSkipPaths:
    def test_ignores_remove_event(self):
        pub = make_publisher()
        pub.process_record(record=make_stream_record(event_name="REMOVE"), cfg=make_cfg())
        pub.outbox_table.update_item.assert_not_called()

    def test_ignores_record_with_no_new_image(self):
        pub = make_publisher()
        pub.process_record(record=make_stream_record(new_image=None), cfg=make_cfg())
        pub.outbox_table.update_item.assert_not_called()

    def test_ignores_non_pending_status(self):
        pub = make_publisher()
        image = ddb_string_image(outbox_id="ob-1", status="SENT")
        pub.process_record(record=make_stream_record(new_image=image), cfg=make_cfg())
        pub.outbox_table.update_item.assert_not_called()

    def test_missing_outbox_id_logs_error_and_returns(self):
        logger = MagicMock()
        pub = make_publisher(logger=logger)
        image = ddb_string_image(status="PENDING")
        pub.process_record(record=make_stream_record(new_image=image), cfg=make_cfg())
        pub.outbox_table.update_item.assert_not_called()
        logger.error.assert_called_once()
        assert logger.error.call_args.kwargs["event_name"] == "OUTBOX_RECORD_MISSING_ID"

    def test_already_claimed_skips_publish_cleanly(self):
        logger = MagicMock()
        aws = MagicMock()
        pub = make_publisher(aws=aws, logger=logger)
        pub.outbox_table.update_item.side_effect = _client_error("ConditionalCheckFailedException")
        image = ddb_string_image(outbox_id="ob-1", status="PENDING")
        pub.process_record(record=make_stream_record(new_image=image), cfg=make_cfg())
        aws.sqs_send.assert_not_called()
        assert logger.info.call_args.kwargs["event_name"] == "OUTBOX_ALREADY_CLAIMED"

    def test_unexpected_claim_error_propagates_uncaught(self):
        """Documents current behavior: a non-conditional ClientError from the claim
        step happens before the try/except in process_record, so it is NOT marked
        FAILED — it propagates straight out."""
        pub = make_publisher()
        pub.outbox_table.update_item.side_effect = _client_error("ProvisionedThroughputExceededException")
        image = ddb_string_image(outbox_id="ob-1", status="PENDING")
        with pytest.raises(ClientError):
            pub.process_record(record=make_stream_record(new_image=image), cfg=make_cfg())


class TestProcessRecordPublishSuccess:
    def test_single_destination_published_and_marked_sent(self):
        aws = MagicMock()
        aws.sqs_send.return_value = "msg-1"
        pub = make_publisher(aws=aws)
        image = ddb_string_image(outbox_id="ob-1", status="PENDING", destination="notifications")
        image["payload"] = {"M": {"a": {"S": "b"}}}
        pub.process_record(record=make_stream_record(new_image=image), cfg=make_cfg())

        aws.sqs_send.assert_called_once()
        assert aws.sqs_send.call_args.kwargs["queue_url"] == make_cfg().notifications_queue_url
        # second update_item call is the SENT mark (first was the claim)
        assert pub.outbox_table.update_item.call_count == 2
        sent_kwargs = pub.outbox_table.update_item.call_args_list[1].kwargs
        assert sent_kwargs["ExpressionAttributeValues"][":sent"] == "SENT"

    def test_multiple_destinations_all_published_last_msg_id_recorded(self):
        aws = MagicMock()
        aws.sqs_send.side_effect = ["msg-1", "msg-2"]
        pub = make_publisher(aws=aws)
        image = ddb_string_image(outbox_id="ob-1", status="PENDING")
        image["destinations"] = {"L": [{"S": "notifications"}, {"S": "responses"}]}
        image["payload"] = {"M": {}}
        pub.process_record(record=make_stream_record(new_image=image), cfg=make_cfg())

        assert aws.sqs_send.call_count == 2
        sent_kwargs = pub.outbox_table.update_item.call_args_list[1].kwargs
        assert sent_kwargs["ExpressionAttributeValues"][":m"] == "msg-2"

    def test_optional_sqs_attributes_forwarded(self):
        aws = MagicMock()
        aws.sqs_send.return_value = "msg-1"
        pub = make_publisher(aws=aws)
        image = ddb_string_image(
            outbox_id="ob-1", status="PENDING", destination="notifications",
            signal_id="sig-1", rule_id="rule-1",
        )
        image["payload"] = {"M": {}}
        pub.process_record(record=make_stream_record(new_image=image), cfg=make_cfg())
        assert aws.sqs_send.call_args.kwargs["attributes"] == {"signal_id": "sig-1", "rule_id": "rule-1"}


class TestProcessRecordPublishFailure:
    def test_no_destinations_resets_to_pending_for_retry_and_reraises(self):
        """Fixed: on the first failure (attempts=1, under
        PUBLISHER_MAX_ATTEMPTS), the record is reset to PENDING instead of
        FAILED, so it's retried via the outbox table's own stream rather
        than stuck forever. See TestBoundedRetry for the exhausted-attempts
        case."""
        pub = make_publisher()
        image = ddb_string_image(outbox_id="ob-1", status="PENDING")
        image["payload"] = {"M": {}}
        with pytest.raises(ValueError):
            pub.process_record(record=make_stream_record(new_image=image), cfg=make_cfg())
        retry_kwargs = pub.outbox_table.update_item.call_args_list[1].kwargs
        assert retry_kwargs["ExpressionAttributeValues"][":pending"] == "PENDING"

    def test_bad_payload_resets_to_pending_for_retry_and_reraises(self):
        pub = make_publisher()
        image = ddb_string_image(
            outbox_id="ob-1", status="PENDING", destination="notifications", payload="{not json",
        )
        with pytest.raises(ValueError):
            pub.process_record(record=make_stream_record(new_image=image), cfg=make_cfg())
        retry_kwargs = pub.outbox_table.update_item.call_args_list[1].kwargs
        assert retry_kwargs["ExpressionAttributeValues"][":pending"] == "PENDING"

    def test_second_destination_failure_preserves_first_as_sent_and_retries(self):
        """Fixed: if destination 1 of 2 succeeds and destination 2 raises,
        destination 1 is recorded in sent_destinations (so a retry won't
        re-publish to it) and the record goes to PENDING for retry rather
        than a terminal FAILED that loses track of what already sent."""
        aws = MagicMock()
        aws.sqs_send.side_effect = ["msg-1", RuntimeError("sqs down")]
        pub = make_publisher(aws=aws)
        image = ddb_string_image(outbox_id="ob-1", status="PENDING")
        image["destinations"] = {"L": [{"S": "notifications"}, {"S": "responses"}]}
        image["payload"] = {"M": {}}
        with pytest.raises(RuntimeError):
            pub.process_record(record=make_stream_record(new_image=image), cfg=make_cfg())

        assert aws.sqs_send.call_count == 2  # first destination WAS published
        retry_kwargs = pub.outbox_table.update_item.call_args_list[1].kwargs
        assert retry_kwargs["ExpressionAttributeValues"][":pending"] == "PENDING"
        assert retry_kwargs["ExpressionAttributeValues"][":sd"] == ["notifications"]

    def test_retry_skips_already_sent_destination(self):
        """A second processing attempt (simulating the retry triggered by
        the PENDING reset above) must not re-publish to "notifications",
        which sent_destinations already marks as sent."""
        aws = MagicMock()
        aws.sqs_send.return_value = "msg-2"
        pub = make_publisher(aws=aws)
        image = ddb_string_image(outbox_id="ob-1", status="PENDING")
        image["attempts"] = {"N": "1"}
        image["destinations"] = {"L": [{"S": "notifications"}, {"S": "responses"}]}
        image["sent_destinations"] = {"L": [{"S": "notifications"}]}
        image["payload"] = {"M": {}}

        pub.process_record(record=make_stream_record(new_image=image), cfg=make_cfg())

        aws.sqs_send.assert_called_once()
        assert aws.sqs_send.call_args.kwargs["queue_url"] == make_cfg().responses_queue_url
        sent_kwargs = pub.outbox_table.update_item.call_args_list[1].kwargs
        assert set(sent_kwargs["ExpressionAttributeValues"][":sd"]) == {"notifications", "responses"}


class TestBoundedRetry:
    def test_marks_terminally_failed_once_max_attempts_reached(self):
        pub = make_publisher()
        image = ddb_string_image(outbox_id="ob-1", status="PENDING")
        image["attempts"] = {"N": "4"}
        image["payload"] = {"M": {}}
        with pytest.raises(ValueError):
            pub.process_record(record=make_stream_record(new_image=image), cfg=make_cfg())
        failed_kwargs = pub.outbox_table.update_item.call_args_list[1].kwargs
        assert failed_kwargs["ExpressionAttributeValues"][":failed"] == "FAILED"

    def test_still_retries_one_attempt_below_max(self):
        pub = make_publisher()
        image = ddb_string_image(outbox_id="ob-1", status="PENDING")
        image["attempts"] = {"N": "3"}
        image["payload"] = {"M": {}}
        with pytest.raises(ValueError):
            pub.process_record(record=make_stream_record(new_image=image), cfg=make_cfg())
        retry_kwargs = pub.outbox_table.update_item.call_args_list[1].kwargs
        assert retry_kwargs["ExpressionAttributeValues"][":pending"] == "PENDING"


# ---------------------------------------------------------------------------
# lambda_handler
# ---------------------------------------------------------------------------


class TestLambdaHandler:
    def test_processes_each_record_and_returns_count(self):
        fake_cfg = make_cfg()
        with patch("src.handlers.publisher.load_publisher_config", return_value=fake_cfg), \
             patch("src.handlers.publisher.AwsHandler"), \
             patch("src.handlers.publisher.OutboxPublisher") as mock_publisher_cls:
            mock_publisher = MagicMock()
            mock_publisher_cls.return_value = mock_publisher

            event = {"Records": [{"eventName": "INSERT"}, {"eventName": "MODIFY"}]}
            ctx = MagicMock()
            ctx.aws_request_id = "test-req-id"
            result = lambda_handler(event, context=ctx)

            assert mock_publisher.process_record.call_count == 2
            assert result == {"ok": True, "records": 2}

    def test_exception_in_one_record_aborts_remaining_records_in_batch(self):
        """Documents current behavior: lambda_handler has no try/except around its
        per-record loop, so an exception raised by process_record for record N
        propagates out of lambda_handler immediately — records after N in the same
        batch are never attempted."""
        fake_cfg = make_cfg()
        with patch("src.handlers.publisher.load_publisher_config", return_value=fake_cfg), \
             patch("src.handlers.publisher.AwsHandler"), \
             patch("src.handlers.publisher.OutboxPublisher") as mock_publisher_cls:
            mock_publisher = MagicMock()
            mock_publisher.process_record.side_effect = [RuntimeError("boom"), None]
            mock_publisher_cls.return_value = mock_publisher

            event = {"Records": [{"eventName": "INSERT"}, {"eventName": "INSERT"}]}
            ctx = MagicMock()
            ctx.aws_request_id = "test-req-id"
            with pytest.raises(RuntimeError):
                lambda_handler(event, context=ctx)

            assert mock_publisher.process_record.call_count == 1

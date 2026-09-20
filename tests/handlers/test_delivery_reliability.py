"""Failure-boundary regressions for durable alert and notification delivery."""
import json
from copy import deepcopy
from unittest.mock import MagicMock

import pytest
from boto3.dynamodb.types import TypeSerializer
from botocore.exceptions import ClientError

from src.handlers import alerter, api, notifier, processor, publisher, responder
from src.infra.aws_handler import AwsHandler
from src.infra.delivery_state import AlreadyDelivered, DeliveryBusy, DeliveryState, delivery_id
from tests.handlers.test_alerter import make_alert, make_signal, make_stream_record
from tests.handlers.test_notifier_webhook import make_settings_webhook
from tests.handlers.test_processor import make_cloudtrail_event, make_signal_rule
from tests.handlers.test_publisher import make_cfg, make_publisher


def conditional_error(operation="PutItem"):
    return ClientError({"Error": {"Code": "ConditionalCheckFailedException", "Message": "conflict"}}, operation)


class ReceiptTable:
    """In-memory claim store; models conditional ownership and expiry for crash tests."""
    def __init__(self):
        self.items = {}

    def put_item(self, *, Item, ConditionExpression, **kwargs):
        key = Item["delivery_key"]
        old = self.items.get(key)
        values = kwargs.get("ExpressionAttributeValues", {})
        if old and not (":now" in values and old["status"] == "IN_FLIGHT"
                        and old["lease_until"] < values[":now"]):
            raise conditional_error()
        self.items[key] = deepcopy(Item)

    def get_item(self, *, Key, ConsistentRead):
        assert ConsistentRead is True
        return {"Item": deepcopy(self.items.get(Key["delivery_key"], {}))}

    def update_item(self, *, Key, ExpressionAttributeValues, **kwargs):
        item = self.items[Key["delivery_key"]]
        if item["token"] != ExpressionAttributeValues[":token"]:
            raise conditional_error("UpdateItem")
        item["status"] = ExpressionAttributeValues[":done"]

    def delete_item(self, *, Key, ExpressionAttributeValues, **kwargs):
        if self.items[Key["delivery_key"]]["token"] != ExpressionAttributeValues[":token"]:
            raise conditional_error("DeleteItem")
        del self.items[Key["delivery_key"]]


@pytest.fixture
def receipts(monkeypatch):
    state = DeliveryState()
    state.table = ReceiptTable()
    monkeypatch.setattr(notifier, "DeliveryState", lambda: state)
    monkeypatch.setattr(responder, "DeliveryState", lambda: state)
    return state


def test_conflicting_settings_write_cannot_change_live_secret(monkeypatch):
    legacy = "/opencdr-dev/settings/global/slack/webhook_url"
    secrets = {legacy: "old-secret"}
    ssm = MagicMock()
    def put(**kw):
        assert kw["Overwrite"] is False
        assert kw["Name"] not in secrets
        secrets[kw["Name"]] = kw["Value"]
    ssm.put_parameter.side_effect = put
    monkeypatch.setattr(api, "ssm", ssm)
    table = MagicMock()
    table.put_item.side_effect = conditional_error()
    monkeypatch.setattr(api, "settings_table", table)
    body = {"expected_rev": 1, "channels": {"slack": {"webhook_url": "new-secret"}}}
    response = api._handle_upsert_settings("global", body)
    assert response["statusCode"] == 409
    assert secrets[legacy] == "old-secret"
    assert body["channels"]["slack"]["webhook_url"] == "new-secret"
    new_reference = table.put_item.call_args.kwargs["Item"]["channels"]["slack"]["webhook_url"]
    assert secrets[new_reference.removeprefix("ssm:")] == "new-secret"


def test_each_secret_write_gets_an_immutable_reference(monkeypatch):
    ssm = MagicMock()
    monkeypatch.setattr(api, "ssm", ssm)
    first = api._normalize_settings_payload({"channels": {"jira": {"api_token": "a"}}}, setting_id="global")
    second = api._normalize_settings_payload({"channels": {"jira": {"api_token": "b"}}}, setting_id="global")
    assert first["channels"]["jira"]["api_token"] != second["channels"]["jira"]["api_token"]


def test_float_raw_event_survives_processor_alert_write(monkeypatch):
    aws = AwsHandler(logger=MagicMock())
    aws.sqs_send = MagicMock()
    aws.put_outbox_record = MagicMock()
    table = MagicMock()
    # Exercise the real high-level storage boundary with boto3's serializer.
    table.put_item.side_effect = lambda **kw: TypeSerializer().serialize(kw["Item"])
    aws._ddb_resource = MagicMock()
    aws._ddb_resource.Table.return_value = table
    monkeypatch.setattr(processor, "AwsHandler", lambda **kw: aws)
    monkeypatch.setattr(processor, "Logger", MagicMock())
    monkeypatch.setattr(processor, "get_rules", lambda *a: [make_signal_rule()])
    monkeypatch.setattr(processor, "get_lists", lambda *a: {})
    monkeypatch.setattr(processor, "ALERTS_TABLE_NAME", "alerts")
    monkeypatch.setattr(processor, "OUTBOX_TABLE_NAME", "outbox")
    result = processor.lambda_handler(make_cloudtrail_event(severity=8.5), None)
    assert result["stored"] == 1
    aws.put_outbox_record.assert_called_once()
    stored = table.put_item.call_args.kwargs["Item"]
    assert str(stored["raw_event"]["detail"]["severity"]) == "8.5"


def test_correlation_transaction_failure_retries_whole_delivery(monkeypatch):
    aws = AwsHandler(logger=MagicMock())
    aws._ddb = MagicMock()
    aws._ddb.transact_write_items.side_effect = [RuntimeError("temporary outage"), {}]
    monkeypatch.setattr(alerter, "AwsHandler", lambda **kw: aws)
    monkeypatch.setattr(alerter, "Logger", MagicMock())
    monkeypatch.setattr(alerter, "ALERTS_TABLE_NAME", "alerts")
    monkeypatch.setattr(alerter, "OUTBOX_TABLE_NAME", "outbox")
    monkeypatch.setattr(alerter, "SIGNALS_TABLE_NAME", "signals")
    monkeypatch.setattr(alerter, "get_correlation_rules", lambda **kw: [{}])
    engine = MagicMock()
    engine.correlate.return_value = [make_alert()]
    monkeypatch.setattr(alerter, "CorrelationEngine", lambda **kw: engine)
    event = {"Records": [make_stream_record(make_signal())]}
    with pytest.raises(RuntimeError):
        alerter.lambda_handler(event, None)
    assert alerter.lambda_handler(event, None)["outboxed"] == 1
    assert aws._ddb.transact_write_items.call_count == 2
    writes = aws._ddb.transact_write_items.call_args.kwargs["TransactItems"]
    assert [w["Put"]["TableName"] for w in writes] == ["alerts", "outbox"]
    assert json.loads(writes[1]["Put"]["Item"]["destinations"]["S"]) == ["signals", "notifications", "responses"]


def test_transaction_only_treats_conditional_cancellation_as_duplicate():
    aws = AwsHandler(logger=MagicMock())
    aws._ddb = MagicMock()
    args = dict(alerts_table="alerts", outbox_table="outbox", alert_item=make_alert(),
                payload=make_alert(), destinations=["notifications"])
    for code, expected in [("ConditionalCheckFailed", False), ("TransactionConflict", None)]:
        aws._ddb.transact_write_items.side_effect = ClientError({
            "Error": {"Code": "TransactionCanceledException", "Message": "cancelled"},
            "CancellationReasons": [{"Code": code}, {"Code": "None"}],
        }, "TransactWriteItems")
        if expected is False:
            assert aws.put_alert_with_outbox(**args) is False
        else:
            with pytest.raises(ClientError):
                aws.put_alert_with_outbox(**args)


def test_only_failed_webhook_target_is_retried(monkeypatch, receipts):
    settings = make_settings_webhook(targets=[{"name": "one", "url": "https://one.example"},
                                               {"name": "two", "url": "https://two.example"}])
    monkeypatch.setattr(notifier, "load_global_settings", lambda **kw: settings)
    monkeypatch.setattr(notifier, "Logger", MagicMock())
    post = MagicMock(side_effect=[(200, "ok"), TimeoutError(), (200, "ok")])
    monkeypatch.setattr(notifier, "_post_json", post)
    event = {"Records": [{"messageId": "m1", "body": json.dumps(make_alert())}]}
    first = notifier.lambda_handler(event, None)
    assert first["batchItemFailures"] == [{"itemIdentifier": "m1"}]
    second = notifier.lambda_handler(event, None)
    assert second["batchItemFailures"] == []
    assert [c.args[0] for c in post.call_args_list] == ["https://one.example", "https://two.example", "https://two.example"]


def test_completed_channel_not_repeated_when_sibling_fails(monkeypatch, receipts):
    settings = {"notifications_enabled": True, "channels": {
        "slack": {"enabled": True, "webhook_url": "https://slack.example"},
        "discord": {"enabled": True, "webhook_url": "https://discord.example"}},
        "routing": {"CRITICAL": ["slack", "discord"]}}
    monkeypatch.setattr(notifier, "load_global_settings", lambda **kw: settings)
    monkeypatch.setattr(notifier, "Logger", MagicMock())
    post = MagicMock(side_effect=[(200, "ok"), TimeoutError(), (200, "ok")])
    monkeypatch.setattr(notifier, "_post_json", post)
    event = {"Records": [{"messageId": "m", "body": json.dumps(make_alert())}]}
    assert notifier.lambda_handler(event, None)["batchItemFailures"]
    assert not notifier.lambda_handler(event, None)["batchItemFailures"]
    assert [c.args[0] for c in post.call_args_list] == ["https://slack.example", "https://discord.example", "https://discord.example"]


def test_ir_uncertain_outcome_never_reclaims_expired_claim(receipts):
    class ProcessCrash(BaseException):
        pass
    with pytest.raises(ProcessCrash), receipts.delivery("alert", "response:delete_user", replay=False):
        raise ProcessCrash()
    stored = next(iter(receipts.table.items.values()))
    stored["lease_until"] = 0
    assert "expires_at" not in stored
    with pytest.raises(DeliveryBusy), receipts.delivery("alert", "response:delete_user", replay=False):
        pytest.fail("Destructive action replayed")


def test_completed_delivery_skips_and_active_lease_blocks(receipts):
    with receipts.delivery("alert", "slack"):
        with pytest.raises(DeliveryBusy), receipts.delivery("alert", "slack"):
            pytest.fail("Concurrent send")
    with pytest.raises(AlreadyDelivered), receipts.delivery("alert", "slack"):
        pytest.fail("Duplicate send")


def test_publisher_reads_current_claim_state_and_checkpoints_each_destination():
    pub = make_publisher()
    pub.outbox_table.update_item.return_value = {"Attributes": {
        "outbox_id": "o", "status": "IN_FLIGHT", "attempts": 2,
        "payload": {}, "destinations": ["notifications", "responses"],
        "sent_destinations": ["notifications"],
    }}
    stale = {"outbox_id": "o", "status": "PENDING", "attempts": 0,
             "payload": {}, "destinations": ["notifications", "responses"]}
    pub.process_record(record=make_stream_record(stale), cfg=make_cfg())
    pub.aws.sqs_send.assert_called_once()
    assert pub.aws.sqs_send.call_args.kwargs["queue_url"] == make_cfg().responses_queue_url
    assert pub.aws.sqs_send.call_args.kwargs["attributes"]["delivery_id"] == "o"
    updates = pub.outbox_table.update_item.call_args_list
    assert updates[0].kwargs["ReturnValues"] == "ALL_NEW"
    assert updates[1].kwargs["ExpressionAttributeValues"][":sd"] == ["notifications", "responses"]
    assert updates[1].kwargs["ConditionExpression"] == "claim_token = :token"


def test_recovery_requeues_expired_claims_and_stops_unsafe_legacy_replays():
    pub = make_publisher()
    pub.outbox_table.query.side_effect = [{"Items": [
        {"outbox_id": "fresh-code", "attempts": 1, "claim_token": "old"},
        {"outbox_id": "legacy", "attempts": 1},
        {"outbox_id": "exhausted", "attempts": publisher.PUBLISHER_MAX_ATTEMPTS, "claim_token": "old"},
    ]}, {"Items": []}]
    assert pub.recover_abandoned() == 3
    updates = pub.outbox_table.update_item.call_args_list
    assert [c.kwargs["ExpressionAttributeValues"][":next"] for c in updates] == ["PENDING", "FAILED", "FAILED"]
    assert all("updated_at <= :cutoff" in c.kwargs["ConditionExpression"] for c in updates)
    assert all("REMOVE claim_token" in c.kwargs["UpdateExpression"] for c in updates)


def test_publisher_routes_correlation_writeback_with_loop_guard(monkeypatch):
    monkeypatch.setenv("SIGNALS_WRITE_QUEUE_URL", "signals-queue")
    pub = make_publisher()
    item = {"outbox_id": "o", "status": "PENDING", "attempts": 1,
            "payload": make_alert(), "destinations": ["signals"]}
    pub.outbox_table.update_item.return_value = {"Attributes": item}
    pub.process_record(record=make_stream_record(item), cfg=make_cfg())
    sent = pub.aws.sqs_send.call_args.kwargs
    assert sent["queue_url"] == "signals-queue"
    assert sent["body"]["item_type"] == "correlation"
    assert sent["body"]["detection_id"] == make_alert()["alert_id"]


def test_republished_message_keeps_consumer_identity():
    item = {"alert_id": "a"}
    attrs = {"delivery_id": {"stringValue": "outbox-1"}}
    assert delivery_id({"messageId": "first", "messageAttributes": attrs}, item) == delivery_id(
        {"messageId": "second", "messageAttributes": attrs}, item)


def test_outbox_key_deduplicates_alerts_with_different_timestamp_sort_keys():
    aws = AwsHandler(logger=MagicMock())
    aws._ddb = MagicMock()
    aws._ddb.transact_write_items.side_effect = ClientError({
        "Error": {"Code": "TransactionCanceledException", "Message": "duplicate outbox"},
        "CancellationReasons": [{"Code": "None"}, {"Code": "ConditionalCheckFailed"}],
    }, "TransactWriteItems")
    assert aws.put_alert_with_outbox(alerts_table="alerts", outbox_table="outbox",
        alert_item=make_alert(timestamp="2026-09-16T00:01:00Z"), payload=make_alert(),
        destinations=["notifications"]) is False


def test_responder_executes_republished_action_only_once(monkeypatch, receipts):
    from tests.handlers.test_responder import ok_result
    handler = MagicMock(return_value=ok_result())
    monkeypatch.setitem(responder.RESPONSE_MODULE_HANDLERS, "test_action", handler)
    monkeypatch.setattr(responder, "_resolve_role_arn", lambda account: "role")
    monkeypatch.setattr(responder, "_recent_action_count", lambda: 0)
    monkeypatch.setattr(responder, "_get_dredge", lambda role: MagicMock())
    monkeypatch.setattr(responder, "_outbox_table", None)
    record = {"body": json.dumps({"detection_id": "d1", "response_module": "test_action"}),
              "messageAttributes": {"delivery_id": {"stringValue": "outbox1"}}}
    for message_id in ["first", "replayed"]:
        responder._process_record({**record, "messageId": message_id}, None, None, MagicMock())
    handler.assert_called_once()


def test_responder_does_not_reexecute_after_action_exception(monkeypatch, receipts):
    handler = MagicMock(side_effect=TimeoutError("outcome unknown"))
    monkeypatch.setitem(responder.RESPONSE_MODULE_HANDLERS, "test_action", handler)
    monkeypatch.setattr(responder, "_resolve_role_arn", lambda account: "role")
    monkeypatch.setattr(responder, "_recent_action_count", lambda: 0)
    monkeypatch.setattr(responder, "_get_dredge", lambda role: MagicMock())
    record = {"body": json.dumps({"detection_id": "d1", "response_module": "test_action"})}
    responder._process_record(record, None, None, MagicMock())
    responder._process_record(record, None, None, MagicMock())
    handler.assert_called_once()
    assert next(iter(receipts.table.items.values()))["status"] == "IN_FLIGHT"


def test_notification_reclaims_expired_lease_without_accepting_old_owner(receipts, monkeypatch):
    class Crash(BaseException):
        pass
    with pytest.raises(Crash), receipts.delivery("alert", "slack"):
        raise Crash()
    key, old = next(iter(receipts.table.items.items()))
    old_token = old["token"]
    monkeypatch.setattr("src.infra.delivery_state.time.time", lambda: old["lease_until"] + 1)
    with receipts.delivery("alert", "slack"):
        with pytest.raises(ClientError):
            receipts.table.update_item(Key={"delivery_key": key},
                ExpressionAttributeValues={":token": old_token, ":done": "DONE"})
    assert receipts.table.items[key]["status"] == "DONE"


def test_settings_outage_does_not_ack_notification_batch(monkeypatch):
    monkeypatch.setattr(notifier, "_cached_settings", None)
    monkeypatch.setattr(notifier, "SETTINGS_TABLE_NAME", "settings")
    aws = MagicMock()
    aws._ddb.get_item.side_effect = RuntimeError("unavailable")
    with pytest.raises(RuntimeError, match="unavailable"):
        notifier.load_global_settings(aws=aws, logger=MagicMock())
    assert notifier._cached_settings is None


def test_partial_batch_failure_identifies_only_unsuccessful_message(monkeypatch, receipts):
    monkeypatch.setattr(notifier, "load_global_settings", lambda **kw: make_settings_webhook())
    monkeypatch.setattr(notifier, "Logger", MagicMock())
    monkeypatch.setattr(notifier, "_post_json", MagicMock(side_effect=[(200, "ok"), (503, "retry")]))
    result = notifier.lambda_handler({"Records": [
        {"messageId": "success", "body": json.dumps(make_alert(alert_key="a"))},
        {"messageId": "failure", "body": json.dumps(make_alert(alert_key="b"))},
    ]}, None)
    assert result["batchItemFailures"] == [{"itemIdentifier": "failure"}]


def test_numeric_values_stay_numeric_when_forwarded_to_sqs():
    from decimal import Decimal
    aws = AwsHandler(logger=MagicMock())
    aws._sqs = MagicMock()
    aws.sqs_send(queue_url="q", body={"raw_event": {"severity": Decimal("8.5")}})
    assert json.loads(aws._sqs.send_message.call_args.kwargs["MessageBody"]) == {"raw_event": {"severity": 8.5}}


def test_ir_completion_receipt_failure_does_not_hide_action_audit(receipts, monkeypatch, caplog):
    monkeypatch.setattr(receipts.table, "update_item", MagicMock(side_effect=RuntimeError("storage down")))
    with receipts.delivery("alert", "response:action", replay=False):
        pass  # action succeeded; caller must still be able to record rollback data
    assert next(iter(receipts.table.items.values()))["status"] == "IN_FLIGHT"
    assert "IR_DELIVERY_COMPLETE_WRITE_FAILED" in caplog.text
    with pytest.raises(DeliveryBusy), receipts.delivery("alert", "response:action", replay=False):
        pytest.fail("Receipt outage allowed repeated action")

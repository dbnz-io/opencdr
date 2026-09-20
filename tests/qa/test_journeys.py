"""User journeys through real Lambda handlers and Moto's AWS service models."""

import json
from unittest.mock import MagicMock

import pytest
from dredge.aws_ir.models import OperationResult


@pytest.mark.parametrize(
    ("rule_file", "event_file", "source"),
    [
        (
            "cloudtrail/009_admin_policy_attached.json",
            "009_admin_policy_attached.json",
            "cloudtrail",
        ),
        (
            "guardduty/024_guardduty_iam_credential_compromise.json",
            "024_guardduty_iam_credential_compromise.json",
            "guardduty",
        ),
    ],
)
def test_detection_to_query_and_notification(app, rule_file, event_file, source):
    rule = app.rule(rule_file, response_module="")
    event = app.event(event_file)
    batch = app.ingest(event)
    signals = app.rows("signals")
    assert len(signals) == 1
    signal = signals[0]
    assert signal["source"] == source
    assert signal["rule_id"] == rule["rule_id"]
    assert signal["expires_at"] > 0
    found = app.call("GET", "/signals", query={"event_id": signal["event_id"]})
    assert [r["detection_id"] for r in found["items"]] == [signal["detection_id"]]
    # Replay the actual queued message, not a second freshly generated detection.
    assert app.signal_writer.lambda_handler(batch, None) == {"batchItemFailures": []}
    assert len(app.rows("signals")) == 1
    assert len(app.rows("alerts")) == len(app.rows("outbox")) == 1
    app.publish()
    notifications = app.consume("notifications", app.notifier)
    mail = app.receive("mailbox")["Records"]
    assert len(mail) == 1
    assert rule["rule_id"] in json.loads(mail[0]["body"])["Message"]
    # Duplicate stream delivery and duplicate SQS delivery must not notify twice.
    app.publish()
    assert not app.receive("notifications")["Records"]
    assert not app.notifier.lambda_handler(notifications, None)["batchItemFailures"]
    assert not app.receive("mailbox")["Records"]
    receipts = app.rows("delivery_state")
    assert len(receipts) == 1 and receipts[0]["status"] == "DONE"


def test_rule_lifecycle_and_access_control(app, monkeypatch):
    rule = app.rule(response_module="")
    path = f"/rules/{rule['rule_id']}"
    query = {"rule_kind": "signal"}
    assert app.call("GET", path, query=query)["enabled"]
    app.call("POST", "/rules", rule, status=409)
    app.call("GET", path, query=query, key="unknown-key", status=403)
    app.call("GET", "/signals", query={}, status=400)
    changed = app.call("PUT", path, {**rule, "enabled": False, "expected_rev": 0})
    app.call("PUT", path, {**rule, "expected_rev": changed["rev"] + 1}, status=409)
    monkeypatch.setattr(app.processor, "RULES_CACHE", None)
    assert app.processor.lambda_handler(app.event(), None)["status"] == "no_rules"
    assert not app.rows("signals") and not app.rows("outbox")
    app.call("DELETE", path, query=query)
    app.call("GET", path, query=query, status=404)
    app.call("GET", "/status")
    app.call("GET", "/help")


def test_unmatched_and_unsupported_events_have_no_effects(app):
    app.rule(response_module="")
    event = app.event()
    event["detail"]["eventName"] = "ListBuckets"
    assert app.processor.lambda_handler(event, None)["status"] == "no_detection"
    assert (
        app.processor.lambda_handler({"source": "qa.unsupported", "detail": {}}, None)["status"]
        == "ignored"
    )
    assert not app.receive("signals_write")["Records"]
    assert not app.rows("alerts") and not app.rows("outbox")


def test_correlation_persists_and_does_not_recurse(app):
    app.rule(notify=False, response_module="")
    rule = app.rule("cloudtrail/021_correlation_iam_activity_burst.json", response_module="")
    for _ in range(rule["threshold"]):
        app.ingest(app.event())
    signals = app.stream("signals")
    assert len(signals["Records"]) == rule["threshold"]
    result = app.alerter.lambda_handler(signals, None)
    assert result["alerts_stored"] == result["outboxed"] == 1
    assert app.rows("alerts")[0]["rule_id"] == rule["rule_id"]
    # Replay the same source records: correlation must not emit another alert.
    assert app.alerter.lambda_handler(signals, None)["alerts_stored"] == 0
    app.publish()
    written = app.consume("signals_write", app.signal_writer)
    assert json.loads(written["Records"][0]["body"])["item_type"] == "correlation"
    assert len(app.rows("signals")) == rule["threshold"] + 1
    assert app.alerter.lambda_handler(app.stream("signals"), None)["alerts_stored"] == 0
    app.consume("notifications", app.notifier)
    assert len(app.receive("mailbox")["Records"]) == 1


def test_response_and_api_requested_rollback(app, monkeypatch):
    # Only the external remediation SDK is replaced. Claims, action records,
    # role lookup, rollback queue, audit and notification outboxes remain real.
    dredge = MagicMock()
    dredge.aws_ir.response.disable_user.return_value = OperationResult(
        operation="disable_user",
        target="user=attacker",
        success=True,
        details={
            "access_keys_disabled": ["AKIAQA"],
            "groups_removed": ["admins"],
            "managed_policies_detached": [],
            "inline_policies": {},
        },
    )
    dredge.aws_ir.response.restore_user.return_value = OperationResult(
        operation="restore_user",
        target="user=attacker",
        success=True,
        details={},
    )
    monkeypatch.setattr(app.responder, "_get_dredge", lambda role_arn=None: dredge)
    monkeypatch.setattr(app.ir_rollback, "_get_dredge", lambda role_arn=None: dredge)
    app.rule()
    app.ingest(app.event())
    app.publish()
    batch = app.consume("responses", app.responder)
    dredge.aws_ir.response.disable_user.assert_called_once_with(user_name="attacker")
    app.responder.lambda_handler(batch, None)
    assert dredge.aws_ir.response.disable_user.call_count == 1
    actions = app.rows("ir_actions")
    assert len(actions) == 1 and actions[0]["rollback_supported"]
    path = f"/ir-actions/{actions[0]['detection_id']}"
    app.call("GET", path)
    app.call("POST", path + "/rollback", {"reason": "QA verification"}, status=202)
    app.call("POST", path + "/rollback", {}, status=409)
    rollback = app.consume("ir_rollback", app.ir_rollback)
    dredge.aws_ir.response.restore_user.assert_called_once_with(
        user_name="attacker",
        access_keys_disabled=["AKIAQA"],
        groups_removed=["admins"],
        managed_policies_detached=[],
        inline_policies={},
    )
    action = app.call("GET", path)
    assert action["rolled_back"] and action["rollback_status"] == "succeeded"
    assert action["rollback_requested_by"] == app.key
    app.ir_rollback.lambda_handler(rollback, None)
    assert dredge.aws_ir.response.restore_user.call_count == 1
    app.call("POST", path + "/rollback", {}, status=409)
    assert "rollback_success" in {json.loads(row["payload"])["type"] for row in app.rows("outbox")}


def test_notification_failure_retries_without_losing_delivery(app):
    app.rule(response_module="")
    app.ingest(app.event())
    app.publish()
    batch = app.receive("notifications")
    assert len(batch["Records"]) == 1
    # A real service error in the emulator: topic no longer exists.
    import boto3

    settings = app.call("GET", "/settings")
    topic = settings["channels"]["email"]["topic_arn"]
    sns = boto3.client("sns")
    sns.delete_topic(TopicArn=topic)
    result = app.notifier.lambda_handler(batch, None)
    assert result["batchItemFailures"] == [{"itemIdentifier": batch["Records"][0]["messageId"]}]
    assert not app.rows("delivery_state")
    # Restore destination and replay precisely the failed message.
    assert sns.create_topic(Name="qa-email")["TopicArn"] == topic
    arn = app.sqs.get_queue_attributes(QueueUrl=app.queues["mailbox"], AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    sns.subscribe(TopicArn=topic, Protocol="sqs", Endpoint=arn)
    assert not app.notifier.lambda_handler(batch, None)["batchItemFailures"]
    assert len(app.receive("mailbox")["Records"]) == 1
    assert app.rows("delivery_state")[0]["status"] == "DONE"


def test_partial_signal_batch_preserves_good_record(app):
    app.rule(response_module="")
    assert app.processor.lambda_handler(app.event(), None)["status"] == "processed"
    batch = app.receive("signals_write")
    assert len(batch["Records"]) == 1
    batch["Records"].append({"messageId": "invalid-signal", "body": "{}"})
    result = app.signal_writer.lambda_handler(batch, None)
    assert result["batchItemFailures"] == [{"itemIdentifier": "invalid-signal"}]
    assert len(app.rows("signals")) == 1


def test_publisher_resumes_after_partial_fanout(app):
    from botocore.exceptions import ClientError

    app.rule(response_module="")
    app.ingest(app.event())
    app.sqs.delete_queue(QueueUrl=app.queues["responses"])
    with pytest.raises(ClientError):
        app.publisher.lambda_handler(app.stream("outbox"), None)
    outbox = app.rows("outbox")
    assert len(outbox) == 1
    assert outbox[0]["status"] == "PENDING"
    assert outbox[0]["sent_destinations"] == ["notifications"]
    assert len(app.receive("notifications")["Records"]) == 1
    app.sqs.create_queue(QueueName="qa-responses")
    app.publish()
    assert not app.receive("notifications")["Records"]
    assert len(app.receive("responses")["Records"]) == 1
    assert app.rows("outbox")[0]["attempts"] == 2


def test_signal_archival_contract(app, monkeypatch):
    from src.handlers import archiver

    app.rule(response_module="")
    app.ingest(app.event())
    transport = MagicMock()
    transport.put_record_batch.return_value = {"FailedPutCount": 0}
    monkeypatch.setattr(archiver, "_firehose", transport)
    monkeypatch.setenv("SIGNALS_FIREHOSE_STREAM_NAME", "qa-archive")
    result = archiver.lambda_handler(app.stream("signals"), None)
    assert result == {"sent": 1, "skipped": 0, "flatten_failed": 0}
    request = transport.put_record_batch.call_args.kwargs
    assert request["DeliveryStreamName"] == "qa-archive"
    archived = json.loads(request["Records"][0]["Data"])
    signal = app.rows("signals")[0]
    assert archived["detection_id"] == signal["detection_id"]
    assert archived["actor_user_name"] == "attacker"
    assert json.loads(archived["raw_item"])["event_id"] == signal["event_id"]
    transport.put_record_batch.return_value = {"FailedPutCount": 1}
    with pytest.raises(RuntimeError, match="rejected by Firehose"):
        archiver.lambda_handler(app.stream("signals"), None)

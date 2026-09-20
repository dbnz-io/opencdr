"""Validate the deployment wiring required by the delivery recovery paths."""
from pathlib import Path

import yaml


def config():
    class Loader(yaml.SafeLoader):
        pass
    def intrinsic(loader, tag, node):
        if isinstance(node, yaml.ScalarNode):
            return {tag: loader.construct_scalar(node)}
        return {tag: loader.construct_sequence(node)}
    Loader.add_multi_constructor("!", intrinsic)
    return yaml.load(Path("serverless.yml").read_text(), Loader=Loader)


def test_notification_retry_visibility_exceeds_receipt_lease():
    cfg = config()
    notifier = cfg["functions"]["notifier"]
    queue = cfg["resources"]["Resources"]["NotificationsQueue"]["Properties"]
    sqs = next(e["sqs"] for e in notifier["events"] if "sqs" in e)
    assert sqs["functionResponseType"] == "ReportBatchItemFailures"
    assert sqs["batchSize"] == 1
    assert notifier["timeout"] < 120 < queue["VisibilityTimeout"]
    assert queue["VisibilityTimeout"] >= 6 * notifier["timeout"]


def test_publisher_recovery_has_schedule_index_and_signal_permission():
    cfg = config()
    publisher = cfg["functions"]["publisher"]
    assert publisher["timeout"] < 120
    assert any(e.get("schedule", {}).get("input") == {"recover_outbox": True}
               for e in publisher["events"])
    assert "SIGNALS_WRITE_QUEUE_URL" in publisher["environment"]
    outbox = cfg["resources"]["Resources"]["OutboxTable"]["Properties"]
    index = outbox["GlobalSecondaryIndexes"][0]
    assert index["IndexName"] == "gsi_outbox_status_updated_at"
    assert [k["AttributeName"] for k in index["KeySchema"]] == ["status", "updated_at"]
    assert any("dynamodb:Query" in st["Action"] and any("gsi_outbox_status_updated_at" in str(r) for r in st["Resource"])
               for st in publisher["iamRoleStatements"])


def test_notification_and_response_functions_have_receipt_store_permissions():
    cfg = config()
    assert cfg["resources"]["Resources"]["DeliveryStateTable"]["Properties"]["TimeToLiveSpecification"]["AttributeName"] == "expires_at"
    for name in ("notifier", "responder"):
        function = cfg["functions"][name]
        assert function["environment"]["DELIVERY_STATE_TABLE_NAME"] == {"Ref": "DeliveryStateTable"}
        assert any({"GetAtt": "DeliveryStateTable.Arn"} in st["Resource"]
                   and "dynamodb:PutItem" in st["Action"] for st in function["iamRoleStatements"])

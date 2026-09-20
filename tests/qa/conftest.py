"""Isolated handler integration environment; no deployed resources are used."""

import importlib
import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import boto3
import pytest
import yaml
from moto import mock_aws

ROOT = Path(__file__).resolve().parents[2]
TABLES = {
    "signals": "signals-table-v2",
    "alerts": "alerts-table",
    "logs": "logs-table-v2",
    "detection_rules": "detection-rules-table",
    "settings": "settings-table",
    "ir_account_roles": "ir-account-roles-table",
    "ir_actions": "ir-actions-table",
    "outbox": "outbox-table",
    "delivery_state": "delivery-state-table",
}


class App:
    def call(self, method, path, body=None, query=None, *, status=200, key=None):
        response = self.api.lambda_handler(
            {
                "httpMethod": method,
                "path": path,
                "body": json.dumps(body) if body is not None else None,
                "queryStringParameters": query or {},
                "requestContext": {"identity": {"apiKeyId": self.key if key is None else key}},
            },
            None,
        )
        assert response["statusCode"] == status, response
        return json.loads(response["body"])

    def rule(self, name="cloudtrail/009_admin_policy_attached.json", **overrides):
        rule = json.loads((ROOT / "support_files/detection_rules" / name).read_text())
        rule.update(overrides)
        self.call("POST", "/rules", rule, status=201)
        return rule

    def event(self, name="009_admin_policy_attached.json"):
        event = json.loads((ROOT / "support_files/test_events" / name).read_text())
        now = datetime.now(UTC).isoformat()
        event["time"] = now
        detail = event["detail"]
        if event["source"] == "aws.guardduty":
            detail.update(id=str(uuid4()), updatedAt=now, createdAt=now)
        else:
            detail.update(eventID=str(uuid4()), eventTime=now)
        return event

    def rows(self, name):
        return self.tables[name].scan(ConsistentRead=True)["Items"]

    def receive(self, queue):
        messages = self.sqs.receive_message(
            QueueUrl=self.queues[queue],
            MaxNumberOfMessages=10,
            MessageAttributeNames=["All"],
        ).get("Messages", [])
        return {
            "Records": [
                {
                    "messageId": m["MessageId"],
                    "body": m["Body"],
                    "receiptHandle": m["ReceiptHandle"],
                    "messageAttributes": {
                        k: {"stringValue": v["StringValue"], "dataType": v["DataType"]}
                        for k, v in m.get("MessageAttributes", {}).items()
                    },
                }
                for m in messages
            ]
        }

    def consume(self, queue, handler):
        batch = self.receive(queue)
        assert batch["Records"], f"No messages in {queue}"
        result = handler.lambda_handler(batch, None)
        assert not result.get("batchItemFailures"), result
        for record in batch["Records"]:
            self.sqs.delete_message(
                QueueUrl=self.queues[queue], ReceiptHandle=record["receiptHandle"]
            )
        return batch

    def stream(self, name):
        table = self.tables[name]
        stream = self.streams.describe_stream(StreamArn=table.latest_stream_arn)[
            "StreamDescription"
        ]
        records = []
        for shard in stream["Shards"]:
            iterator = self.streams.get_shard_iterator(
                StreamArn=table.latest_stream_arn,
                ShardId=shard["ShardId"],
                ShardIteratorType="TRIM_HORIZON",
            )["ShardIterator"]
            while iterator:
                page = self.streams.get_records(ShardIterator=iterator)
                if not page["Records"]:
                    break
                records.extend(
                    {**r, "eventSourceARN": table.latest_stream_arn} for r in page["Records"]
                )
                iterator = page.get("NextShardIterator")
        return {"Records": records}

    def ingest(self, event):
        result = self.processor.lambda_handler(event, None)
        assert result == {"status": "processed", "detections": 1, "stored": 1}, result
        return self.consume("signals_write", self.signal_writer)

    def publish(self):
        result = self.publisher.lambda_handler(self.stream("outbox"), None)
        assert result["ok"]
        assert all(row["status"] == "SENT" for row in self.rows("outbox"))


@pytest.fixture
def app(monkeypatch):
    for key, value in {
        "AWS_ACCESS_KEY_ID": "testing",
        "AWS_SECRET_ACCESS_KEY": "testing",
        "AWS_SESSION_TOKEN": "testing",
        "AWS_DEFAULT_REGION": "us-east-1",
        "AWS_REGION": "us-east-1",
        "AWS_EC2_METADATA_DISABLED": "true",
        "AWS_XRAY_SDK_ENABLED": "false",
        "DREDGE_DRY_RUN": "true",
    }.items():
        monkeypatch.setenv(key, value)
    with mock_aws():
        a = App()
        ddb = boto3.resource("dynamodb")
        a.tables = {}
        # Read real key/index schemas, including CloudFormation-tagged YAML.
        template = yaml.load((ROOT / "serverless.yml").read_text(), Loader=yaml.BaseLoader)
        for resource in template["resources"]["Resources"].values():
            if resource.get("Type") != "AWS::DynamoDB::Table":
                continue
            props = resource["Properties"]
            suffix = props["TableName"].split("${self:provider.stage}-")[-1]
            for name, expected in TABLES.items():
                if suffix != expected:
                    continue
                spec = {
                    k: props[k]
                    for k in ("KeySchema", "AttributeDefinitions", "GlobalSecondaryIndexes")
                    if k in props
                }
                table = ddb.create_table(
                    TableName=f"qa-{suffix}",
                    BillingMode="PAY_PER_REQUEST",
                    StreamSpecification={
                        "StreamEnabled": True,
                        "StreamViewType": "NEW_AND_OLD_IMAGES",
                    },
                    **spec,
                )
                a.tables[name] = table
                monkeypatch.setenv(name.upper() + "_TABLE_NAME", table.name)
        assert set(a.tables) == set(TABLES), "Deployment table mapping drifted"
        a.sqs = boto3.client("sqs")
        a.streams = boto3.client("dynamodbstreams")
        a.queues = {}
        for name in ("signals_write", "notifications", "responses", "ir_rollback", "mailbox"):
            a.queues[name] = a.sqs.create_queue(QueueName=f"qa-{name}")["QueueUrl"]
            monkeypatch.setenv(name.upper() + "_QUEUE_URL", a.queues[name])
        for name in (
            "api",
            "processor",
            "signal_writer",
            "alerter",
            "publisher",
            "notifier",
            "responder",
            "ir_rollback",
        ):
            module = importlib.import_module(f"src.handlers.{name}")
            setattr(a, name, module)
            for table_name, table in a.tables.items():
                for attr, value in (
                    (table_name + "_table", table),
                    ("_" + table_name + "_table", table),
                    (table_name.upper() + "_TABLE_NAME", table.name),
                ):
                    if hasattr(module, attr):
                        monkeypatch.setattr(module, attr, value)
            for queue_name, url in a.queues.items():
                attr = queue_name.upper() + "_QUEUE_URL"
                if hasattr(module, attr):
                    monkeypatch.setattr(module, attr, url)
        for module, attr, value in (
            (a.processor, "RULES_CACHE", None),
            (a.processor, "LISTS_CACHE", None),
            (a.alerter, "CORR_RULES_CACHE", None),
            (a.notifier, "_cached_settings", None),
            (a.api, "_key_scope_cache", {}),
        ):
            monkeypatch.setattr(module, attr, value)
        logger = importlib.import_module("src.infra.logger")
        monkeypatch.setattr(logger, "_logs_table", a.tables["logs"])
        monkeypatch.setattr(a.api, "sqs", a.sqs)
        gateway = boto3.client("apigateway")
        monkeypatch.setattr(a.api, "apigateway", gateway)
        monkeypatch.setattr(a.api, "ssm", boto3.client("ssm"))
        a.key = gateway.create_api_key(
            name=a.api._API_KEY_NAME_PREFIX + "-" + "-".join(sorted(a.api.ALL_SCOPES)), enabled=True
        )["id"]
        sns = boto3.client("sns")
        topic = sns.create_topic(Name="qa-email")["TopicArn"]
        mailbox_arn = a.sqs.get_queue_attributes(
            QueueUrl=a.queues["mailbox"], AttributeNames=["QueueArn"]
        )["Attributes"]["QueueArn"]
        sns.subscribe(TopicArn=topic, Protocol="sqs", Endpoint=mailbox_arn)
        a.call(
            "POST",
            "/settings",
            {
                "notifications_enabled": True,
                "channels": {"email": {"enabled": True, "topic_arn": topic}},
                "routing": {"CRITICAL": ["email"], "HIGH": ["email"]},
                "guardduty_notify": {"default": True},
            },
            status=201,
        )
        yield a

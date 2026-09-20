"""Durable per-destination receipts and fail-closed incident-response claims."""
import hashlib
import logging
import os
import time
import uuid
from contextlib import contextmanager

import boto3
from botocore.exceptions import ClientError

from .aws_handler import ttl_expires_at

_log = logging.getLogger(__name__)


class AlreadyDelivered(Exception):
    pass


class DeliveryBusy(Exception):
    pass


def delivery_id(record: dict, item: dict) -> str:
    attributes = record.get("messageAttributes") or {}
    published_id = (attributes.get("delivery_id") or {}).get("stringValue")
    return str(published_id or item.get("alert_key") or item.get("detection_id")
               or item.get("alert_id") or record.get("messageId")
               or hashlib.sha256(record.get("body", "").encode()).hexdigest())


class DeliveryState:
    def __init__(self):
        name = os.getenv("DELIVERY_STATE_TABLE_NAME", "")
        self.table = boto3.resource("dynamodb").Table(name) if name else None

    @contextmanager
    def delivery(self, identity: str, destination: str, *, replay: bool = True):
        """Notification leases can expire; destructive-action claims cannot.

        External effects and DynamoDB cannot commit atomically. A notification
        can repeat after an ambiguous timeout; an IR action must never repeat
        automatically after such an outcome.
        """
        if self.table is None:
            if os.getenv("AWS_LAMBDA_FUNCTION_NAME"):
                raise RuntimeError("DELIVERY_STATE_TABLE_NAME is required")
            yield  # local callers without deployment infrastructure
            return
        key = hashlib.sha256(f"{identity}\0{destination}".encode()).hexdigest()
        token = uuid.uuid4().hex
        now = int(time.time())
        item = {"delivery_key": key, "identity": identity, "destination": destination,
                "status": "IN_FLIGHT", "token": token, "created_at": now,
                "lease_until": now + 120}
        if replay:
            item["expires_at"] = ttl_expires_at()
        condition = "attribute_not_exists(delivery_key)"
        args = {}
        if replay:
            condition += " OR (#s = :inflight AND lease_until < :now)"
            args = {"ExpressionAttributeNames": {"#s": "status"},
                    "ExpressionAttributeValues": {":inflight": "IN_FLIGHT", ":now": now}}
        try:
            self.table.put_item(Item=item, ConditionExpression=condition, **args)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConditionalCheckFailedException":
                raise
            stored = self.table.get_item(Key={"delivery_key": key}, ConsistentRead=True).get("Item", {})
            if stored.get("status") == "DONE":
                raise AlreadyDelivered from exc
            raise DeliveryBusy(f"Delivery {key} is in progress or has an uncertain outcome") from exc
        try:
            yield
        except Exception:
            if replay:
                self.table.delete_item(
                    Key={"delivery_key": key}, ConditionExpression="#t = :token",
                    ExpressionAttributeNames={"#t": "token"},
                    ExpressionAttributeValues={":token": token},
                )
            raise
        else:
            try:
                self.table.update_item(
                    Key={"delivery_key": key},
                    UpdateExpression="SET #s = :done",
                    ConditionExpression="#t = :token",
                    ExpressionAttributeNames={"#s": "status", "#t": "token"},
                    ExpressionAttributeValues={":done": "DONE", ":token": token},
                )
            except Exception:
                if replay:
                    raise
                # The permanent claim already prevents replay. Let responder
                # retain its action-result log and rollback record even when
                # the completion receipt cannot be updated.
                _log.exception("IR_DELIVERY_COMPLETE_WRITE_FAILED delivery_key=%s", key)

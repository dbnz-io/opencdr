# src/handlers/publisher.py

import json
import os
import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from src.config.requirements import load_publisher_config
from src.infra.aws_handler import AwsHandler
from src.infra.logger import Logger
from src.infra.metrics import emit_metric
from src.infra.xray_setup import patch_boto3

patch_boto3()

# Bounded automatic retry: a FAILED outbox record was previously never
# revisited by anything. Instead of new retry infrastructure, this reuses
# the outbox table's own existing `attempts` counter and its own DynamoDB
# stream (the same one that already triggers this Lambda) -- resetting
# status to PENDING on failure re-triggers processing naturally. No
# backoff between attempts; only gives up (FAILED) once attempts reaches
# this cap.
PUBLISHER_CLAIM_SECONDS = 120  # longer than the deployed 30-second Lambda timeout

PUBLISHER_MAX_ATTEMPTS = int(os.getenv("PUBLISHER_MAX_ATTEMPTS", "5"))


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _err_code(e: Exception) -> str:
    if isinstance(e, ClientError):
        return e.response.get("Error", {}).get("Code", "ClientError")
    return type(e).__name__


def _dynamodb_unmarshal_image(image: dict) -> dict:
    from boto3.dynamodb.types import TypeDeserializer

    d = TypeDeserializer()
    return {k: d.deserialize(v) for k, v in image.items()}


class OutboxPublisher:
    """
    Reads Outbox table stream and publishes to SQS, then updates outbox status.

    Supports BOTH formats:
      A) { destination: "notifications", payload: {..} }
      B) { destinations: ["notifications","responses"], payload: "<json str>" }
    """

    def __init__(self, *, logger: Logger, aws: AwsHandler, outbox_table_name: str):
        self.logger = logger
        self.aws = aws
        self._ddb = boto3.resource("dynamodb")
        self.outbox_table = self._ddb.Table(outbox_table_name)
        self._claim_token = uuid.uuid4().hex
        self._claimed_item = {}

    def _queue_url_for_destination(self, *, destination: str, cfg) -> str:
        dest = (destination or "").strip().upper()
        if dest in ("NOTIFICATIONS", "NOTIFICATION"):
            if not cfg.notifications_queue_url:
                raise RuntimeError("NOTIFICATIONS_QUEUE_URL not configured for publisher")
            return cfg.notifications_queue_url
        if dest == "SIGNALS":
            url = os.getenv("SIGNALS_WRITE_QUEUE_URL", "")
            if not url:
                raise RuntimeError("SIGNALS_WRITE_QUEUE_URL not configured")
            return url
        if dest in ("RESPONSES", "RESPONSE"):
            if not cfg.responses_queue_url:
                raise RuntimeError("RESPONSES_QUEUE_URL not configured for publisher")
            return cfg.responses_queue_url
        raise ValueError(f"Unknown outbox destination: {destination}")

    def _claim_outbox(self, *, outbox_id: str) -> bool:
        try:
            self._claim_token = uuid.uuid4().hex
            response = self.outbox_table.update_item(
                Key={"outbox_id": outbox_id},
                UpdateExpression="SET #s = :inflight, updated_at = :u, claim_token = :token ADD attempts :one",
                ReturnValues="ALL_NEW",
                ConditionExpression="#s = :pending",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={
                    ":pending": "PENDING",
                    ":inflight": "IN_FLIGHT",
                    ":u": _utc_now_iso(),
                    ":one": Decimal(1),
                    ":token": self._claim_token,
                },
            )
            self._claimed_item = response["Attributes"]
            return True
        except ClientError as e:
            if _err_code(e) == "ConditionalCheckFailedException":
                return False
            raise

    def _mark_sent(self, *, outbox_id: str, sqs_message_id: str, sent_destinations: list[str] | None = None) -> None:
        expr = "SET #s = :sent, updated_at = :u, sqs_message_id = :m REMOVE last_error"
        values = {
            ":sent": "SENT",
            ":u": _utc_now_iso(),
            ":m": sqs_message_id,
        }
        if sent_destinations is not None:
            expr = "SET #s = :sent, updated_at = :u, sqs_message_id = :m, sent_destinations = :sd REMOVE last_error"
            values[":sd"] = sent_destinations
        values[":token"] = self._claim_token
        self.outbox_table.update_item(
            Key={"outbox_id": outbox_id},
            UpdateExpression=expr,
            ConditionExpression="claim_token = :token",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues=values,
        )

    def _mark_failed(self, *, outbox_id: str, error_code: str, error_message: str) -> None:
        self.outbox_table.update_item(
            Key={"outbox_id": outbox_id},
            UpdateExpression="SET #s = :failed, updated_at = :u, last_error = :e",
            ConditionExpression="claim_token = :token",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":token": self._claim_token,
                ":failed": "FAILED",
                ":u": _utc_now_iso(),
                ":e": {"code": error_code, "message": error_message[:2000]},
            },
        )

    def _mark_retry_or_failed(
        self,
        *,
        outbox_id: str,
        error_code: str,
        error_message: str,
        attempts: int,
        sent_destinations: list[str],
    ) -> bool:
        """
        Bounded automatic retry: reset to PENDING (re-triggers processing
        via this table's own stream) if attempts is still under
        PUBLISHER_MAX_ATTEMPTS, persisting sent_destinations so a retry
        never re-publishes to a destination that already got the message.
        Otherwise, terminal FAILED via the existing _mark_failed.

        Returns True if reset to PENDING for retry, False if marked FAILED.
        """
        if attempts < PUBLISHER_MAX_ATTEMPTS:
            self.outbox_table.update_item(
                Key={"outbox_id": outbox_id},
                UpdateExpression="SET #s = :pending, updated_at = :u, last_error = :e, sent_destinations = :sd",
                ConditionExpression="claim_token = :token",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={
                    ":pending": "PENDING",
                    ":token": self._claim_token,
                    ":u": _utc_now_iso(),
                    ":e": {"code": error_code, "message": error_message[:2000]},
                    ":sd": sent_destinations,
                },
            )
            return True

        self._mark_failed(outbox_id=outbox_id, error_code=error_code, error_message=error_message)
        return False

    def recover_abandoned(self) -> int:
        """Recover expired claims and pending records whose stream delivery failed.

        The GSI includes legacy IN_FLIGHT rows (which already had updated_at).
        Conditional updates fence the scan against active workers and races.
        """
        cutoff = (datetime.now(UTC) - timedelta(seconds=PUBLISHER_CLAIM_SECONDS)).isoformat()
        recovered = 0
        for status in ("IN_FLIGHT", "PENDING"):
            query = {
                "IndexName": "gsi_outbox_status_updated_at",
                "KeyConditionExpression": Key("status").eq(status) & Key("updated_at").lte(cutoff),
                "Limit": 100,
            }
            # Bound work per invocation; subsequent scheduled runs drain more.
            for item in self.outbox_table.query(**query).get("Items", []):
                terminal = int(item.get("attempts", 0)) >= PUBLISHER_MAX_ATTEMPTS
                # Before durable consumer receipts existed, an abandoned claim
                # might already have executed a destructive response. Never
                # automatically replay that ambiguous legacy delivery.
                legacy_claim = status == "IN_FLIGHT" and not item.get("claim_token")
                terminal = terminal or legacy_claim
                try:
                    self.outbox_table.update_item(
                        Key={"outbox_id": item["outbox_id"]},
                        UpdateExpression="SET #s = :next, updated_at = :now, last_error = :error REMOVE claim_token",
                        ConditionExpression="#s = :old AND updated_at <= :cutoff",
                        ExpressionAttributeNames={"#s": "status"},
                        ExpressionAttributeValues={
                            ":old": status, ":next": "FAILED" if terminal else "PENDING",
                            ":now": _utc_now_iso(), ":cutoff": cutoff,
                            ":error": {"code": "RecoveryRequired" if terminal else "ClaimExpired",
                                       "message": "Legacy delivery requires inspection before replay" if legacy_claim
                                       else "Publisher retry budget exhausted" if terminal
                                       else "Abandoned delivery returned to pending"},
                        },
                    )
                    recovered += 1
                except ClientError as exc:
                    if _err_code(exc) != "ConditionalCheckFailedException":
                        raise
        return recovered

    def _checkpoint(self, outbox_id: str, sent_destinations: list[str]) -> None:
        self.outbox_table.update_item(
            Key={"outbox_id": outbox_id},
            UpdateExpression="SET sent_destinations = :sd",
            ConditionExpression="claim_token = :token",
            ExpressionAttributeValues={":sd": sent_destinations, ":token": self._claim_token},
        )

    def _load_payload(self, item: dict) -> dict:
        payload = item.get("payload")

        # If stored as a dict/map -> good
        if isinstance(payload, dict):
            return payload

        # If stored as JSON string -> parse
        if isinstance(payload, str) and payload.strip():
            try:
                return json.loads(payload)
            except Exception:
                # fallthrough below
                pass

        # Optional S3 pointer
        bucket = item.get("payload_s3_bucket")
        key = item.get("payload_s3_key")
        if bucket and key:
            s3 = boto3.client("s3")
            obj = s3.get_object(Bucket=bucket, Key=key)
            body = obj["Body"].read().decode("utf-8")
            return json.loads(body)

        raise ValueError("Outbox item missing payload (dict/JSON) and S3 pointer")

    def _extract_destinations(self, item: dict) -> list[str]:
        """
        Supports:
          - destination: "notifications"
          - destinations: ["notifications","responses"]
          - destinations: '["notifications","responses"]'
        """
        if isinstance(item.get("destination"), str) and item["destination"].strip():
            return [item["destination"]]

        dests = item.get("destinations")

        if isinstance(dests, list):
            return [str(d) for d in dests if str(d).strip()]

        if isinstance(dests, str) and dests.strip():
            try:
                parsed = json.loads(dests)
                if isinstance(parsed, list):
                    return [str(d) for d in parsed if str(d).strip()]
            except Exception:
                # treat as single destination string
                return [dests]

        return []

    def process_record(self, *, record: dict, cfg) -> None:
        event_name = record.get("eventName")
        if event_name not in ("INSERT", "MODIFY"):
            return

        ddb = record.get("dynamodb") or {}
        new_image = ddb.get("NewImage")
        if not new_image:
            return

        item = _dynamodb_unmarshal_image(new_image)

        outbox_id = item.get("outbox_id")
        status = (item.get("status") or "").upper()

        if status != "PENDING":
            return

        if not outbox_id:
            self.logger.error(
                event_type="ERROR",
                event_name="OUTBOX_RECORD_MISSING_ID",
                message="Outbox stream record missing outbox_id",
                details={"record": {"eventName": event_name}},
            )
            return

        claimed = self._claim_outbox(outbox_id=outbox_id)
        if not claimed:
            self.logger.info(
                event_type="PROCESSING",
                event_name="OUTBOX_ALREADY_CLAIMED",
                message="Outbox item already claimed/processed",
                details={"outbox_id": outbox_id},
            )
            return

        # Use the authoritative claimed row, never the stale stream snapshot.
        item = self._claimed_item
        if int(item.get("attempts", 0)) > PUBLISHER_MAX_ATTEMPTS:
            self._mark_failed(outbox_id=outbox_id, error_code="AttemptsExhausted",
                              error_message="Publisher retry budget exhausted")
            return

        # Populated as destinations succeed; referenced in the except block
        # too, so it must be defined before the try in case the exception
        # happens before (or between) any send -- e.g. no destinations, a
        # bad payload, or the very first destination failing.
        sent_this_attempt: list[str] = []
        current_destination: str | None = None

        try:
            destinations = self._extract_destinations(item)
            if not destinations:
                raise ValueError("Outbox item has no destination(s)")

            payload = self._load_payload(item)

            # Optional SQS attrs
            attrs = {"delivery_id": str(outbox_id)}
            if isinstance(item.get("signal_id"), str):
                attrs["signal_id"] = item["signal_id"]
            if isinstance(item.get("rule_id"), str):
                attrs["rule_id"] = item["rule_id"]

            # Destinations already sent on a prior attempt (persisted by
            # _mark_retry_or_failed) are never re-attempted -- avoids
            # double-publishing to a destination that already got the
            # message (notably "responses", which triggers an IR action).
            already_sent = set(item.get("sent_destinations") or [])
            sent_this_attempt = list(already_sent)
            remaining = [d for d in destinations if d not in already_sent]

            last_msg_id = None
            for dest in remaining:
                current_destination = dest
                queue_url = self._queue_url_for_destination(destination=dest, cfg=cfg)

                message = payload
                if dest.upper() == "SIGNALS":
                    message = {**payload, "item_type": "correlation",
                               "detection_id": str(payload["alert_id"])}
                msg_id = self.aws.sqs_send(
                    queue_url=queue_url,
                    body=message,
                    attributes=attrs if attrs else None,
                    success_event_name="OUTBOX_SQS_SEND_OK",
                    failure_event_name="OUTBOX_SQS_SEND_FAIL",
                    details={"outbox_id": outbox_id, "destination": dest},
                )
                last_msg_id = msg_id
                sent_this_attempt.append(dest)
                self._checkpoint(outbox_id, sent_this_attempt)
                emit_metric("PublishSuccess", dimensions={"destination": dest})

            self._mark_sent(
                outbox_id=outbox_id,
                sqs_message_id=last_msg_id or "unknown",
                sent_destinations=sent_this_attempt,
            )

            self.logger.info(
                event_type="PROCESSING",
                event_name="OUTBOX_PUBLISHED",
                message="Outbox item published and marked SENT",
                details={
                    "outbox_id": outbox_id,
                    "destinations": destinations,
                    "sqs_message_id": last_msg_id,
                },
            )

        except Exception as e:
            code = _err_code(e)
            msg = str(e)

            emit_metric(
                "PublishFailure",
                dimensions={"destination": current_destination or "unknown"},
            )

            attempts = int(item.get("attempts", 0))
            retrying = self._mark_retry_or_failed(
                outbox_id=outbox_id,
                error_code=code,
                error_message=msg,
                attempts=attempts,
                sent_destinations=sent_this_attempt,
            )

            self.logger.error(
                event_type="ERROR",
                event_name="OUTBOX_PUBLISH_RETRY" if retrying else "OUTBOX_PUBLISH_FAILED",
                message=(
                    "Failed to publish outbox item, reset to PENDING for retry"
                    if retrying
                    else "Failed to publish outbox item, giving up after max attempts"
                ),
                details={
                    "outbox_id": outbox_id,
                    "error_code": code,
                    "error": repr(e),
                    "attempts": attempts,
                    "max_attempts": PUBLISHER_MAX_ATTEMPTS,
                    "sent_destinations": sent_this_attempt,
                },
            )
            raise


def lambda_handler(event: dict, context) -> dict:
    cfg = load_publisher_config()

    logger = Logger(
        service=cfg.service,
        source=cfg.lambda_name,
        request_id=getattr(context, "aws_request_id", None),
        event_id="NOT_USED",
    )

    aws = AwsHandler(logger=logger, region_name=cfg.region)

    publisher = OutboxPublisher(
        logger=logger,
        aws=aws,
        outbox_table_name=cfg.outbox_table_name,
    )

    if event.get("recover_outbox") is True:
        return {"recovered": publisher.recover_abandoned()}

    records = event.get("Records", [])
    logger.info(
        event_type="INGESTION",
        event_name="OUTBOX_STREAM_BATCH_RECEIVED",
        message="Received DynamoDB stream batch",
        details={"records": len(records)},
    )

    for r in records:
        publisher.process_record(record=r, cfg=cfg)

    return {"ok": True, "records": len(records)}

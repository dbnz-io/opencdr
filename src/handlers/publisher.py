# src/handlers/publisher.py

import json
import os
from datetime import UTC, datetime
from decimal import Decimal

import boto3
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

    def _queue_url_for_destination(self, *, destination: str, cfg) -> str:
        dest = (destination or "").strip().upper()
        if dest in ("NOTIFICATIONS", "NOTIFICATION"):
            if not cfg.notifications_queue_url:
                raise RuntimeError("NOTIFICATIONS_QUEUE_URL not configured for publisher")
            return cfg.notifications_queue_url
        if dest in ("RESPONSES", "RESPONSE"):
            if not cfg.responses_queue_url:
                raise RuntimeError("RESPONSES_QUEUE_URL not configured for publisher")
            return cfg.responses_queue_url
        raise ValueError(f"Unknown outbox destination: {destination}")

    def _claim_outbox(self, *, outbox_id: str) -> bool:
        try:
            self.outbox_table.update_item(
                Key={"outbox_id": outbox_id},
                UpdateExpression="SET #s = :inflight, updated_at = :u ADD attempts :one",
                ConditionExpression="#s = :pending",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={
                    ":pending": "PENDING",
                    ":inflight": "IN_FLIGHT",
                    ":u": _utc_now_iso(),
                    ":one": Decimal(1),
                },
            )
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
        self.outbox_table.update_item(
            Key={"outbox_id": outbox_id},
            UpdateExpression=expr,
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues=values,
        )

    def _mark_failed(self, *, outbox_id: str, error_code: str, error_message: str) -> None:
        self.outbox_table.update_item(
            Key={"outbox_id": outbox_id},
            UpdateExpression="SET #s = :failed, updated_at = :u, last_error = :e",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
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
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={
                    ":pending": "PENDING",
                    ":u": _utc_now_iso(),
                    ":e": {"code": error_code, "message": error_message[:2000]},
                    ":sd": sent_destinations,
                },
            )
            return True

        self._mark_failed(outbox_id=outbox_id, error_code=error_code, error_message=error_message)
        return False

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
            attrs = {}
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

                msg_id = self.aws.sqs_send(
                    queue_url=queue_url,
                    body=payload,
                    attributes=attrs if attrs else None,
                    success_event_name="OUTBOX_SQS_SEND_OK",
                    failure_event_name="OUTBOX_SQS_SEND_FAIL",
                    details={"outbox_id": outbox_id, "destination": dest},
                )
                last_msg_id = msg_id
                sent_this_attempt.append(dest)
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

            # item's own "attempts" reflects the count *before* this
            # invocation's _claim_outbox call (its ADD attempts :one isn't
            # visible in this stream-captured snapshot) -- +1 for the
            # current attempt.
            attempts = int(item.get("attempts", 0)) + 1
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

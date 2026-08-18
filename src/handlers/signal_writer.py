# src/handlers/signal_writer.py
"""
SQS-triggered consumer for signals-table-v2 writes -- decouples burst
signal writes from that table's partition-key throughput ceiling (see
serverless.yml's SIGNALS TABLE V2 comment and docs/architecture.md).
severity_bucket is computed here, inside put_signal_if_not_exists
(src/infra/aws_handler.py), so the actual write happens exactly once,
as close to the table as possible.

This is the same shape of problem the outbox pattern
(OutboxTable/publisher.py) already solves, just for the opposite leg:
outbox defers the SQS *send* (guards against that failing after a
reliable DynamoDB write); this defers the DynamoDB *write* itself
(guards against that failing due to a hot partition), with SQS as the
durable buffer in front of it instead.

Deliberately does NOT follow responder.py/notifier.py's "log and
swallow every record, always ack the batch" convention -- that would
make this queue pointless: a throttled write would just be silently
dropped one hop later, never redelivered, and the DLQ would never
fill to alert anyone. Uses functionResponseType: ReportBatchItemFailures
instead, so only messages that actually failed to write are left
un-acked and eligible for SQS's own retry/backoff -> DLQ after
maxReceiveCount, while successfully-processed messages in the same
batch (including legitimate duplicates) are acked normally.
"""
from __future__ import annotations

import json
import os
from decimal import Decimal

from ..infra.aws_handler import AwsHandler
from ..infra.logger import Logger
from ..infra.metrics import emit_metric
from ..infra.xray_setup import patch_boto3

patch_boto3()

SIGNALS_TABLE_NAME = os.environ["SIGNALS_TABLE_NAME"]
_SERVICE = os.getenv("SERVICE_NAME", "OPENCDR-SIGNAL-WRITER")
LAMBDA_NAME = os.getenv("LAMBDA_NAME", "signal-writer")


def lambda_handler(event: dict, context) -> dict:
    logger = Logger(
        service=_SERVICE,
        source=LAMBDA_NAME,
        request_id=getattr(context, "aws_request_id", None),
    )
    aws = AwsHandler(logger=logger)
    batch_item_failures: list[dict] = []

    for record in event.get("Records", []):
        message_id = record.get("messageId")

        try:
            # parse_float=Decimal: a GuardDuty-sourced detection's raw_event
            # carries AWS's own float severity (e.g. 8.0) inside a nested
            # dict that gets written to DynamoDB as-is via put_item's
            # high-level resource API. That API's TypeSerializer rejects
            # native Python floats outright ("Float types are not
            # supported. Use Decimal types instead.") -- parsing floats as
            # Decimal here, at the JSON boundary, is the standard fix and
            # matches what boto3 itself returns when reading Numbers back.
            # CloudTrail-sourced items have no floats anywhere in their
            # raw_event, which is why this was invisible until a real
            # GuardDuty finding went through this path.
            signal_item = json.loads(record.get("body") or "{}", parse_float=Decimal)
        except (TypeError, ValueError):
            # Poison pill -- will never parse on retry. Log and drop
            # (ack) rather than retrying it into the DLQ forever.
            logger.error(
                event_name="SIGNAL_WRITE_MALFORMED_MESSAGE",
                message="Could not parse SQS message body as JSON",
                details={"message_id": message_id},
            )
            continue

        try:
            inserted = aws.put_signal_if_not_exists(
                table_name=SIGNALS_TABLE_NAME,
                signal_item=signal_item,
            )
            if inserted:
                emit_metric(
                    "SignalsCreated",
                    dimensions={
                        "rule_id": str(signal_item.get("rule_id", "unknown")),
                        "severity": str(signal_item.get("severity", "UNKNOWN")),
                    },
                )
        except Exception:
            # put_signal_if_not_exists already logs internally
            # (SIGNAL_INSERT_FAIL). Retryable -- let SQS redeliver
            # rather than dropping it.
            batch_item_failures.append({"itemIdentifier": message_id})

    return {"batchItemFailures": batch_item_failures}

# infra/aws_handler.py

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

import boto3
from boto3.dynamodb.conditions import Attr
from botocore.exceptions import ClientError

from .logger import Logger


def _err_code(e: Exception) -> str:
    if isinstance(e, ClientError):
        return e.response.get("Error", {}).get("Code", "ClientError")
    return type(e).__name__


def _is_conditional_failed(e: Exception) -> bool:
    return isinstance(e, ClientError) and _err_code(e) == "ConditionalCheckFailedException"


@dataclass(frozen=True)
class AwsHandlerConfig:
    service: str = "OPENCDR"
    source: str = "opencdr.processor"
    request_id: str | None = None


class AwsHandler:
    """
    Thin AWS adapter. Do not hide boto3—standardize common correctness patterns.

    Recommended: instantiate once per Lambda invocation:
        logger = Logger(service="OPENCDR", source=LAMBDA_NAME, request_id=context.aws_request_id)
        aws = AwsHandler(logger=logger)
    """

    def __init__(self, *, logger: Logger, region_name: str | None = None) -> None:
        self.logger = logger
        self._session = boto3.session.Session(region_name=region_name)
        self.__ddb = None
        self.__sqs = None
        self.__s3 = None
        self.__ddb_resource = None
        self.__sns = None
        self.__securityhub = None
        self.__ssm = None

    # -------------------------
    # Lazily-constructed boto3 clients (built on first use, not at
    # __init__ — most handlers only ever touch 1-2 of these). Each has a
    # setter purely so tests can inject a fake client the same way they'd
    # assign a plain attribute, e.g. `aws._ddb = MagicMock()`.
    # -------------------------
    @property
    def _ddb(self):
        if self.__ddb is None:
            self.__ddb = self._session.client("dynamodb")
        return self.__ddb

    @_ddb.setter
    def _ddb(self, value):
        self.__ddb = value

    @property
    def _sqs(self):
        if self.__sqs is None:
            self.__sqs = self._session.client("sqs")
        return self.__sqs

    @_sqs.setter
    def _sqs(self, value):
        self.__sqs = value

    @property
    def _s3(self):
        if self.__s3 is None:
            self.__s3 = self._session.client("s3")
        return self.__s3

    @_s3.setter
    def _s3(self, value):
        self.__s3 = value

    @property
    def _ddb_resource(self):
        if self.__ddb_resource is None:
            self.__ddb_resource = self._session.resource("dynamodb")
        return self.__ddb_resource

    @_ddb_resource.setter
    def _ddb_resource(self, value):
        self.__ddb_resource = value

    @property
    def _sns(self):
        if self.__sns is None:
            self.__sns = self._session.client("sns")
        return self.__sns

    @_sns.setter
    def _sns(self, value):
        self.__sns = value

    @property
    def _securityhub(self):
        if self.__securityhub is None:
            self.__securityhub = self._session.client("securityhub")
        return self.__securityhub

    @_securityhub.setter
    def _securityhub(self, value):
        self.__securityhub = value

    @property
    def _ssm(self):
        if self.__ssm is None:
            self.__ssm = self._session.client("ssm")
        return self.__ssm

    @_ssm.setter
    def _ssm(self, value):
        self.__ssm = value

    # -------------------------
    # SSM Parameter Store (settings secrets indirection)
    # -------------------------

    def ssm_get_secure_param(self, *, name: str) -> str | None:
        """
        Reads a SecureString SSM parameter. Returns None if it doesn't
        exist (e.g. deleted out-of-band) rather than raising, so a caller
        can fall back to treating the channel as unconfigured.
        """
        try:
            resp = self._ssm.get_parameter(Name=name, WithDecryption=True)
            return resp["Parameter"]["Value"]
        except ClientError as e:
            if _err_code(e) == "ParameterNotFound":
                return None
            raise

    # -------------------------
    # DynamoDB
    # -------------------------
    def ddb_put_item(
        self,
        *,
        table_name: str,
        item: dict[str, Any],
        log_event_name: str = "DDB_PUT_ITEM",
        details: dict[str, Any] | None = None,
    ) -> None:
        start = time.time()
        try:
            self._ddb.put_item(TableName=table_name, Item=item)
            self.logger.info(
                event_name=log_event_name,
                event_type="STORAGE",
                message=f"PutItem succeeded: {table_name}",
                details={
                    "table": table_name,
                    "latency_ms": int((time.time() - start) * 1000),
                    **(details or {}),
                },
            )
        except Exception as e:
            self.logger.error(
                event_name="DDB_PUT_ITEM_FAILED",
                event_type="STORAGE",
                message=f"PutItem failed: {table_name}",
                details={
                    "table": table_name,
                    "error_code": _err_code(e),
                    "latency_ms": int((time.time() - start) * 1000),
                    **(details or {}),
                },
            )
            raise

    def ddb_put_item_if_absent(
        self,
        *,
        table_name: str,
        item: dict[str, Any],
        id_attribute: str,
        id_value: str,
        success_event_name: str = "DDB_PUT_IF_ABSENT_OK",
        duplicate_event_name: str = "DDB_PUT_IF_ABSENT_DUP",
        failure_event_name: str = "DDB_PUT_IF_ABSENT_FAIL",
        details: dict[str, Any] | None = None,
    ) -> bool:
        """
        Conditional PutItem: insert only if item doesn't exist.
        Returns:
            True  -> inserted (new)
            False -> duplicate (already existed)
        """
        start = time.time()
        try:
            self._ddb.put_item(
                TableName=table_name,
                Item=item,
                ConditionExpression=f"attribute_not_exists({id_attribute})",
            )

            self.logger.info(
                event_name=success_event_name,
                event_type="STORAGE",
                message=f"Inserted new item into {table_name}",
                details={
                    "table": table_name,
                    id_attribute: id_value,
                    "latency_ms": int((time.time() - start) * 1000),
                    **(details or {}),
                },
            )
            return True

        except Exception as e:
            if _is_conditional_failed(e):
                self.logger.info(
                    event_name=duplicate_event_name,
                    event_type="STORAGE",
                    message=f"Duplicate detected in {table_name}; ignoring",
                    details={
                        "table": table_name,
                        id_attribute: id_value,
                        "latency_ms": int((time.time() - start) * 1000),
                        **(details or {}),
                    },
                )
                return False

            self.logger.error(
                event_name=failure_event_name,
                event_type="STORAGE",
                message=f"Conditional PutItem failed for {table_name}",
                details={
                    "table": table_name,
                    id_attribute: id_value,
                    "error_code": _err_code(e),
                    "latency_ms": int((time.time() - start) * 1000),
                    **(details or {}),
                },
            )
            raise

    def ddb_update_item(
        self,
        *,
        table_name: str,
        key: dict[str, Any],
        update_expression: str,
        expr_attr_values: dict[str, Any],
        condition_expression: str | None = None,
        expr_attr_names: dict[str, str] | None = None,
        success_event_name: str = "DDB_UPDATE_OK",
        condition_fail_event_name: str = "DDB_UPDATE_CONDITION_NOT_MET",
        failure_event_name: str = "DDB_UPDATE_FAIL",
        details: dict[str, Any] | None = None,
    ) -> bool:
        """
        UpdateItem with optional ConditionExpression.
        Returns True if updated, False if condition not met.
        """
        start = time.time()
        try:
            kwargs: dict[str, Any] = {
                "TableName": table_name,
                "Key": key,
                "UpdateExpression": update_expression,
                "ExpressionAttributeValues": expr_attr_values,
                "ReturnValues": "NONE",
            }
            if condition_expression:
                kwargs["ConditionExpression"] = condition_expression
            if expr_attr_names:
                kwargs["ExpressionAttributeNames"] = expr_attr_names

            self._ddb.update_item(**kwargs)

            self.logger.info(
                event_name=success_event_name,
                event_type="STORAGE",
                message=f"UpdateItem succeeded: {table_name}",
                details={
                    "table": table_name,
                    "latency_ms": int((time.time() - start) * 1000),
                    **(details or {}),
                },
            )
            return True

        except Exception as e:
            if _is_conditional_failed(e):
                self.logger.info(
                    event_name=condition_fail_event_name,
                    event_type="STORAGE",
                    message=f"UpdateItem condition not met: {table_name}",
                    details={
                        "table": table_name,
                        "latency_ms": int((time.time() - start) * 1000),
                        **(details or {}),
                    },
                )
                return False

            self.logger.error(
                event_name=failure_event_name,
                event_type="STORAGE",
                message=f"UpdateItem failed: {table_name}",
                details={
                    "table": table_name,
                    "error_code": _err_code(e),
                    "latency_ms": int((time.time() - start) * 1000),
                    **(details or {}),
                },
            )
            raise

    def ddb_transact_write(
        self,
        *,
        transact_items: list[dict[str, Any]],
        success_event_name: str = "DDB_TXN_OK",
        failure_event_name: str = "DDB_TXN_FAIL",
        details: dict[str, Any] | None = None,
    ) -> None:
        start = time.time()
        try:
            self._ddb.transact_write_items(TransactItems=transact_items)  # type: ignore[arg-type]
            self.logger.info(
                event_name=success_event_name,
                event_type="STORAGE",
                message="DynamoDB transaction succeeded",
                details={
                    "items": len(transact_items),
                    "latency_ms": int((time.time() - start) * 1000),
                    **(details or {}),
                },
            )
        except Exception as e:
            self.logger.error(
                event_name=failure_event_name,
                event_type="STORAGE",
                message="DynamoDB transaction failed",
                details={
                    "items": len(transact_items),
                    "error_code": _err_code(e),
                    "latency_ms": int((time.time() - start) * 1000),
                    **(details or {}),
                },
            )
            raise

    def ddb_get_item_simple(
        self,
        *,
        table_name: str,
        key: dict[str, Any],
        consistent_read: bool = False,
    ) -> dict[str, Any] | None:
        """
        Low-level DynamoDB GetItem wrapper.
        `key` must be marshalled (AttributeValue dict), e.g.:
          {"setting_id": {"S": "global"}}
        Returns the raw DynamoDB item (marshalled) or None.
        """
        if not table_name:
            return None

        resp = self._ddb.get_item(
            TableName=table_name,
            Key=key,
            ConsistentRead=consistent_read,
        )
        return resp.get("Item")

    # -------------------------
    # SQS
    # -------------------------
    def sqs_send(
        self,
        *,
        queue_url: str,
        body: dict[str, Any],
        attributes: dict[str, str] | None = None,
        success_event_name: str = "SQS_SEND_OK",
        failure_event_name: str = "SQS_SEND_FAIL",
        details: dict[str, Any] | None = None,
    ) -> str:
        """
        Sends message to SQS. Returns MessageId.
        Adds consistent attributes (request_id/producer) via MessageAttributes.
        """
        start = time.time()

        msg_attrs: dict[str, Any] = {}
        # Correlation fields
        if getattr(self.logger, "request_id", None):
            msg_attrs["request_id"] = {"DataType": "String", "StringValue": self.logger.request_id}
        msg_attrs["producer"] = {
            "DataType": "String",
            "StringValue": getattr(self.logger, "source", "unknown"),
        }

        if attributes:
            for k, v in attributes.items():
                msg_attrs[k] = {"DataType": "String", "StringValue": str(v)}

        try:
            resp = self._sqs.send_message(
                QueueUrl=queue_url,
                MessageBody=json.dumps(body),
                MessageAttributes=msg_attrs,
            )
            msg_id = resp.get("MessageId", "")

            self.logger.info(
                event_name=success_event_name,
                event_type="QUEUE",
                message="Sent message to SQS",
                details={
                    "queue_url": queue_url,
                    "message_id": msg_id,
                    "latency_ms": int((time.time() - start) * 1000),
                    **(details or {}),
                },
            )
            return msg_id

        except Exception as e:
            self.logger.error(
                event_name=failure_event_name,
                event_type="QUEUE",
                message="Failed to send message to SQS",
                details={
                    "queue_url": queue_url,
                    "error_code": _err_code(e),
                    "latency_ms": int((time.time() - start) * 1000),
                    **(details or {}),
                },
            )
            raise

    # -------------------------
    # S3 (optional helpers)
    # -------------------------
    def s3_put_json(
        self,
        *,
        bucket: str,
        key: str,
        payload: dict[str, Any],
        success_event_name: str = "S3_PUT_OK",
        failure_event_name: str = "S3_PUT_FAIL",
        details: dict[str, Any] | None = None,
    ) -> None:
        start = time.time()
        try:
            self._s3.put_object(
                Bucket=bucket,
                Key=key,
                Body=json.dumps(payload).encode("utf-8"),
                ContentType="application/json",
            )
            self.logger.info(
                event_name=success_event_name,
                event_type="STORAGE",
                message="Stored JSON in S3",
                details={
                    "bucket": bucket,
                    "key": key,
                    "latency_ms": int((time.time() - start) * 1000),
                    **(details or {}),
                },
            )
        except Exception as e:
            self.logger.error(
                event_name=failure_event_name,
                event_type="STORAGE",
                message="Failed to store JSON in S3",
                details={
                    "bucket": bucket,
                    "key": key,
                    "error_code": _err_code(e),
                    "latency_ms": int((time.time() - start) * 1000),
                    **(details or {}),
                },
            )
            raise

    # ==========================================================
    # DOMAIN OPERATIONS (USED BY PROCESSOR / PUBLISHER)
    # ==========================================================

    # NOTE:
    # These methods sit above raw DynamoDB primitives.
    # They encapsulate table schema + reliability guarantees.
    # This keeps lambdas simple and infra logic centralized.

    # -------------------------
    # Detection Signals
    # -------------------------

    def put_signal_if_not_exists(
        self,
        *,
        table_name: str,
        signal_item: dict,
        id_attribute: str = "detection_id",
    ) -> bool:
        signal_id = signal_item.get(id_attribute)
        return self.ddb_put_item_if_absent_resource(
            table_name=table_name,
            item=signal_item,
            id_attribute=id_attribute,
            id_value=str(signal_id),
            success_event_name="SIGNAL_INSERTED",
            duplicate_event_name="SIGNAL_DUPLICATE",
            failure_event_name="SIGNAL_INSERT_FAIL",
        )

    # -------------------------
    # Outbox Pattern
    # -------------------------

    def put_outbox_record(
        self,
        *,
        table_name: str,
        payload: dict,
        destinations: list[str],
        outbox_id: str | None = None,
    ) -> str:
        """
        Creates outbox record for publisher pipeline.

        Publisher lambda consumes DynamoDB stream.
        """
        import uuid as _uuid
        from datetime import UTC as _UTC, datetime as _datetime

        if not outbox_id:
            outbox_id = str(_uuid.uuid4())

        item = {
            "outbox_id": {"S": outbox_id},
            "timestamp": {"S": _datetime.now(_UTC).isoformat()},
            "status": {"S": "PENDING"},
            "payload": {"S": json.dumps(payload)},
            # JSON string so publisher's _extract_destinations can parse it as a list
            "destinations": {"S": json.dumps(destinations)},
            "attempts": {"N": "0"},
        }

        self.ddb_put_item(
            table_name=table_name,
            item=item,
            log_event_name="OUTBOX_CREATED",
        )

        return outbox_id

    def put_alert_if_not_exists(
        self,
        *,
        table_name: str,
        alert_item: dict,
        id_attribute: str = "alert_key",
        success_event_name: str = "ALERT_INSERTED",
        duplicate_event_name: str = "ALERT_DUPLICATE",
        failure_event_name: str = "ALERT_INSERT_FAIL",
        details: dict[str, Any] | None = None,
    ) -> bool:
        """
        Idempotent alert write using the high-level resource API.
        Returns True if inserted (new), False if duplicate.
        """
        alert_id = alert_item.get(id_attribute)
        return self.ddb_put_item_if_absent_resource(
            table_name=table_name,
            item=alert_item,
            id_attribute=id_attribute,
            id_value=str(alert_id),
            success_event_name=success_event_name,
            duplicate_event_name=duplicate_event_name,
            failure_event_name=failure_event_name,
            details=details,
        )

    def ddb_put_item_if_absent_resource(
        self,
        *,
        table_name: str,
        item: dict[str, Any],
        id_attribute: str,
        id_value: str,
        success_event_name: str = "DDB_PUT_IF_ABSENT_OK",
        duplicate_event_name: str = "DDB_PUT_IF_ABSENT_DUP",
        failure_event_name: str = "DDB_PUT_IF_ABSENT_FAIL",
        details: dict[str, Any] | None = None,
    ) -> bool:
        start = time.time()
        table = self._ddb_resource.Table(table_name)
        try:
            table.put_item(
                Item=item,
                ConditionExpression=Attr(id_attribute).not_exists(),
            )
            self.logger.info(
                event_name=success_event_name,
                event_type="STORAGE",
                message=f"Inserted new item into {table_name}",
                details={
                    "table": table_name,
                    id_attribute: id_value,
                    "latency_ms": int((time.time() - start) * 1000),
                    **(details or {}),
                },
            )
            return True
        except Exception as e:
            if _is_conditional_failed(e):
                self.logger.info(
                    event_name=duplicate_event_name,
                    event_type="STORAGE",
                    message=f"Duplicate detected in {table_name}; ignoring",
                    details={
                        "table": table_name,
                        id_attribute: id_value,
                        "latency_ms": int((time.time() - start) * 1000),
                        **(details or {}),
                    },
                )
                return False

            self.logger.error(
                event_name=failure_event_name,
                event_type="STORAGE",
                message=f"Conditional PutItem failed for {table_name}",
                details={
                    "table": table_name,
                    id_attribute: id_value,
                    "error_code": _err_code(e),
                    "latency_ms": int((time.time() - start) * 1000),
                    **(details or {}),
                },
            )
            raise

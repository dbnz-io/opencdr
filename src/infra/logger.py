# logger.py

import json
import os
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import boto3

from ..config.requirements import ALLOWED_EVENT_TYPES
from .partition_keys import day_bucket_key

_logs_table = None

# Optional, off by default: narrow which levels actually get persisted to
# DynamoDB (CloudWatch still gets every line via the print() below,
# regardless). Unset means "store everything" -- today's behavior,
# unchanged -- since GET /logs already only supports targeted GSI Query
# lookups, never a full scan (see docs/data-archival.md), storing
# everything isn't itself a correctness problem, just a cost one some
# deployments may want to opt into trimming. Every log line is archived
# to S3 first regardless of what's persisted to DynamoDB (see
# src/handlers/archiver.py) -- narrowing this only affects what's
# queryable live via the API, never what's retained for investigation.
_LEVEL_ORDER = {"INFO": 0, "WARNING": 1, "ERROR": 2}


def _should_store_in_dynamodb(level: str) -> bool:
    min_level = os.environ.get("LOGS_MIN_LEVEL_TO_STORE", "").upper()
    if min_level not in _LEVEL_ORDER:
        return True
    return _LEVEL_ORDER.get(level, 0) >= _LEVEL_ORDER[min_level]


def _ttl_expires_at() -> int:
    # Duplicated from aws_handler.ttl_expires_at rather than imported --
    # aws_handler.py itself imports Logger from this module, so importing
    # back would be circular. Same DYNAMODB_TTL_DAYS env var, same math.
    days = int(os.environ.get("DYNAMODB_TTL_DAYS", "90"))
    return int((datetime.now(UTC) + timedelta(days=days)).timestamp())


def _get_logs_table():
    """
    Lazily resolves the logs table on first use rather than at import time,
    so a missing LOGS_TABLE_NAME surfaces as a handled runtime error (caught
    in Logger._log, after the log line already reached stdout/CloudWatch)
    instead of crashing every handler's cold start via the import chain.
    """
    global _logs_table
    if _logs_table is None:
        table_name = os.getenv("LOGS_TABLE_NAME")
        if not table_name:
            raise RuntimeError("LOGS_TABLE_NAME env var not set")
        _logs_table = boto3.resource("dynamodb").Table(table_name)
    return _logs_table


class Logger:
    """
    Structured logger for OpenCDR.

    Responsibilities:
    - structured audit logs (DynamoDB)
    - context binding (service, source, request_id, etc.)
    - consistent schema
    - stdout logging for Lambda
    - correlation propagation (future-safe)

    NOT a full logging framework.
    """

    def __init__(
        self,
        *,
        service: str = "OPENCDR",
        source: str | None = None,
        request_id: str | None = None,
        correlation_id: str | None = None,
        signal_id: str | None = None,
        execution_id: str | None = None,
        source_ip: str | None = None,
        user_agent: str | None = None,
        user_name: str | None = None,
        event_id: str | None = None,
    ):
        self.service = service
        self.source = source or "opencdr.processor"
        self.request_id = request_id
        self.correlation_id = correlation_id
        self.signal_id = signal_id
        self.execution_id = execution_id
        self.source_ip = source_ip
        self.user_agent = user_agent
        self.user_name = user_name
        self.event_id = event_id

    # ------------------------------------------------
    # Context helpers
    # ------------------------------------------------

    def bind(self, **kwargs) -> "Logger":
        """
        Returns a new logger with additional context.

        Example:
            child = logger.bind(signal_id="abc")
        """
        data = {
            "service": self.service,
            "source": self.source,
            "request_id": self.request_id,
            "correlation_id": self.correlation_id,
            "signal_id": self.signal_id,
            "execution_id": self.execution_id,
            "source_ip": self.source_ip,
            "user_agent": self.user_agent,
            "user_name": self.user_name,
            **({"event_id": self.event_id} if self.event_id else {}),
        }

        data.update(kwargs)
        return Logger(**data)

    # ------------------------------------------------
    # Public logging methods
    # ------------------------------------------------

    def info(self, event_name: str, message: str, **kwargs):
        self._log("INFO", event_name=event_name, message=message, **kwargs)

    def warning(self, event_name: str, message: str, **kwargs):
        self._log("WARNING", event_name=event_name, message=message, **kwargs)

    def error(self, event_name: str, message: str, **kwargs):
        self._log("ERROR", event_name=event_name, message=message, **kwargs)

    def audit(self, event_name: str, message: str, **kwargs):
        """
        Explicit audit log alias (same as info but semantic clarity).
        """
        self._log("INFO", event_name=event_name, message=message, **kwargs)

    # ------------------------------------------------
    # Core log method
    # ------------------------------------------------

    def _log(
        self,
        level: str,
        *,
        event_name: str,
        message: str,
        event_type: str = "SYSTEM",
        method: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        timestamp = datetime.now(UTC).isoformat()

        base_details = details.copy() if details else {}

        # inject context automatically
        if self.request_id:
            base_details["request_id"] = self.request_id

        if self.correlation_id:
            base_details["correlation_id"] = self.correlation_id

        if self.signal_id:
            base_details["signal_id"] = self.signal_id

        if self.execution_id:
            base_details["execution_id"] = self.execution_id

        # enforce allowed event types
        if event_type not in ALLOWED_EVENT_TYPES:
            base_details["original_event_type"] = event_type
            event_type = "SYSTEM"

        merged_details = {
            "level": level,
            "message": message,
            **base_details,
        }

        event_id_value = self.event_id
        if event_id_value is not None:
            event_id_value = str(event_id_value).strip()
            if event_id_value == "":
                event_id_value = None

        log_item: dict[str, Any] = {
            "log_id": str(uuid.uuid4()),
            "timestamp": timestamp,
            "source": self.source,
            "event_type": event_type,
            "event_name": event_name,
            "source_ip": self.source_ip,
            "user_agent": self.user_agent,
            "method": method,
            "user_name": self.user_name,
            "details": merged_details,
            "service": self.service,
            # logs-table-v2's actual HASH key -- a separate attribute
            # from `service`, so `service` stays clean for archiver.py's
            # flatten_log and the S3/Athena archive.
            "service_bucket": day_bucket_key(self.service, timestamp),
            "expires_at": _ttl_expires_at(),
        }

        # Only include event_id if it's a real string
        if event_id_value is not None:
            log_item["event_id"] = event_id_value

        # Always print to stdout (Lambda logging)
        print(json.dumps(log_item, default=str))

        if not _should_store_in_dynamodb(level):
            return

        # Write audit record to DynamoDB
        try:
            _get_logs_table().put_item(Item=log_item)
        except Exception as e:
            print("Failed to write log entry:", repr(e))
            print("Log item that failed:", json.dumps(log_item, indent=2))

    # ------------------------------------------------
    # Convenience helpers (optional patterns)
    # ------------------------------------------------

    def exception(self, event_name: str, error: Exception, **kwargs):
        """
        Logs exception with traceback info.
        """
        self._log(
            "ERROR",
            event_name=event_name,
            message=str(error),
            details={
                "error_type": type(error).__name__,
                "error": repr(error),
                **kwargs.get("details", {}),
            },
        )

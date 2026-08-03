import json
import uuid
from datetime import UTC, datetime
from typing import Any

from .config.requirements import ALLOWED_EVENT_TYPES
from .infra.logger import logs_table


def log_operation(
    *,
    level: str,
    event_type: str,
    event_name: str,
    message: str,
    service: str | None = "OPENCDR",
    source: str | None = None,
    source_ip: str | None = None,
    user_agent: str | None = None,
    method: str | None = None,
    user_name: str | None = None,
    details: dict | None = None,
) -> None:
    timestamp = datetime.now(UTC).isoformat()

    base_details = details.copy() if details else {}

    if event_type not in ALLOWED_EVENT_TYPES:
        base_details["original_event_type"] = event_type
        event_type = "SYSTEM"

    merged_details = {
        "level": level,
        "message": message,
    }
    merged_details.update(base_details)

    log_item: dict[str, Any] = {
        "log_id": str(uuid.uuid4()),
        "timestamp": timestamp,
        "source": source or "opencdr.processor",
        "event_type": event_type,
        "event_name": event_name,
        "source_ip": source_ip,
        "user_agent": user_agent,
        "method": method,
        "user_name": user_name,
        "details": merged_details,
        "service": service,
    }

    try:
        logs_table.put_item(Item=log_item)
    except Exception as e:
        print("Failed to write log entry:", repr(e))
        print("Log item that failed:", json.dumps(log_item, indent=2))

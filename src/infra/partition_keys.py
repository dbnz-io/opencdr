"""
Composite day-bucketed DynamoDB partition keys for signals-table-v2 /
logs-table-v2 (severity_bucket / service_bucket) -- see
docs/architecture.md and docs/data-archival.md for why the base tables
moved off a bare low-cardinality severity/service hash key.

Zero internal dependencies deliberately -- both src/infra/aws_handler.py
and src/infra/logger.py need this, and aws_handler.py imports Logger
from logger.py, so anything logger.py imports back from aws_handler.py
would be circular. Keeping this module stdlib-only sidesteps that.
"""

from __future__ import annotations

from datetime import UTC, datetime


def day_bucket_key(prefix_value: str | None, timestamp_iso: str | None) -> str:
    """
    f"{prefix_value}#{YYYY-MM-DD}" -- always derived from the item's OWN
    timestamp (never wall-clock "now"), matching
    src/handlers/archiver.py's partition_fields() day-bucketing
    convention, so a late-arriving/reprocessed item lands in the bucket
    for its actual event date. Falls back to "now" on a malformed or
    missing timestamp -- a partition-key problem must never be able to
    block a write outright.
    """
    try:
        dt = datetime.fromisoformat((timestamp_iso or "").replace("Z", "+00:00"))
    except (ValueError, TypeError):
        dt = datetime.now(UTC)
    return f"{str(prefix_value or 'UNKNOWN')}#{dt.strftime('%Y-%m-%d')}"

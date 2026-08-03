"""Tests for the real (non-legacy) account-extraction paths in
_extract_account_id (src/handlers/responder.py).

Found while designing multi-account IR role selection: the responder's
detection_event never actually has "aws_account_id" or "raw_event" at the
top level for real detections -- those are only exercised by hand-crafted
test/legacy events (see tests/handlers/test_responder.py::TestExtractAccountId).
Real payloads look like:

  - signal-level (processor.py's alert_item, src/handlers/processor.py:175-193):
    flat dict with a top-level "cloud_account_id".
  - correlation-level (correlation_engine.py's alert, correlation_engine.py:440-458):
    no top-level account field at all -- it's nested under
    "primary_signal.cloud_account_id" (a _signal_snapshot, correlation_engine.py:340-397),
    with "primary_signal.raw_event_min.account" as a further fallback.

publisher.py forwards the outbox payload to SQS verbatim (body=payload), and
responder._process_record uses it directly (there's no "detection_event"
wrapper key in either real shape) -- so these are exactly the dicts
_extract_account_id receives in production.
"""
from __future__ import annotations

import os

os.environ.setdefault("LOGS_TABLE_NAME", "test-logs-table")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

from src.handlers import responder


class TestSignalLevelShape:
    def test_top_level_cloud_account_id(self):
        event = {"cloud_account_id": "111111111111", "response_module": "disable_user"}
        assert responder._extract_account_id(event) == "111111111111"

    def test_empty_string_is_treated_as_missing(self):
        event = {"cloud_account_id": ""}
        assert responder._extract_account_id(event) is None


class TestCorrelationLevelShape:
    def test_primary_signal_cloud_account_id(self):
        event = {
            "type": "correlation",
            "primary_signal": {"cloud_account_id": "222222222222"},
        }
        assert responder._extract_account_id(event) == "222222222222"

    def test_falls_back_to_raw_event_min_account(self):
        event = {
            "type": "correlation",
            "primary_signal": {
                "cloud_account_id": "",
                "raw_event_min": {"account": "333333333333"},
            },
        }
        assert responder._extract_account_id(event) == "333333333333"

    def test_no_account_anywhere_returns_none(self):
        event = {"type": "correlation", "primary_signal": {"cloud_account_id": ""}}
        assert responder._extract_account_id(event) is None

    def test_missing_primary_signal_falls_through_safely(self):
        event = {"type": "correlation"}
        assert responder._extract_account_id(event) is None


class TestPriorityOrder:
    def test_top_level_cloud_account_id_wins_over_primary_signal(self):
        event = {
            "cloud_account_id": "111111111111",
            "primary_signal": {"cloud_account_id": "222222222222"},
        }
        assert responder._extract_account_id(event) == "111111111111"

    def test_real_shapes_win_over_legacy_fallbacks(self):
        event = {
            "cloud_account_id": "111111111111",
            "aws_account_id": "999999999999",
            "raw_event": {"account": "888888888888"},
        }
        assert responder._extract_account_id(event) == "111111111111"

    def test_legacy_fallback_still_used_when_no_real_shape_present(self):
        # Confirms the fix doesn't regress hand-crafted/legacy test events.
        event = {"aws_account_id": "444444444444"}
        assert responder._extract_account_id(event) == "444444444444"

"""Tests for the rule/list-cache TTL fix (Phase 1: "rule edits have no
reliable time-to-effect"). RULES_CACHE/LISTS_CACHE (processor.py) and
CORR_RULES_CACHE (alerter.py) previously cached forever once loaded; both
now expire after a TTL, same pattern as notifier.py's settings cache.
"""
from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

os.environ.setdefault("LOGS_TABLE_NAME", "test-logs-table")
os.environ.setdefault("SIGNALS_TABLE_NAME", "test-signals-table")
os.environ.setdefault("ALERTS_TABLE_NAME", "test-alerts-table")
os.environ.setdefault("OUTBOX_TABLE_NAME", "test-outbox-table")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

from src.handlers import alerter, processor


class TestProcessorRulesCacheExpiry:
    def setup_method(self):
        processor.RULES_CACHE = None
        processor.RULES_CACHE_LOADED_AT = 0.0
        processor.LISTS_CACHE = None
        processor.LISTS_CACHE_LOADED_AT = 0.0

    def teardown_method(self):
        processor.RULES_CACHE = None
        processor.RULES_CACHE_LOADED_AT = 0.0
        processor.LISTS_CACHE = None
        processor.LISTS_CACHE_LOADED_AT = 0.0

    def test_get_rules_reloads_after_ttl_expires(self, monkeypatch):
        logger = MagicMock()
        aws = MagicMock()
        monkeypatch.setattr(processor, "RULES_TTL_SECONDS", 60)

        with patch("src.handlers.processor.load_detection_rules", return_value=[{"rule_id": "r1"}]) as load_rules:
            with patch("src.handlers.processor.time.time", return_value=1000.0):
                processor.get_rules(aws, logger)
            with patch("src.handlers.processor.time.time", return_value=1030.0):
                processor.get_rules(aws, logger)  # still within TTL
            with patch("src.handlers.processor.time.time", return_value=1061.0):
                processor.get_rules(aws, logger)  # TTL elapsed

        assert load_rules.call_count == 2

    def test_get_lists_reloads_after_ttl_expires(self, monkeypatch):
        logger = MagicMock()
        aws = MagicMock()
        monkeypatch.setattr(processor, "RULES_TTL_SECONDS", 60)
        raw = [{"rule_id": "blocklist", "values": ["1.2.3.4"]}]

        with patch("src.handlers.processor.load_detection_rules", return_value=raw) as load_rules:
            with patch("src.handlers.processor.time.time", return_value=1000.0):
                processor.get_lists(aws, logger)
            with patch("src.handlers.processor.time.time", return_value=1061.0):
                processor.get_lists(aws, logger)

        assert load_rules.call_count == 2


class TestAlerterCorrRulesCacheExpiry:
    def setup_method(self):
        alerter.CORR_RULES_CACHE = None
        alerter.CORR_RULES_CACHE_LOADED_AT = 0.0

    def teardown_method(self):
        alerter.CORR_RULES_CACHE = None
        alerter.CORR_RULES_CACHE_LOADED_AT = 0.0

    def test_reloads_after_ttl_expires(self, monkeypatch):
        logger = MagicMock()
        aws = MagicMock()
        monkeypatch.setattr(alerter, "CORR_RULES_TTL_SECONDS", 60)

        with patch("src.handlers.alerter.load_detection_rules", return_value=[{"rule_id": "c1"}]) as load_rules:
            with patch("src.handlers.alerter.time.time", return_value=1000.0):
                alerter.get_correlation_rules(aws=aws, logger=logger)
            with patch("src.handlers.alerter.time.time", return_value=1030.0):
                alerter.get_correlation_rules(aws=aws, logger=logger)  # still within TTL
            with patch("src.handlers.alerter.time.time", return_value=1061.0):
                alerter.get_correlation_rules(aws=aws, logger=logger)  # TTL elapsed

        assert load_rules.call_count == 2

    def test_within_ttl_reuses_cache(self, monkeypatch):
        logger = MagicMock()
        aws = MagicMock()
        monkeypatch.setattr(alerter, "CORR_RULES_TTL_SECONDS", 60)

        with patch("src.handlers.alerter.load_detection_rules", return_value=[{"rule_id": "c1"}]) as load_rules:
            with patch("src.handlers.alerter.time.time", return_value=1000.0):
                first = alerter.get_correlation_rules(aws=aws, logger=logger)
            with patch("src.handlers.alerter.time.time", return_value=1010.0):
                second = alerter.get_correlation_rules(aws=aws, logger=logger)

        assert first is second
        load_rules.assert_called_once()

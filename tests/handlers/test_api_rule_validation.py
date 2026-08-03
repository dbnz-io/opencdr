"""Tests for the semantic rule-mutation validation added to
_normalize_rule_payload (src/handlers/api.py): regex-compile checks for
matches/not_matches conditions, and sanity bounds for correlation rules'
threshold/time_window_seconds. Neither existed before -- confirmed absent
from both this function and CI's rule validation
(.github/workflows/ci.yml only checks JSON syntax + required fields).
"""
from __future__ import annotations

import os

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

import pytest

from src.handlers import api


class TestRegexConditionValidation:
    def test_valid_regex_is_accepted(self):
        payload = {
            "rule_kind": "signal",
            "conditions": [{"field": "user_agent", "op": "matches", "value": r"^curl/.*"}],
        }
        out = api._normalize_rule_payload(payload, force_rule_id=None)
        assert out["conditions"][0]["value"] == r"^curl/.*"

    def test_invalid_regex_in_matches_is_rejected(self):
        payload = {
            "rule_kind": "signal",
            "conditions": [{"field": "user_agent", "op": "matches", "value": "(unclosed["}],
        }
        with pytest.raises(ValueError, match="not a valid regex"):
            api._normalize_rule_payload(payload, force_rule_id=None)

    def test_invalid_regex_in_not_matches_is_rejected(self):
        payload = {
            "rule_kind": "signal",
            "conditions": [{"field": "user_agent", "op": "not_matches", "value": "[invalid"}],
        }
        with pytest.raises(ValueError, match="not a valid regex"):
            api._normalize_rule_payload(payload, force_rule_id=None)

    def test_non_string_regex_value_is_rejected_not_500(self):
        payload = {
            "rule_kind": "signal",
            "conditions": [{"field": "user_agent", "op": "matches", "value": 123}],
        }
        with pytest.raises(ValueError, match="not a valid regex"):
            api._normalize_rule_payload(payload, force_rule_id=None)

    def test_non_regex_ops_unaffected(self):
        payload = {
            "rule_kind": "signal",
            "conditions": [{"field": "activity_name", "op": "equals", "value": "ConsoleLogin"}],
        }
        out = api._normalize_rule_payload(payload, force_rule_id=None)
        assert out["conditions"][0]["value"] == "ConsoleLogin"


class TestCorrelationThresholdBounds:
    def _payload(self, **overrides):
        payload = {"rule_kind": "correlation", "conditions": []}
        payload.update(overrides)
        return payload

    def test_valid_threshold_and_window_accepted(self):
        out = api._normalize_rule_payload(
            self._payload(threshold=5, time_window_seconds=300), force_rule_id=None
        )
        assert out["threshold"] == 5
        assert out["time_window_seconds"] == 300

    def test_threshold_below_minimum_rejected(self):
        with pytest.raises(ValueError, match="threshold must be between"):
            api._normalize_rule_payload(self._payload(threshold=0), force_rule_id=None)

    def test_threshold_above_maximum_rejected(self):
        with pytest.raises(ValueError, match="threshold must be between"):
            api._normalize_rule_payload(self._payload(threshold=100000), force_rule_id=None)

    def test_non_integer_threshold_rejected(self):
        with pytest.raises(ValueError, match="threshold must be an integer"):
            api._normalize_rule_payload(self._payload(threshold="not-a-number"), force_rule_id=None)

    def test_time_window_seconds_below_minimum_rejected(self):
        with pytest.raises(ValueError, match="time_window_seconds must be between"):
            api._normalize_rule_payload(self._payload(time_window_seconds=0), force_rule_id=None)

    def test_time_window_seconds_above_maximum_rejected(self):
        with pytest.raises(ValueError, match="time_window_seconds must be between"):
            api._normalize_rule_payload(self._payload(time_window_seconds=999999), force_rule_id=None)

    def test_bounds_not_enforced_for_signal_rules(self):
        # threshold/time_window_seconds are correlation-only concepts;
        # a signal rule carrying a bogus value in those fields isn't this
        # validation's concern.
        out = api._normalize_rule_payload(
            {"rule_kind": "signal", "conditions": [], "threshold": -999}, force_rule_id=None
        )
        assert out["threshold"] == -999

    def test_missing_threshold_and_window_use_engine_defaults_untouched(self):
        out = api._normalize_rule_payload(self._payload(), force_rule_id=None)
        assert "threshold" not in out
        assert "time_window_seconds" not in out

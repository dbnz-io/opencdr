"""Tests for src/infra/metrics.py (CloudWatch EMF emission)."""
from __future__ import annotations

import json

from src.infra.metrics import emit_metric


def _captured_payload(capsys) -> dict:
    out = capsys.readouterr().out.strip()
    return json.loads(out)


class TestEmitMetric:
    def test_emits_valid_emf_shape_with_dimensions(self, capsys):
        emit_metric("SignalsCreated", dimensions={"rule_id": "001", "severity": "HIGH"})

        payload = _captured_payload(capsys)
        assert payload["_aws"]["CloudWatchMetrics"][0]["Namespace"] == "OpenCDR"
        assert payload["_aws"]["CloudWatchMetrics"][0]["Dimensions"] == [["rule_id", "severity"]]
        assert payload["_aws"]["CloudWatchMetrics"][0]["Metrics"] == [
            {"Name": "SignalsCreated", "Unit": "Count"}
        ]
        # Dimension keys/values and the metric itself must be top-level
        # members per the EMF spec, not nested under _aws.
        assert payload["rule_id"] == "001"
        assert payload["severity"] == "HIGH"
        assert payload["SignalsCreated"] == 1

    def test_timestamp_is_integer_milliseconds(self, capsys):
        emit_metric("X")
        payload = _captured_payload(capsys)
        assert isinstance(payload["_aws"]["Timestamp"], int)
        assert payload["_aws"]["Timestamp"] > 1_700_000_000_000  # sanity: ms since epoch, not seconds

    def test_no_dimensions_produces_one_empty_dimension_set(self, capsys):
        emit_metric("PublishSuccess")
        payload = _captured_payload(capsys)
        assert payload["_aws"]["CloudWatchMetrics"][0]["Dimensions"] == [[]]

    def test_custom_value_and_unit(self, capsys):
        emit_metric("Latency", value=42.5, unit="Milliseconds")
        payload = _captured_payload(capsys)
        assert payload["Latency"] == 42.5
        assert payload["_aws"]["CloudWatchMetrics"][0]["Metrics"][0]["Unit"] == "Milliseconds"

    def test_never_raises_on_a_genuinely_unserializable_dimension(self, capsys):
        class ExplodesOnStr:
            def __str__(self):
                raise RuntimeError("can't stringify this")

        # json.dumps(..., default=str) calls str() on anything it can't
        # natively serialize -- if that itself raises, dumps raises too.
        # Must not propagate into the caller either way.
        emit_metric("X", dimensions={"weird": ExplodesOnStr()})  # type: ignore[dict-item]

        assert "METRIC_EMIT_FAILED" in capsys.readouterr().out

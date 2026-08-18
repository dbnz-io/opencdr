"""Tests for _request_parameters and the four extractors that now go
through it (_extract_role_name, _extract_bucket_name, _extract_bucket_and_key,
_extract_instance_ids), plus _detection_error_code and the structural
failed-API-call backstop in _process_record.

INFORME-AUTOR-ES.md §1.1 found this exact bug in _extract_user_name (fixed,
see the golden-path pipeline test and TestExtractUserName in
test_responder.py); the report explicitly flagged these four as having the
identical shape of bug -- reading raw_event.detail.requestParameters, which
a correlation alert never has, with no fallback to
primary_signal.raw_event_min.detail.requestParameters, which it does.
"""
from unittest.mock import MagicMock

from src.handlers import responder

CORRELATION_ALERT_TEMPLATE = {
    "group_by": "actor.user_name",
    "group_value": "attacker",
    "primary_signal": {
        "actor": {"user_name": "attacker"},
        "raw_event_min": {
            "detail": {
                "requestParameters": {
                    "roleName": "victim-role",
                    "bucketName": "victim-bucket",
                    "key": "secrets.txt",
                    "instancesSet": [{"instanceId": "i-0correlation1"}],
                }
            }
        },
    },
}


class TestRequestParameters:
    def test_signal_shape_wins_when_present(self):
        event = {"raw_event": {"detail": {"requestParameters": {"roleName": "signal-role"}}}}
        assert responder._request_parameters(event) == {"roleName": "signal-role"}

    def test_falls_back_to_correlation_shape(self):
        req = responder._request_parameters(CORRELATION_ALERT_TEMPLATE)
        assert req["roleName"] == "victim-role"
        assert req["bucketName"] == "victim-bucket"

    def test_missing_everything_returns_empty_dict(self):
        assert responder._request_parameters({}) == {}

    def test_non_dict_raw_event_falls_through_safely(self):
        event = {"raw_event": "not-a-dict", **CORRELATION_ALERT_TEMPLATE}
        req = responder._request_parameters(event)
        assert req["roleName"] == "victim-role"


class TestExtractRoleNameCorrelation:
    def test_resolves_from_correlation_alert(self):
        assert responder._extract_role_name(CORRELATION_ALERT_TEMPLATE) == "victim-role"

    def test_target_value_still_wins_first(self):
        event = {"target_value": "explicit-role", **CORRELATION_ALERT_TEMPLATE}
        assert responder._extract_role_name(event) == "explicit-role"


class TestExtractBucketNameCorrelation:
    def test_resolves_from_correlation_alert(self):
        assert responder._extract_bucket_name(CORRELATION_ALERT_TEMPLATE) == "victim-bucket"


class TestExtractBucketAndKeyCorrelation:
    def test_resolves_bucket_and_key_from_correlation_alert(self):
        bucket, key = responder._extract_bucket_and_key(CORRELATION_ALERT_TEMPLATE)
        assert bucket == "victim-bucket"
        assert key == "secrets.txt"


class TestExtractInstanceIdsCorrelation:
    def test_resolves_from_correlation_alert(self):
        assert responder._extract_instance_ids(CORRELATION_ALERT_TEMPLATE) == ["i-0correlation1"]


class TestDetectionErrorCode:
    def test_signal_shape_error_code(self):
        event = {"api": {"error_code": "AccessDenied"}}
        assert responder._detection_error_code(event) == "AccessDenied"

    def test_signal_shape_no_error_code_returns_none(self):
        assert responder._detection_error_code({"api": {"error_code": None}}) is None

    def test_correlation_shape_error_code(self):
        event = {"primary_signal": {"api": {"error_code": "AccessDenied"}}}
        assert responder._detection_error_code(event) == "AccessDenied"

    def test_missing_everything_returns_none(self):
        assert responder._detection_error_code({}) is None


def _sqs_record(body_obj) -> dict:
    import json

    return {"body": json.dumps(body_obj), "receiptHandle": "rh-backstop"}


class TestFailedApiCallBackstop:
    """The structural backstop in _process_record: a denied/errored API
    call is skipped before role resolution or handler execution, even if
    the rule's own conditions didn't filter it out."""

    def test_skips_response_when_error_code_present(self, monkeypatch):
        dredge = MagicMock()
        monkeypatch.setattr(responder, "_get_dredge", lambda role_arn=None: dredge)
        logger = MagicMock()

        record = _sqs_record(
            {
                "response_module": "disable_user",
                "detection_id": "d-backstop-1",
                "rule_id": "test-rule",
                "user_name": "attacker",
                "api": {"error_code": "AccessDenied"},
            }
        )
        responder._process_record(record, "req-1", "rh-1", logger)

        dredge.aws_ir.response.disable_user.assert_not_called()
        logger.info.assert_called_once()
        assert logger.info.call_args.kwargs["event_name"] == "IR_SKIPPED_FAILED_API_CALL"

    def test_executes_normally_when_no_error_code(self, monkeypatch):
        dredge = MagicMock()
        monkeypatch.setattr(responder, "_get_dredge", lambda role_arn=None: dredge)
        logger = MagicMock()

        record = _sqs_record(
            {
                "response_module": "disable_user",
                "detection_id": "d-backstop-2",
                "rule_id": "test-rule",
                "user_name": "attacker",
            }
        )
        responder._process_record(record, "req-2", "rh-2", logger)

        dredge.aws_ir.response.disable_user.assert_called_once_with(user_name="attacker")

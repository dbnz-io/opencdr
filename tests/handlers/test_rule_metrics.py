import json
from unittest.mock import patch

from src.handlers import api


def test_rule_metrics_are_aggregate_only_and_attribute_response_success():
    signal = {
        "detection_id": "det-1", "rule_id": "console_login", "rule_version": 3,
        "release_id": "rel-2", "severity": "HIGH", "evaluation_mode": "production",
        "notify": True, "response_module": "disable_user",
    }
    with (
        patch.object(api, "_query_bucketed_range", side_effect=lambda *_args, **_kwargs: ([signal], None, False) if _args[2] == "HIGH" else ([], None, False)),
        patch.object(api, "ir_actions_table") as actions,
    ):
        actions.scan.return_value = {"Items": [{"detection_id": "det-1"}]}
        response = api._handle_rule_metrics({"date_from": "2026-09-27", "date_to": "2026-09-27"})
    body = json.loads(response["body"])
    assert body["privacy"] == "aggregate-only"
    assert body["groups"] == [{
        "rule_id": "console_login", "rule_version": "3", "release_id": "rel-2",
        "severity": "HIGH", "evaluation_mode": "production", "detections": 1,
        "notification_requested": 1, "response_requested": 1,
        "response_succeeded": 1, "response_outcome_unknown": 0,
    }]
    assert "detection_id" not in json.dumps(body)

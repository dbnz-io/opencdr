"""Regression test for a real bug: notifier's lambda_handler used to
construct its Logger with hardcoded service="OCDR-NOTIFIER"/
source="ocdr.notifier" instead of reading SERVICE_NAME/LAMBDA_NAME from
the environment like every other handler (responder.py, ir_rollback.py,
...). The typo'd, non-env-driven value meant every log line this Lambda
ever wrote used a service name GET /logs?service=OPENCDR-NOTIFIER (what
serverless.yml's SERVICE_NAME env var and every other Lambda actually use)
could never match.
"""
from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

os.environ.setdefault("LOGS_TABLE_NAME", "test-logs-table")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

from src.handlers import notifier


def make_context():
    ctx = MagicMock()
    ctx.aws_request_id = "test-req-id"
    return ctx


class TestLoggerUsesEnvironmentServiceName:
    def test_lambda_handler_constructs_logger_from_module_env_constants(self, monkeypatch):
        monkeypatch.setattr(notifier, "_SERVICE", "OPENCDR-NOTIFIER")
        monkeypatch.setattr(notifier, "LAMBDA_NAME", "opencdr-dev-notifier")

        with (
            patch.object(notifier, "Logger") as mock_logger_cls,
            patch.object(notifier, "load_global_settings", return_value={"notifications_enabled": False}),
            patch.object(notifier, "AwsHandler"),
        ):
            notifier.lambda_handler({"Records": []}, make_context())

        call_kwargs = mock_logger_cls.call_args.kwargs
        assert call_kwargs["service"] == "OPENCDR-NOTIFIER"
        assert call_kwargs["source"] == "opencdr-dev-notifier"
        # The exact bug: these two literals used to be hardcoded regardless
        # of SERVICE_NAME/LAMBDA_NAME.
        assert call_kwargs["service"] != "OCDR-NOTIFIER"
        assert call_kwargs["source"] != "ocdr.notifier"

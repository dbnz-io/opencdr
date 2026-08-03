import os
import sys
from unittest.mock import MagicMock

import boto3

# Make project root importable so tests can use `from src.domain.x import ...`
sys.path.insert(0, os.path.dirname(__file__))

# src.handlers.responder._resolve_role_arn falls back to OPENCDR_IR_ROLE_ARN
# when a detection's account has no row in irAccountRolesTable (or no
# account could be determined at all). Set a harmless default so test
# modules that don't care about role resolution get a usable role_arn by
# default; tests exercising resolution itself
# (tests/handlers/test_responder_init.py) override it explicitly.
os.environ.setdefault("OPENCDR_IR_ROLE_ARN", "arn:aws:iam::123456789012:role/test-ir-role")
os.environ.setdefault("LOGS_TABLE_NAME", "test-logs-table")
os.environ.setdefault("IR_ACCOUNT_ROLES_TABLE_NAME", "test-ir-account-roles-table")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

# responder._get_dredge() eagerly calls sts:AssumeRole when building a Dredge
# client for a resolved role_arn. Stub only the "sts" service so that never
# makes a real network call in tests that reach it (directly, or via
# _process_record when a test doesn't mock the mock_dredge fixture's
# _get_dredge seam); every other boto3 client/resource (dynamodb, etc.) is
# untouched and keeps going through each test's own per-call mocking.
_real_session_client = boto3.Session.client


def _session_client_with_fake_sts(self, service_name, *args, **kwargs):
    if service_name == "sts":
        fake_sts = MagicMock()
        fake_sts.assume_role.return_value = {
            "Credentials": {
                "AccessKeyId": "ASIAFAKETESTKEYID",
                "SecretAccessKey": "fake-secret-access-key",
                "SessionToken": "fake-session-token",
            }
        }
        return fake_sts
    return _real_session_client(self, service_name, *args, **kwargs)


boto3.Session.client = _session_client_with_fake_sts

# responder's circuit breaker (_recent_action_count) queries the logs table
# for every processed record, via a module-level table reference built at
# import time. Default it to an empty-result mock -- same convention as
# other handlers' `patch.object(module, "some_table")` per-test mocking --
# so tests that don't care about the rate limit aren't affected by it.
# tests/handlers/test_responder_rate_limit.py overrides this per-test via
# monkeypatch to exercise the breaker itself.
from src.handlers import responder as _responder_module  # noqa: E402

_responder_module._logs_table = MagicMock()
_responder_module._logs_table.query.return_value = {"Items": []}

# responder._resolve_role_arn() GetItems this table whenever a detection has
# a resolvable account_id. Default it to an empty-result mock (no row found
# -> falls back to OPENCDR_IR_ROLE_ARN above) for the same reason as
# _logs_table. tests/handlers/test_responder_init.py overrides this per-test
# via the mock_roles_table fixture to exercise resolution itself.
_responder_module._ir_account_roles_table = MagicMock()
_responder_module._ir_account_roles_table.get_item.return_value = {}

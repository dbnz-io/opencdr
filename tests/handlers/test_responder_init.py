"""Tests for src.handlers.responder's per-account IR role resolution and
Dredge caching (_resolve_role_arn, _get_dredge) -- the multi-account
replacement for the old single-role _init_dredge().

Resolution order (see _resolve_role_arn's docstring in responder.py):
  1) account_id has an enabled row in irAccountRolesTable -> that role_arn
  2) account_id has a *disabled* row -> None (kill switch, no fallback)
  3) no row for account_id, or account_id is None -> OPENCDR_IR_ROLE_ARN

conftest.py sets a default OPENCDR_IR_ROLE_ARN and stubs the "sts" boto3
client so importing src.handlers.responder never makes a real network call.
"""
from __future__ import annotations

import os
from unittest.mock import MagicMock

import pytest

os.environ.setdefault("LOGS_TABLE_NAME", "test-logs-table")
os.environ.setdefault("IR_ACCOUNT_ROLES_TABLE_NAME", "test-ir-account-roles-table")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

from dredge import Dredge
from src.handlers import responder


@pytest.fixture(autouse=True)
def _reset_caches():
    """Module-level caches persist across tests in the same process."""
    responder._role_arn_cache.clear()
    responder._dredge_cache.clear()
    yield
    responder._role_arn_cache.clear()
    responder._dredge_cache.clear()


@pytest.fixture()
def mock_roles_table(monkeypatch):
    table = MagicMock()
    monkeypatch.setattr(responder, "_ir_account_roles_table", table)
    return table


class TestResolveRoleArnNoAccount:
    def test_no_account_id_returns_default_env_var(self, monkeypatch):
        monkeypatch.setenv("OPENCDR_IR_ROLE_ARN", "arn:aws:iam::123456789012:role/home-role")
        assert responder._resolve_role_arn(None) == "arn:aws:iam::123456789012:role/home-role"

    def test_no_account_id_and_no_default_returns_none(self, monkeypatch):
        monkeypatch.delenv("OPENCDR_IR_ROLE_ARN", raising=False)
        assert responder._resolve_role_arn(None) is None


class TestResolveRoleArnWithAccount:
    def test_enabled_row_returns_its_role_arn(self, monkeypatch, mock_roles_table):
        monkeypatch.setenv("OPENCDR_IR_ROLE_ARN", "arn:aws:iam::111111111111:role/home-role")
        mock_roles_table.get_item.return_value = {
            "Item": {
                "aws_account_id": "222222222222",
                "role_arn": "arn:aws:iam::222222222222:role/opencdr-ir-role",
                "enabled": True,
            }
        }
        assert (
            responder._resolve_role_arn("222222222222")
            == "arn:aws:iam::222222222222:role/opencdr-ir-role"
        )
        mock_roles_table.get_item.assert_called_once_with(Key={"aws_account_id": "222222222222"})

    def test_disabled_row_returns_none_without_falling_back(self, monkeypatch, mock_roles_table):
        monkeypatch.setenv("OPENCDR_IR_ROLE_ARN", "arn:aws:iam::111111111111:role/home-role")
        mock_roles_table.get_item.return_value = {
            "Item": {
                "aws_account_id": "222222222222",
                "role_arn": "arn:aws:iam::222222222222:role/opencdr-ir-role",
                "enabled": False,
            }
        }
        assert responder._resolve_role_arn("222222222222") is None

    def test_no_row_falls_back_to_default_env_var(self, monkeypatch, mock_roles_table):
        monkeypatch.setenv("OPENCDR_IR_ROLE_ARN", "arn:aws:iam::111111111111:role/home-role")
        mock_roles_table.get_item.return_value = {}
        assert (
            responder._resolve_role_arn("333333333333")
            == "arn:aws:iam::111111111111:role/home-role"
        )

    def test_result_is_cached_within_ttl(self, monkeypatch, mock_roles_table):
        monkeypatch.setenv("OPENCDR_IR_ROLE_ARN", "arn:aws:iam::111111111111:role/home-role")
        mock_roles_table.get_item.return_value = {
            "Item": {"aws_account_id": "222222222222", "role_arn": "arn:aws:iam::222222222222:role/x", "enabled": True}
        }
        responder._resolve_role_arn("222222222222")
        responder._resolve_role_arn("222222222222")
        mock_roles_table.get_item.assert_called_once()

    def test_cache_expiry_triggers_a_fresh_lookup(self, monkeypatch, mock_roles_table):
        monkeypatch.setenv("OPENCDR_IR_ROLE_ARN", "arn:aws:iam::111111111111:role/home-role")
        monkeypatch.setattr(responder, "ROLE_ARN_CACHE_TTL_SECONDS", 0)
        mock_roles_table.get_item.return_value = {
            "Item": {"aws_account_id": "222222222222", "role_arn": "arn:aws:iam::222222222222:role/x", "enabled": True}
        }
        responder._resolve_role_arn("222222222222")
        responder._resolve_role_arn("222222222222")
        assert mock_roles_table.get_item.call_count == 2


class TestGetDredge:
    def test_returns_a_dredge_instance(self, monkeypatch):
        dredge = responder._get_dredge("arn:aws:iam::123456789012:role/opencdr-ir-role")
        assert isinstance(dredge, Dredge)

    def test_same_role_arn_is_cached(self, monkeypatch):
        role_arn = "arn:aws:iam::123456789012:role/opencdr-ir-role"
        first = responder._get_dredge(role_arn)
        second = responder._get_dredge(role_arn)
        assert first is second

    def test_different_role_arns_get_different_clients(self, monkeypatch):
        a = responder._get_dredge("arn:aws:iam::111111111111:role/opencdr-ir-role")
        b = responder._get_dredge("arn:aws:iam::222222222222:role/opencdr-ir-role")
        assert a is not b

    def test_cache_expiry_builds_a_new_client(self, monkeypatch):
        monkeypatch.setattr(responder, "DREDGE_CACHE_TTL_SECONDS", 0)
        role_arn = "arn:aws:iam::123456789012:role/opencdr-ir-role"
        first = responder._get_dredge(role_arn)
        second = responder._get_dredge(role_arn)
        assert first is not second

    def test_region_falls_back_to_default(self, monkeypatch):
        monkeypatch.delenv("AWS_REGION", raising=False)
        monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)
        dredge = responder._get_dredge("arn:aws:iam::123456789012:role/opencdr-ir-role")
        assert isinstance(dredge, Dredge)

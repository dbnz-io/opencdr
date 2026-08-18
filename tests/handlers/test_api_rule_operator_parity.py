"""Tests for the operator/rule_kind parity fix (INFORME-AUTOR-ES.md §3.1):
`ALLOWED_CONDITION_OPS` had drifted from what detection_engine.py actually
implements in both directions (wildcard/in_list/not_in_list implemented but
rejected here; not_prefix/not_suffix accepted here but not implemented,
silently never matching with no error either side). rule_kind="list" was
also storage-layer-only, unreachable through the API at all.
"""
from __future__ import annotations

import os

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

import pytest

from src.handlers import api


class TestWildcardAcceptedByApi:
    def test_wildcard_condition_needs_no_value(self):
        payload = {
            "rule_kind": "signal",
            "conditions": [{"field": "activity_name", "op": "wildcard"}],
        }
        out = api._normalize_rule_payload(payload, force_rule_id=None)
        assert out["conditions"][0]["op"] == "wildcard"


class TestInListAcceptedByApi:
    def test_in_list_requires_list_id(self):
        payload = {
            "rule_kind": "signal",
            "conditions": [{"field": "actor.user_name", "op": "in_list"}],
        }
        with pytest.raises(ValueError, match="list_id is required"):
            api._normalize_rule_payload(payload, force_rule_id=None)

    def test_in_list_with_list_id_is_accepted_and_preserved(self):
        payload = {
            "rule_kind": "signal",
            "conditions": [
                {"field": "actor.user_name", "op": "in_list", "list_id": "automation-identities"}
            ],
        }
        out = api._normalize_rule_payload(payload, force_rule_id=None)
        cond = out["conditions"][0]
        assert cond["op"] == "in_list"
        assert cond["list_id"] == "automation-identities"

    def test_not_in_list_with_list_id_is_accepted(self):
        payload = {
            "rule_kind": "signal",
            "conditions": [
                {
                    "field": "actor.user_name",
                    "op": "not_in_list",
                    "list_id": "automation-identities",
                }
            ],
        }
        out = api._normalize_rule_payload(payload, force_rule_id=None)
        assert out["conditions"][0]["list_id"] == "automation-identities"


class TestNotPrefixSuffixAcceptedByApi:
    """Accepted by the API before this fix too -- what's new is that the
    engine now actually implements them (see
    tests/domain/test_detection_engine_prefix_negation.py)."""

    def test_not_prefix_condition_accepted(self):
        payload = {
            "rule_kind": "signal",
            "conditions": [{"field": "api.service", "op": "not_prefix", "value": "iam."}],
        }
        out = api._normalize_rule_payload(payload, force_rule_id=None)
        assert out["conditions"][0]["op"] == "not_prefix"

    def test_not_suffix_condition_accepted(self):
        payload = {
            "rule_kind": "signal",
            "conditions": [{"field": "api.service", "op": "not_suffix", "value": ".com"}],
        }
        out = api._normalize_rule_payload(payload, force_rule_id=None)
        assert out["conditions"][0]["op"] == "not_suffix"


class TestListRuleKind:
    def test_list_rule_requires_non_empty_values(self):
        payload = {"rule_kind": "list", "rule_id": "automation-identities"}
        with pytest.raises(ValueError, match="values must be a non-empty list"):
            api._normalize_rule_payload(payload, force_rule_id=None)

    def test_list_rule_rejects_non_list_values(self):
        payload = {"rule_kind": "list", "rule_id": "automation-identities", "values": "not-a-list"}
        with pytest.raises(ValueError, match="values must be a non-empty list"):
            api._normalize_rule_payload(payload, force_rule_id=None)

    def test_list_rule_accepted_and_normalized(self):
        payload = {
            "rule_kind": "list",
            "rule_id": "automation-identities",
            "values": ["ci-deploy-role", "terraform-apply"],
        }
        out = api._normalize_rule_payload(payload, force_rule_id=None)
        assert out["rule_kind"] == "list"
        assert out["rule_id"] == "automation-identities"
        assert out["values"] == ["ci-deploy-role", "terraform-apply"]
        # List rules have no conditions/severity/enabled -- different shape
        # entirely, not a signal/correlation rule with an empty conditions list.
        assert "conditions" not in out
        assert "severity" not in out

    def test_list_rule_values_coerced_to_strings(self):
        payload = {"rule_kind": "list", "rule_id": "ports", "values": [22, 3389]}
        out = api._normalize_rule_payload(payload, force_rule_id=None)
        assert out["values"] == ["22", "3389"]


class TestDefaultListingExcludesListKind:
    """GET /rules with no rule_kind filter queries signal+correlation only
    -- a rule_kind="list" lookup table isn't something a user browsing "all
    rules" expects mixed in. See _DEFAULT_RULE_LISTING_KINDS in api.py."""

    def test_default_listing_kinds_excludes_list(self):
        assert "list" not in api._DEFAULT_RULE_LISTING_KINDS
        assert api._DEFAULT_RULE_LISTING_KINDS == {"signal", "correlation"}

    def test_allowed_rule_kinds_includes_list(self):
        assert "list" in api.ALLOWED_RULE_KINDS

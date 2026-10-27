from __future__ import annotations

import json
from pathlib import Path

from scripts.validate_catalog import validate_catalog


def _write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_validates_rules_and_independent_lists(tmp_path: Path):
    _write(
        tmp_path / "cloudtrail" / "rule.json",
        {
            "rule_id": "example",
            "rule_kind": "signal",
            "enabled": True,
            "notify": False,
            "severity": "LOW",
            "conditions": [{"field": "activity_name", "op": "equals", "value": "ListUsers"}],
        },
    )
    _write(
        tmp_path / "lists" / "admins.json",
        {"list_id": "admins", "matcher": "exact", "values": ["alice"]},
    )

    assert validate_catalog(tmp_path) == (1, 1, [])


def test_rejects_invalid_list_and_skips_root_fixture_stub(tmp_path: Path):
    _write(tmp_path / "lists" / "admins.json", {"list_id": "admins", "values": ["alice"]})
    _write(tmp_path / "test_atomic_rule.json", {"fixture": True})

    rules, lists, errors = validate_catalog(tmp_path)

    assert (rules, lists) == (0, 0)
    assert len(errors) == 1
    assert "matcher is required" in errors[0]

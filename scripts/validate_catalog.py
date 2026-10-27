#!/usr/bin/env python3
"""Validate a detection-rules catalog, including independent reusable lists."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.domain.detection_lists import validate_list_document  # noqa: E402
from src.domain.rule_schema import validate_rule_document  # noqa: E402

_FIXTURE_STUBS = {
    "test_atomic_rule.json",
    "test_correlation_rule.json",
    "test_detection_rule.json",
}


def validate_catalog(root: Path) -> tuple[int, int, list[str]]:
    paths = sorted(root.rglob("*.json"))
    if not paths:
        return 0, 0, [f"{root}: no JSON catalog files found"]

    rule_count = 0
    list_count = 0
    errors: list[str] = []
    for path in paths:
        relative = path.relative_to(root)
        if len(relative.parts) == 1 and path.name in _FIXTURE_STUBS:
            continue
        try:
            payload: Any = json.loads(path.read_text(encoding="utf-8"))
            if "lists" in relative.parts:
                validate_list_document(payload)
                list_count += 1
            else:
                if isinstance(payload, dict) and payload.get("rule_kind") == "list":
                    raise ValueError("legacy rule_kind=list is not allowed; use the lists/ catalog")
                validate_rule_document(payload)
                rule_count += 1
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            errors.append(f"{path}: {exc}")
    return rule_count, list_count, errors


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("support_files/detection_rules")
    rules, lists, errors = validate_catalog(root)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"Validated {rules} detection rules and {lists} reusable lists.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Validate one complete detection-rule JSON file without contacting AWS."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.domain.rule_schema import validate_rule_document  # noqa: E402


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: validate_rule.py <rule.json>", file=sys.stderr)
        return 2

    path = Path(sys.argv[1])
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        validate_rule_document(payload)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

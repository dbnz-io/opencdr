#!/usr/bin/env python3
"""Fail on actionable CloudFormation drift while suppressing one AWS normalization.

API Gateway drops an explicitly empty integration ResponseTemplates object after
CloudFormation creates generated CORS OPTIONS methods. CloudFormation then reports
that service-side normalization as drift on every check. Only that exact shape is
ignored; any additional resource or property difference remains actionable.
"""

from __future__ import annotations

import json
import sys
from typing import Any

_CORS_NORMALIZATION_PATH = "/Integration/IntegrationResponses/0/ResponseTemplates"


def is_expected_api_gateway_normalization(drift: dict[str, Any]) -> bool:
    differences = drift.get("PropertyDifferences")
    return bool(differences) and all(
        (
            drift.get("ResourceType") == "AWS::ApiGateway::Method"
            and str(drift.get("LogicalResourceId", "")).endswith("Options")
            and difference.get("PropertyPath") == _CORS_NORMALIZATION_PATH
            and difference.get("DifferenceType") == "REMOVE"
            and difference.get("ActualValue") in (None, "null")
        )
        for difference in differences
    )


def partition_drifts(
    drifts: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    expected = []
    actionable = []
    for drift in drifts:
        (expected if is_expected_api_gateway_normalization(drift) else actionable).append(drift)
    return expected, actionable


def main() -> int:
    try:
        drifts = json.load(sys.stdin)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        print(f"ERROR: invalid drift JSON: {exc}", file=sys.stderr)
        return 2

    if not isinstance(drifts, list):
        print("ERROR: expected a JSON array of CloudFormation resource drifts", file=sys.stderr)
        return 2

    expected, actionable = partition_drifts(drifts)
    if expected:
        names = ", ".join(str(item.get("LogicalResourceId")) for item in expected)
        print(
            f"Ignored {len(expected)} generated API Gateway CORS normalization difference(s): "
            f"{names}"
        )

    if actionable:
        print(f"ERROR: {len(actionable)} actionable drifted resource(s) detected", file=sys.stderr)
        print(json.dumps(actionable, indent=2, default=str), file=sys.stderr)
        return 1

    print("No actionable stack drift detected.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

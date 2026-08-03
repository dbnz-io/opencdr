# src/infra/metrics.py
"""
Domain-level metrics via CloudWatch Embedded Metric Format (EMF).

EMF metrics are extracted automatically by CloudWatch Logs from a specially
shaped JSON log line (the "_aws" key) -- no separate PutMetricData API
call, no new IAM permission beyond the logs:PutLogEvents every function
already has. Chosen over the OTel Metrics API (the other option this
project's roadmap considered) specifically because it's zero extra
infrastructure: it works the moment a function can write to CloudWatch
Logs at all, which is already guaranteed.

https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Embedded_Metric_Format_Specification.html
"""
from __future__ import annotations

import json
import time
from typing import Any

_NAMESPACE = "OpenCDR"


def emit_metric(
    name: str,
    value: float = 1,
    unit: str = "Count",
    dimensions: dict[str, str] | None = None,
) -> None:
    """
    Prints one EMF-formatted log line. Never raises -- a metrics emission
    failure must not be able to break the pipeline it's measuring, same
    reasoning as every other observability integration in this codebase.
    """
    try:
        dims = dimensions or {}
        payload: dict[str, Any] = {
            "_aws": {
                "Timestamp": int(time.time() * 1000),
                "CloudWatchMetrics": [
                    {
                        "Namespace": _NAMESPACE,
                        "Dimensions": [list(dims.keys())] if dims else [[]],
                        "Metrics": [{"Name": name, "Unit": unit}],
                    }
                ],
            },
            name: value,
            **dims,
        }
        print(json.dumps(payload, default=str))
    except Exception as e:
        print("METRIC_EMIT_FAILED:", repr(e))

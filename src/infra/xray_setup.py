# src/infra/xray_setup.py
"""
Patches boto3/botocore so DynamoDB, SQS, SNS, etc. calls each show up as
their own node in the X-Ray service map, not just the Lambda invocation
itself.

`provider.tracing` in serverless.yml only enables Active Tracing on the
Lambda boundary -- it emits one segment per invocation, but does not
instrument anything a handler's code does internally. This is the piece
that closes that gap: the official, AWS-maintained aws-xray-sdk, patching
only boto3 (not the broader patch_all(), which also touches requests/
sqlite3/mysql/etc. this codebase doesn't use for outbound calls this needs
traced). This is a materially different risk than the OTel instrumentor
that broke api.py in production -- that library wrapped Lambda invocation
and API Gateway event parsing itself; this only wraps outgoing boto3 client
calls and never touches event handling.

Every handler calls patch_boto3() once, at module import time (cold
start), before constructing any boto3 client/resource.
"""
from __future__ import annotations

from aws_xray_sdk.core import patch, xray_recorder


def patch_boto3() -> None:
    # Outside a real Lambda invocation (local scripts, tests) there's no
    # active X-Ray segment; without this, a patched boto3 call in that
    # context raises SegmentNotFoundException instead of just not tracing.
    xray_recorder.configure(context_missing="LOG_ERROR")
    patch(["boto3"])

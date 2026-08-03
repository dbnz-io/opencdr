# src/handlers/alarm_notifier.py
"""
Subscribed to AlarmsSnsTopic. Formats a CloudWatch Alarm state-change
notification and forwards it to Slack.

The alarms this delivers (Lambda errors per function, DLQ depth, DynamoDB
stream iterator age) already existed in serverless.yml -- this is only the
delivery mechanism that was missing. alarmEmail was never set in any
deployment, so AlarmsEmailSubscription's Condition (HasAlarmEmail) never
created a subscription, and every one of those alarms had been firing into
a topic with zero subscribers.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

import boto3

from ..infra.logger import Logger
from ..infra.xray_setup import patch_boto3

patch_boto3()

_webhook_cache: str | None = None
_webhook_cache_loaded_at = 0.0
_WEBHOOK_TTL_SECONDS = int(os.getenv("ALARM_WEBHOOK_TTL_SECONDS", "300"))


def _get_webhook_url() -> str:
    """
    Cached per warm container with a TTL, same pattern as processor.py's
    RULES_CACHE / notifier.py's settings cache.
    """
    global _webhook_cache, _webhook_cache_loaded_at
    now = time.time()
    if _webhook_cache is not None and (now - _webhook_cache_loaded_at) < _WEBHOOK_TTL_SECONDS:
        return _webhook_cache

    stage = os.getenv("STAGE", "dev")
    ssm = boto3.client("ssm")
    resp = ssm.get_parameter(
        Name=f"/opencdr-{stage}/ops-alerts/slack-webhook", WithDecryption=True
    )
    _webhook_cache = resp["Parameter"]["Value"]
    _webhook_cache_loaded_at = now
    return _webhook_cache


def _post_to_slack(webhook_url: str, text: str) -> None:
    if urllib.parse.urlparse(webhook_url).scheme != "https":
        raise ValueError(f"Webhook URL must use HTTPS, got: {webhook_url!r}")

    data = json.dumps({"text": text}).encode("utf-8")
    req = urllib.request.Request(
        url=webhook_url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:  # nosec B310 -- scheme validated https-only above
        resp.read()


def _format_alarm_message(alarm: dict) -> str:
    name = alarm.get("AlarmName", "unknown alarm")
    state = alarm.get("NewStateValue", "UNKNOWN")
    reason = alarm.get("NewStateReason", "")
    description = alarm.get("AlarmDescription", "")
    emoji = {"ALARM": "\U0001f534", "OK": "✅"}.get(state, "⚪")
    return f"{emoji} *{name}* is now *{state}*\n{description}\n{reason}"


def lambda_handler(event, context):
    base_logger = Logger(
        service=os.getenv("SERVICE_NAME", "OPENCDR"),
        source="ocdr.alarm_notifier",
        request_id=context.aws_request_id if context else None,
    )

    webhook_url = _get_webhook_url()

    for record in event.get("Records", []):
        sns_message = record.get("Sns", {}).get("Message", "{}")
        try:
            alarm = json.loads(sns_message)
        except json.JSONDecodeError:
            # Non-JSON SNS messages happen legitimately here -- AWS Budgets
            # notifications (see CostBudget in serverless.yml, also
            # subscribed to this topic) are plain text, not the CloudWatch
            # alarm JSON shape this formatter otherwise expects.
            alarm = {
                "AlarmName": "AWS Budgets notification",
                "NewStateValue": "ALARM",
                "NewStateReason": sns_message,
            }

        try:
            _post_to_slack(webhook_url, _format_alarm_message(alarm))
            base_logger.info(
                event_name="ALARM_FORWARDED",
                event_type="SYSTEM",
                message="Forwarded CloudWatch alarm to Slack",
                details={"alarm_name": alarm.get("AlarmName")},
            )
        except Exception as e:
            base_logger.error(
                event_name="ALARM_FORWARD_FAILED",
                event_type="SYSTEM",
                message="Failed to forward alarm to Slack",
                details={"error": repr(e), "alarm_name": alarm.get("AlarmName")},
            )
            # Re-raise so SNS's own retry policy attempts redelivery --
            # this Lambda failing shouldn't mean the alarm silently drops.
            raise

    return {"status": "ok"}

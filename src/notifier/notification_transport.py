import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from decimal import Decimal
from typing import Any

from src.infra.aws_handler import AwsHandler
from src.infra.logger import Logger


@dataclass
class DeliveryResult:
    channel: str  # "slack" | "discord"
    status: str  # "SUCCESS" | "SKIPPED" | "FAILED"
    http_status: int | None = None
    error_code: str | None = None
    error_message: str | None = None


class NotificationTransport:
    """
    Notifier-side delivery utilities.

    This module does NOT publish to SQS. It only delivers notifications (Slack/Discord)
    and emits structured logs via Logger.

    Dependencies:
      - Logger (for structured logging/audit)
      - AwsHandler (optional; kept for future expansions like S3 evidence fetch or DDB execution writes)
    """

    def __init__(
        self,
        *,
        logger: Logger,
        aws: AwsHandler | None = None,
        service: str = "OPENCDR",
        lambda_name: str = "opencdr.notifier",
    ):
        self.logger = logger
        self.aws = aws
        self.service = service
        self.lambda_name = lambda_name

    # ---------- shared helpers ----------

    @staticmethod
    def decimal_to_native(obj: Any) -> Any:
        if isinstance(obj, list):
            return [NotificationTransport.decimal_to_native(x) for x in obj]
        if isinstance(obj, dict):
            return {k: NotificationTransport.decimal_to_native(v) for k, v in obj.items()}
        if isinstance(obj, Decimal):
            if obj % 1 == 0:
                return int(obj)
            return float(obj)
        return obj

    @staticmethod
    def _extract_error_info(safe: dict) -> tuple[str | None, str | None]:
        error_code = safe.get("error_code")
        error_message = safe.get("error_message")

        raw_event = safe.get("raw_event") or {}
        if isinstance(raw_event, dict):
            detail = raw_event.get("detail") or {}
            if isinstance(detail, dict):
                error_code = error_code or detail.get("errorCode") or detail.get("ErrorCode")
                error_message = (
                    error_message or detail.get("errorMessage") or detail.get("ErrorMessage")
                )

        return error_code, error_message

    # ---------- Discord ----------

    @staticmethod
    def _severity_color(severity: str | None) -> int:
        if not severity:
            return 0x95A5A6
        sev = str(severity).upper()
        if sev in ("CRITICAL", "SEVERE"):
            return 0xE02424
        if sev == "HIGH":
            return 0xE67E22
        if sev in ("MEDIUM", "MODERATE"):
            return 0xF1C40F
        if sev in ("LOW", "INFO", "INFORMATIONAL"):
            return 0x2ECC71
        return 0x95A5A6

    def _build_discord_payload(self, item: dict) -> dict:
        safe = self.decimal_to_native(item)

        detection_id = safe.get("detection_id")
        severity = safe.get("severity", "UNKNOWN")
        account_id = safe.get("aws_account_id", "N/A")
        region = safe.get("aws_region", "N/A")
        event_name = safe.get("event_name", "N/A")
        event_source = safe.get("event_source", "N/A")
        user_name = safe.get("user_name", "N/A")
        source_ip = safe.get("source_ip", "N/A")

        matched_conditions = safe.get("matched_conditions", "N/A")

        rule_id = safe.get("rule_id", "N/A")
        rule_desc = safe.get("rule_description") or "Detection triggered."
        event_time = safe.get("event_time") or safe.get("timestamp", "N/A")
        playbook = safe.get("playbook", "N/A")
        response_module = safe.get("response_module", "N/A")
        ir_status = safe.get("ir_status")

        # You were forcing these in discord build; keep your behavior.
        error_code = safe.get("error_code", "N/A")
        error_message = safe.get("error_message", "N/A")

        entity = user_name if user_name and user_name != "N/A" else None

        if ir_status == "CONTAINED":
            title_parts = [ir_status, "-", event_name]
        elif error_code and error_code != "N/A":
            title_parts = ["ERROR -", event_name]
        else:
            title_parts = [str(severity).upper(), "–", event_name]

        if entity:
            title_parts.append(f"on {entity}")
        if source_ip and source_ip != "N/A":
            title_parts.append(f"({source_ip})")

        title = " ".join(title_parts)

        description = "\n".join(
            [
                rule_desc,
                "",
                f"**Event source:** `{event_source}`",
            ]
        )

        fields = [
            {"name": "Severity", "value": str(severity), "inline": True},
            {"name": "Account", "value": f"`{account_id}`", "inline": True},
            {"name": "Region", "value": str(region), "inline": True},
            {"name": "User", "value": f"`{user_name}`", "inline": True},
            {"name": "Source IP", "value": f"`{source_ip}`", "inline": True},
            {"name": "Matched Conditions", "value": f"`{matched_conditions}`", "inline": True},
            {"name": "Rule ID", "value": f"`{rule_id}`", "inline": False},
            {"name": "Detection ID", "value": f"`{detection_id}`", "inline": False},
            {"name": "Response module", "value": f"`{response_module}`", "inline": True},
            {"name": "Playbook", "value": f"`{playbook}`", "inline": True},
            {"name": "Event time", "value": str(event_time), "inline": False},
            {"name": "Error Code", "value": str(error_code), "inline": False},
            {"name": "Error Message", "value": str(error_message), "inline": False},
        ]

        if ir_status:
            fields.append({"name": "IR status", "value": f"`{ir_status}`", "inline": True})

        raw_event = safe.get("raw_event")
        if isinstance(raw_event, dict):
            raw_str = json.dumps(raw_event, indent=2)
            if len(raw_str) > 900:
                raw_str = raw_str[:900] + "\n… (truncated)"
            fields.append(
                {
                    "name": "Raw event preview",
                    "value": f"```json\n{raw_str}\n```",
                    "inline": False,
                }
            )

        color = self._severity_color(severity)
        if ir_status == "CONTAINED":
            color = 0x2ECC71
        if error_code and error_code != "N/A":
            color = 0x7B1FA2

        embed = {
            "title": title,
            "description": description,
            "color": color,
            "fields": fields,
        }

        if isinstance(event_time, str):
            embed["footer"] = {"text": f"Detection at {event_time}"}

        return {"content": "", "embeds": [embed]}

    def send_to_discord(self, *, item: dict, discord_webhook: str | None) -> DeliveryResult:
        safe = self.decimal_to_native(item)
        detection_id = safe.get("detection_id")
        rule_id = safe.get("rule_id")

        if not discord_webhook:
            self.logger.info(
                event_type="NOTIFICATION",
                event_name="DISCORD_NOTIFY_SKIP",
                message="Discord webhook URL not configured",
                details={"detection_id": detection_id, "rule_id": rule_id},
            )
            return DeliveryResult(channel="discord", status="SKIPPED")

        if urllib.parse.urlparse(discord_webhook).scheme != "https":
            raise ValueError(f"Discord webhook URL must use HTTPS, got: {discord_webhook!r}")

        payload = self._build_discord_payload(safe)
        data_bytes = json.dumps(payload).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "OpenCDR-Notifier/1.0",
        }

        req = urllib.request.Request(
            url=discord_webhook,
            data=data_bytes,
            headers=headers,
            method="POST",
        )

        try:
            resp = urllib.request.urlopen(req)  # nosec B310 -- scheme validated https-only above (line 207)
            status = getattr(resp, "status", None)

            self.logger.info(
                event_type="NOTIFICATION",
                event_name="DISCORD_NOTIFY_SUCCESS",
                message="Sent detection event to Discord",
                details={"detection_id": detection_id, "rule_id": rule_id, "status": status},
            )
            return DeliveryResult(channel="discord", status="SUCCESS", http_status=status)

        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")
            self.logger.error(
                event_type="ERROR",
                event_name="DISCORD_NOTIFY_HTTP_ERROR",
                message="HTTP error while sending detection event to Discord",
                details={
                    "detection_id": detection_id,
                    "rule_id": rule_id,
                    "status_code": e.code,
                    "reason": e.reason,
                    "body": body[:2000],  # avoid huge logs
                },
            )
            return DeliveryResult(
                channel="discord",
                status="FAILED",
                http_status=e.code,
                error_code="HTTPError",
                error_message=f"{e.reason}",
            )

        except Exception as e:
            self.logger.error(
                event_type="ERROR",
                event_name="DISCORD_NOTIFY_ERROR",
                message="Unexpected error while sending detection event to Discord",
                details={"detection_id": detection_id, "rule_id": rule_id, "error": repr(e)},
            )
            return DeliveryResult(
                channel="discord",
                status="FAILED",
                error_code=type(e).__name__,
                error_message=str(e),
            )

    # ---------- Slack ----------

    @staticmethod
    def _slack_severity_color(severity: str | None) -> str:
        if not severity:
            return "#95A5A6"
        sev = str(severity).upper()
        if sev in ("CRITICAL", "SEVERE"):
            return "#E02424"
        if sev == "HIGH":
            return "#E67E22"
        if sev in ("MEDIUM", "MODERATE"):
            return "#F1C40F"
        if sev in ("LOW", "INFO", "INFORMATIONAL"):
            return "#2ECC71"
        return "#95A5A6"

    def _build_slack_payload(self, item: dict) -> dict:
        safe = self.decimal_to_native(item)

        detection_id = safe.get("detection_id")
        severity = safe.get("severity", "UNKNOWN")
        account_id = safe.get("aws_account_id", "N/A")
        region = safe.get("aws_region", "N/A")
        event_name = safe.get("event_name", "N/A")
        event_source = safe.get("event_source", "N/A")
        user_name = safe.get("user_name", "N/A")
        source_ip = safe.get("source_ip", "N/A")
        rule_id = safe.get("rule_id", "N/A")
        rule_desc = safe.get("rule_description") or "Detection triggered."
        event_time = safe.get("event_time") or safe.get("timestamp", "N/A")
        playbook = safe.get("playbook", "N/A")
        response_module = safe.get("response_module", "N/A")
        ir_status = safe.get("ir_status")

        error_code, error_message = self._extract_error_info(safe)

        entity = user_name if user_name and user_name != "N/A" else None

        if ir_status == "CONTAINED":
            title_base = f"*CONTAINED* – `{event_name}`"
        else:
            title_base = f"*{str(severity).upper()}* – `{event_name}`"

        title_parts = [title_base]
        if entity:
            title_parts.append(f"on `{entity}`")
        if source_ip and source_ip != "N/A":
            title_parts.append(f"(`{source_ip}`)")
        title_text = " ".join(title_parts)

        color = self._slack_severity_color(severity)
        if ir_status == "CONTAINED":
            color = "#2ECC71"

        blocks: list[dict] = [
            {"type": "section", "text": {"type": "mrkdwn", "text": title_text}},
            {"type": "section", "text": {"type": "mrkdwn", "text": rule_desc}},
        ]

        fields = [
            {"type": "mrkdwn", "text": f"*Severity*\n{severity}"},
            {"type": "mrkdwn", "text": f"*Account*\n`{account_id}`"},
            {"type": "mrkdwn", "text": f"*Region*\n{region}"},
            {"type": "mrkdwn", "text": f"*User*\n`{user_name}`"},
            {"type": "mrkdwn", "text": f"*Source IP*\n`{source_ip}`"},
        ]
        blocks.append({"type": "section", "fields": fields})

        blocks.append(
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Rule ID*\n`{rule_id}`"},
                    {"type": "mrkdwn", "text": f"*Detection ID*\n`{detection_id}`"},
                    {"type": "mrkdwn", "text": f"*Response module*\n`{response_module}`"},
                    {"type": "mrkdwn", "text": f"*Playbook*\n`{playbook}`"},
                ],
            }
        )

        if error_code or error_message:
            err_lines = []
            if error_code:
                err_lines.append(f"`{error_code}`")
            if error_message:
                truncated = str(error_message)
                if len(truncated) > 300:
                    truncated = truncated[:300] + "…"
                err_lines.append(truncated)

            blocks.append(
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": "*Error*\n" + "\n".join(err_lines)},
                }
            )

        raw_event = safe.get("raw_event")
        if isinstance(raw_event, dict):
            raw_str = json.dumps(raw_event, indent=2)
            if len(raw_str) > 900:
                raw_str = raw_str[:900] + "\n… (truncated)"
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Raw event preview*:\n```json\n{raw_str}\n```",
                    },
                }
            )

        blocks.append(
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"*Event time:* {event_time}"},
                    {"type": "mrkdwn", "text": f"*Source:* `{event_source}`"},
                ],
            }
        )

        if ir_status:
            blocks.append(
                {
                    "type": "section",
                    "fields": [{"type": "mrkdwn", "text": f"*IR status*\n`{ir_status}`"}],
                }
            )

        status_label = "CONTAINED" if ir_status == "CONTAINED" else str(severity).upper()
        return {
            "text": f"{status_label} – {event_name}",
            "attachments": [{"color": color, "blocks": blocks}],
        }

    def send_to_slack(self, *, item: dict, slack_webhook: str | None) -> DeliveryResult:
        safe = self.decimal_to_native(item)
        detection_id = safe.get("detection_id")
        rule_id = safe.get("rule_id")

        if not slack_webhook:
            self.logger.info(
                event_type="NOTIFICATION",
                event_name="SLACK_NOTIFY_SKIP",
                message="Slack webhook URL not configured",
                details={"detection_id": detection_id, "rule_id": rule_id},
            )
            return DeliveryResult(channel="slack", status="SKIPPED")

        if urllib.parse.urlparse(slack_webhook).scheme != "https":
            raise ValueError(f"Slack webhook URL must use HTTPS, got: {slack_webhook!r}")

        payload = self._build_slack_payload(safe)
        data_bytes = json.dumps(payload).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "OpenCDR-Notifier/1.0",
        }

        req = urllib.request.Request(
            url=slack_webhook,
            data=data_bytes,
            headers=headers,
            method="POST",
        )

        try:
            resp = urllib.request.urlopen(req)  # nosec B310 -- scheme validated https-only above (line 425)
            status = getattr(resp, "status", None)

            self.logger.info(
                event_type="NOTIFICATION",
                event_name="SLACK_NOTIFY_SUCCESS",
                message="Sent detection event to Slack",
                details={"detection_id": detection_id, "rule_id": rule_id, "status": status},
            )
            return DeliveryResult(channel="slack", status="SUCCESS", http_status=status)

        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")
            self.logger.error(
                event_type="ERROR",
                event_name="SLACK_NOTIFY_HTTP_ERROR",
                message="HTTP error while sending detection event to Slack",
                details={
                    "detection_id": detection_id,
                    "rule_id": rule_id,
                    "status_code": e.code,
                    "reason": e.reason,
                    "body": body[:2000],
                },
            )
            return DeliveryResult(
                channel="slack",
                status="FAILED",
                http_status=e.code,
                error_code="HTTPError",
                error_message=f"{e.reason}",
            )

        except Exception as e:
            self.logger.error(
                event_type="ERROR",
                event_name="SLACK_NOTIFY_ERROR",
                message="Unexpected error while sending detection event to Slack",
                details={"detection_id": detection_id, "rule_id": rule_id, "error": repr(e)},
            )
            return DeliveryResult(
                channel="slack",
                status="FAILED",
                error_code=type(e).__name__,
                error_message=str(e),
            )

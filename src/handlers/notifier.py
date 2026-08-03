# src/handlers/notifier.py
from __future__ import annotations

import base64
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from boto3.dynamodb.types import TypeDeserializer

from ..domain.settings_secrets import is_ssm_ref, iter_secret_locations, ssm_ref_param_name
from ..infra.aws_handler import AwsHandler
from ..infra.logger import Logger
from ..infra.xray_setup import patch_boto3

patch_boto3()

# ----------------------------
# Env
# ----------------------------

SETTINGS_TABLE_NAME = os.getenv("SETTINGS_TABLE_NAME", "")
DEFAULT_SETTING_ID = os.getenv("NOTIFIER_SETTINGS_ID", "global")

# Optional: override channel routing at runtime
DEFAULT_CHANNEL = os.getenv("NOTIFIER_DEFAULT_CHANNEL", "auto")  # auto|slack|discord|email

# SNS topic ARN for email notifications (set by serverless.yml; can also be overridden per-settings)
ALERTS_SNS_TOPIC_ARN = os.getenv("ALERTS_SNS_TOPIC_ARN", "")

# Settings cache TTL (warm Lambda reuse)
SETTINGS_TTL_SECONDS = int(os.getenv("NOTIFIER_SETTINGS_TTL_SECONDS", "60"))


# ----------------------------
# Settings cache (reused across warm invocations)
# ----------------------------

_cached_settings: dict[str, Any] | None = None
_cached_settings_loaded_at: float = 0.0
_deser = TypeDeserializer()


# ----------------------------
# Small safe helpers
# ----------------------------


def _ddb_item_to_dict(item: dict[str, Any] | None) -> dict[str, Any]:
    # item is DynamoDB-typed (low-level client shape)
    return {k: _deser.deserialize(v) for k, v in (item or {}).items()}


def _safe_dict(x: Any) -> dict[str, Any]:
    return x if isinstance(x, dict) else {}


def _safe_list(x: Any) -> list:
    return x if isinstance(x, list) else []


def _s(x: Any, default: str = "") -> str:
    try:
        if x is None:
            return default
        return str(x)
    except Exception:
        return default


def _resolve_secret_refs(settings: dict[str, Any], *, aws: AwsHandler) -> None:
    """
    Resolves `ssm:` reference strings in settings["channels"] back into
    their real values, in place -- so every existing read site
    (_route_channels, the per-channel send logic) keeps reading
    webhook_url/api_token/headers exactly as before, with zero changes.
    A reference that no longer resolves (e.g. deleted out-of-band)
    becomes an empty string, same as "channel not configured" today.
    """
    for container, key, _ in iter_secret_locations(settings.get("channels")):
        value = container.get(key)
        if is_ssm_ref(value):
            container[key] = aws.ssm_get_secure_param(name=ssm_ref_param_name(value)) or ""


def _json_loads_maybe(x: Any) -> Any:
    """
    Supports:
      - dict payload
      - JSON string payload
      - {"payload": "<json string>"} wrapper
    """
    if isinstance(x, dict):
        if "payload" in x and isinstance(x["payload"], str):
            try:
                return json.loads(x["payload"])
            except Exception:
                return x
        return x

    if isinstance(x, str):
        try:
            return json.loads(x)
        except Exception:
            return x

    return x


# ----------------------------
# Settings loader
# ----------------------------


def load_global_settings(*, aws: AwsHandler, logger: Logger) -> dict[str, Any]:
    """
    Expected DynamoDB item (PK: setting_id = DEFAULT_SETTING_ID):

    {
      "setting_id": "global",
      "notifications_enabled": true,
      "channels": {
        "slack":   {"enabled": true, "webhook_url": "https://..."},
        "discord": {"enabled": false, "webhook_url": "https://..."},
        "email":   {"enabled": false, "topic_arn": "arn:aws:sns:..."}
      },
      "routing": {
        "CRITICAL": ["slack", "email"],
        "HIGH": "slack",
        "MEDIUM": "discord",
        "LOW": "discord"
      }
    }
    """
    global _cached_settings, _cached_settings_loaded_at

    now = time.time()
    if _cached_settings is not None and (now - _cached_settings_loaded_at) < SETTINGS_TTL_SECONDS:
        return _cached_settings

    # Safe defaults
    defaults: dict[str, Any] = {
        "setting_id": DEFAULT_SETTING_ID,
        "notifications_enabled": False,
        "channels": {},
        "routing": {},
    }

    if not SETTINGS_TABLE_NAME:
        logger.warning(
            event_name="NOTIFIER_SETTINGS_TABLE_MISSING",
            event_type="SYSTEM",
            message="SETTINGS_TABLE_NAME is not set; using safe defaults",
        )
        _cached_settings = defaults
        _cached_settings_loaded_at = now
        return defaults

    settings: dict[str, Any] = {}
    try:
        resp = aws._ddb.get_item(
            TableName=SETTINGS_TABLE_NAME,
            Key={"setting_id": {"S": DEFAULT_SETTING_ID}},
            ConsistentRead=True,
        )
        raw_item = resp.get("Item")
        settings = _ddb_item_to_dict(raw_item) if raw_item else {}
    except Exception as e:
        logger.error(
            event_name="NOTIFIER_SETTINGS_LOAD_FAIL",
            event_type="SYSTEM",
            message="Failed to load settings from DynamoDB; using safe defaults",
            details={"error": repr(e), "setting_id": DEFAULT_SETTING_ID},
        )
        settings = {}

    if not settings:
        settings = dict(defaults)

    # normalize
    settings["channels"] = _safe_dict(settings.get("channels"))
    settings["routing"] = _safe_dict(settings.get("routing"))

    _resolve_secret_refs(settings, aws=aws)

    _cached_settings = settings
    _cached_settings_loaded_at = now
    return settings


# ----------------------------
# Alert helpers
# ----------------------------


def _alert_title(item: dict[str, Any]) -> str:
    sev = _s(item.get("severity", "UNKNOWN")).upper()
    rid = _s(item.get("rule_id", "unknown_rule"))
    kind = _s(item.get("type", "signal"))
    return f"{sev} — {rid} ({kind})"


def _pick_event_id(item: dict[str, Any]) -> str:
    # correlation alerts built by your engine should have primary_signal + signal_refs
    primary = _safe_dict(item.get("primary_signal"))
    eid = _s(primary.get("event_id")).strip()
    if eid:
        return eid

    # signals have event_id at top-level
    eid = _s(item.get("event_id")).strip()
    if eid:
        return eid

    refs = _safe_list(item.get("signal_refs"))
    if refs and isinstance(refs[0], dict):
        eid = _s(refs[0].get("event_id")).strip()
        if eid:
            return eid

    return ""


# ----------------------------
# Slack / Discord payload builders (SOC-friendly, no emoji)
# ----------------------------
def build_slack_payload(item: dict[str, Any]) -> dict[str, Any]:
    primary = _safe_dict(item.get("primary_signal")) or item

    actor = _safe_dict(primary.get("actor"))
    network = _safe_dict(primary.get("network"))
    api = _safe_dict(primary.get("api"))

    severity = _s(item.get("severity", "UNKNOWN")).upper()
    rule_id = _s(item.get("rule_id"), "unknown_rule")
    playbook = _s(item.get("playbook"), "No playbook provided.")

    user = _s(actor.get("user_name"), "-")
    ip = _s(network.get("source_ip"), "-")
    operation = _s(api.get("operation"), _s(primary.get("activity_name"), "-"))
    matches = _s(item.get("match_count"), "1")

    alert_id = _s(item.get("alert_id"), "")
    alert_key = _s(item.get("alert_key"), "")

    # ----------------------------
    # Severity color bar
    # ----------------------------

    severity_colors = {
        "CRITICAL": "#d32f2f",
        "HIGH": "#f57c00",
        "MEDIUM": "#fbc02d",
        "LOW": "#1976d2",
    }

    color = severity_colors.get(severity, "#616161")

    # ----------------------------
    # Evidence list (short + readable)
    # ----------------------------

    refs = _safe_list(item.get("signal_refs"))[:5]

    ref_lines = []
    for r in refs:
        if not isinstance(r, dict):
            continue
        ts = _s(r.get("timestamp"))
        rid = _s(r.get("rule_id"))
        did = _s(r.get("detection_id"))
        ref_lines.append(f"• `{ts}`  {rid}  `{did[:8]}`")

    ref_text = "\n".join(ref_lines) if ref_lines else "—"

    # ----------------------------
    # Layout
    # ----------------------------

    blocks = [
        # Header
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*{severity} SECURITY ALERT*\n*{rule_id}*"},
        },
        {"type": "divider"},
        # Incident summary
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*User*\n`{user}`"},
                {"type": "mrkdwn", "text": f"*Source IP*\n`{ip}`"},
                {"type": "mrkdwn", "text": f"*Action*\n`{operation}`"},
                {"type": "mrkdwn", "text": f"*Matches*\n`{matches}`"},
            ],
        },
        {"type": "divider"},
        # Response guidance (MOST IMPORTANT)
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Recommended Response*\n{playbook}"},
        },
    ]

    # Evidence only for correlation alerts
    if refs:
        blocks.extend(
            [
                {"type": "divider"},
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*Related Signals*\n{ref_text}"},
                },
            ]
        )

    # Metadata footer
    context = []
    if alert_id:
        context.append({"type": "mrkdwn", "text": f"alert_id `{alert_id}`"})
    if alert_key:
        context.append({"type": "mrkdwn", "text": f"key `{alert_key}`"})

    if context:
        blocks.append({"type": "context", "elements": context})

    return {
        "attachments": [
            {
                "color": color,
                "blocks": blocks,
            }
        ]
    }


def build_discord_payload(item: dict[str, Any]) -> dict[str, Any]:
    primary = _safe_dict(item.get("primary_signal"))
    if not primary:
        primary = item

    actor = _safe_dict(primary.get("actor"))
    network = _safe_dict(primary.get("network"))
    api = _safe_dict(primary.get("api"))

    sev = _s(item.get("severity", "UNKNOWN")).upper()

    # Discord embed colors (int)
    color_map = {
        "CRITICAL": 15158332,  # red
        "HIGH": 15105570,  # orange
        "MEDIUM": 15844367,  # yellow
        "LOW": 3447003,  # blue
    }

    playbook = _s(item.get("playbook"), "No playbook provided.")
    alert_id = _s(item.get("alert_id"), "")
    alert_key = _s(item.get("alert_key"), "")

    footer_bits = []
    if alert_id:
        footer_bits.append(f"alert_id: {alert_id}")
    if alert_key:
        footer_bits.append(f"alert_key: {alert_key}")

    return {
        "embeds": [
            {
                "title": _alert_title(item),
                "color": color_map.get(sev, 9807270),
                "fields": [
                    {"name": "User", "value": _s(actor.get("user_name"), "-"), "inline": True},
                    {
                        "name": "Source IP",
                        "value": _s(network.get("source_ip"), "-"),
                        "inline": True,
                    },
                    {
                        "name": "Operation",
                        "value": _s(api.get("operation"), _s(primary.get("activity_name"), "-")),
                        "inline": True,
                    },
                    {"name": "Matches", "value": _s(item.get("match_count"), "1"), "inline": True},
                    {"name": "Playbook", "value": playbook, "inline": False},
                ],
                "footer": {"text": " | ".join(footer_bits)} if footer_bits else {"text": "OpenCDR"},
            }
        ]
    }


# ----------------------------
# Email message builder (plain text for SNS)
# ----------------------------


def build_email_message(item: dict[str, Any]) -> tuple[str, str]:
    """Returns (subject, plain-text body) for SNS email delivery."""
    primary = _safe_dict(item.get("primary_signal")) or item

    actor = _safe_dict(primary.get("actor"))
    network = _safe_dict(primary.get("network"))
    api = _safe_dict(primary.get("api"))

    severity = _s(item.get("severity", "UNKNOWN")).upper()
    rule_id = _s(item.get("rule_id"), "unknown_rule")
    alert_id = _s(item.get("alert_id"), "")
    alert_key = _s(item.get("alert_key"), "")
    playbook = _s(item.get("playbook"), "No playbook provided.")
    match_count = _s(item.get("match_count"), "1")

    user = _s(actor.get("user_name"), "-")
    ip = _s(network.get("source_ip"), "-")
    operation = _s(api.get("operation"), _s(primary.get("activity_name"), "-"))

    subject = f"[OpenCDR] {severity} – {rule_id}"

    lines = [
        f"Severity:  {severity}",
        f"Rule:      {rule_id}",
        f"User:      {user}",
        f"Source IP: {ip}",
        f"Action:    {operation}",
        f"Matches:   {match_count}",
        "",
        "Recommended Response:",
        playbook,
    ]

    refs = _safe_list(item.get("signal_refs"))[:5]
    if refs:
        lines += ["", "Related Signals:"]
        for r in refs:
            if not isinstance(r, dict):
                continue
            ts = _s(r.get("timestamp"))
            rid = _s(r.get("rule_id"))
            did = _s(r.get("detection_id"))
            lines.append(f"  {ts}  {rid}  {did[:8]}")

    if alert_id:
        lines += ["", f"Alert ID:  {alert_id}"]
    if alert_key:
        lines.append(f"Alert Key: {alert_key}")

    return subject, "\n".join(lines)


# ----------------------------
# Remediation-success payload builders (responder's outbox item, not an
# alert -- distinct "type": "remediation_success" shape, green everywhere)
# ----------------------------

_REMEDIATION_COLOR_SLACK = "#2e7d32"
_REMEDIATION_COLOR_DISCORD = 3066993  # discord.js GREEN constant, matches the palette severity_colors/color_map already use


def build_remediation_success_slack_payload(item: dict[str, Any]) -> dict[str, Any]:
    rule_id = _s(item.get("rule_id"), "unknown_rule")
    response_module = _s(item.get("response_module"), "-")
    target = _s(item.get("target"), "-")
    detection_id = _s(item.get("detection_id"), "")

    blocks = [
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*REMEDIATED*\n*{rule_id}*"},
        },
        {"type": "divider"},
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Action*\n`{response_module}`"},
                {"type": "mrkdwn", "text": f"*Target*\n`{target}`"},
            ],
        },
    ]
    if detection_id:
        blocks.append(
            {"type": "context", "elements": [{"type": "mrkdwn", "text": f"detection_id `{detection_id}`"}]}
        )

    return {"attachments": [{"color": _REMEDIATION_COLOR_SLACK, "blocks": blocks}]}


def build_remediation_success_discord_payload(item: dict[str, Any]) -> dict[str, Any]:
    rule_id = _s(item.get("rule_id"), "unknown_rule")

    return {
        "embeds": [
            {
                "title": f"REMEDIATED — {rule_id}",
                "color": _REMEDIATION_COLOR_DISCORD,
                "fields": [
                    {"name": "Action", "value": _s(item.get("response_module"), "-"), "inline": True},
                    {"name": "Target", "value": _s(item.get("target"), "-"), "inline": True},
                ],
                "footer": {"text": f"detection_id: {item.get('detection_id')}" if item.get("detection_id") else "OpenCDR"},
            }
        ]
    }


def build_remediation_success_email_message(item: dict[str, Any]) -> tuple[str, str]:
    rule_id = _s(item.get("rule_id"), "unknown_rule")
    subject = f"[OpenCDR] Remediated – {rule_id}"
    lines = [
        "Status:    REMEDIATED",
        f"Rule:      {rule_id}",
        f"Action:    {_s(item.get('response_module'), '-')}",
        f"Target:    {_s(item.get('target'), '-')}",
    ]
    if item.get("detection_id"):
        lines += ["", f"Detection ID: {item.get('detection_id')}"]
    return subject, "\n".join(lines)


# ----------------------------
# Security Hub finding builder (ASFF)
# ----------------------------

_SECURITYHUB_SEVERITY: dict[str, tuple[str, int]] = {
    "CRITICAL": ("CRITICAL", 90),
    "HIGH": ("HIGH", 70),
    "MEDIUM": ("MEDIUM", 40),
    "LOW": ("LOW", 25),
    "INFO": ("INFORMATIONAL", 5),
    "INFORMATIONAL": ("INFORMATIONAL", 5),
}


def _iso8601_z(ts: str) -> str:
    """Ensure an ISO-8601 timestamp has a Z suffix (Security Hub requirement)."""
    if not ts:
        return ts
    if ts.endswith("Z") or "+" in ts:
        return ts
    return ts + "Z"


def build_securityhub_finding(
    item: dict[str, Any],
    *,
    product_arn: str,
    account_id: str,
) -> dict[str, Any]:
    """Convert an OpenCDR alert/signal into an ASFF finding for Security Hub."""
    primary = _safe_dict(item.get("primary_signal")) or item

    actor = _safe_dict(primary.get("actor"))
    api = _safe_dict(primary.get("api"))

    severity_str = _s(item.get("severity", "UNKNOWN")).upper()
    label, normalized = _SECURITYHUB_SEVERITY.get(severity_str, ("INFORMATIONAL", 1))

    rule_id = _s(item.get("rule_id"), "unknown_rule")
    alert_id = _s(item.get("alert_id"), _s(item.get("detection_id"), "unknown"))
    timestamp = _iso8601_z(_s(item.get("timestamp"), ""))

    activity_name = _s(primary.get("activity_name"), _s(api.get("operation"), rule_id))
    playbook = _s(item.get("playbook"), "No playbook provided.")

    user_arn = _s(actor.get("arn"), "")
    user_name = _s(actor.get("user_name"), "")
    monitored_account = _s(actor.get("account_id"), account_id)

    title = f"{rule_id}: {activity_name}"[:256]
    description = playbook[:1024]

    if user_arn:
        resource = {"Type": "AwsIamUser", "Id": user_arn}
    elif user_name:
        resource = {
            "Type": "AwsIamUser",
            "Id": f"arn:aws:iam::{monitored_account}:user/{user_name}",
        }
    else:
        resource = {"Type": "AwsAccount", "Id": f"arn:aws:iam::{monitored_account}:root"}

    finding_types = ["Software and Configuration Checks/AWS Security Best Practices"]

    return {
        "SchemaVersion": "2018-10-08",
        "Id": f"{product_arn}/finding/{alert_id}",
        "ProductArn": product_arn,
        "GeneratorId": f"opencdr/{rule_id}",
        "AwsAccountId": monitored_account,
        "Types": finding_types,
        "CreatedAt": timestamp,
        "UpdatedAt": timestamp,
        "Severity": {"Label": label, "Normalized": normalized},
        "Title": title,
        "Description": description,
        "Resources": [resource],
        "FindingProviderFields": {
            "Severity": {"Label": label},
            "Types": finding_types,
        },
        "Workflow": {"Status": "NEW"},
        "RecordState": "ACTIVE",
    }


# ----------------------------
# Webhook sender (stdlib, no extra deps)
# ----------------------------


def _post_json(
    url: str,
    payload: dict[str, Any],
    *,
    extra_headers: dict[str, str] | None = None,
    timeout: int = 10,
) -> tuple[int, str]:
    if urllib.parse.urlparse(url).scheme != "https":
        raise ValueError(f"URL must use HTTPS, got: {url!r}")
    data = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json", "User-Agent": "opencdr-notifier/1.0"}
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(url=url, data=data, headers=headers, method="POST")

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310 -- scheme is validated https-only above (line 548); bandit can't see the data-flow link to this urlopen call
            body = resp.read().decode("utf-8", errors="replace")
            return resp.status, body
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            body = "<no body>"
        return int(getattr(e, "code", 0) or 0), body


def _post_json_basic_auth(
    url: str,
    payload: dict[str, Any],
    *,
    email: str,
    token: str,
    timeout: int = 10,
) -> tuple[int, str]:
    credentials = base64.b64encode(f"{email}:{token}".encode()).decode()
    return _post_json(
        url,
        payload,
        extra_headers={"Authorization": f"Basic {credentials}", "Accept": "application/json"},
        timeout=timeout,
    )


# ----------------------------
# Jira issue builder (Atlassian Document Format)
# ----------------------------

_JIRA_PRIORITY: dict[str, str] = {
    "CRITICAL": "Highest",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "INFO": "Lowest",
    "INFORMATIONAL": "Lowest",
}


def _adf_text(t: str) -> dict:
    return {"type": "text", "text": t}


def _adf_para(*texts: str) -> dict:
    return {"type": "paragraph", "content": [_adf_text(t) for t in texts]}


def build_jira_issue(
    item: dict[str, Any],
    *,
    project_key: str,
    issue_type: str = "Bug",
) -> dict[str, Any]:
    """Convert an OpenCDR alert/signal into a Jira issue payload (ADF description)."""
    primary = _safe_dict(item.get("primary_signal")) or item

    actor = _safe_dict(primary.get("actor"))
    network = _safe_dict(primary.get("network"))
    api = _safe_dict(primary.get("api"))

    severity = _s(item.get("severity", "UNKNOWN")).upper()
    rule_id = _s(item.get("rule_id"), "unknown_rule")
    alert_id = _s(item.get("alert_id"), _s(item.get("detection_id"), ""))
    activity_name = _s(primary.get("activity_name"), _s(api.get("operation"), rule_id))
    playbook = _s(item.get("playbook"), "No playbook provided.")
    user_name = _s(actor.get("user_name"), "-")
    source_ip = _s(network.get("source_ip"), "-")
    match_count = _s(item.get("match_count"), "1")
    timestamp = _s(item.get("timestamp"), "")

    priority = _JIRA_PRIORITY.get(severity, "Medium")
    summary = f"[{severity}] {rule_id}: {activity_name}"[:255]

    content = [
        _adf_para(f"Severity: {severity}"),
        _adf_para(f"Rule: {rule_id}"),
        _adf_para(f"User: {user_name}"),
        _adf_para(f"Source IP: {source_ip}"),
        _adf_para(f"Action: {activity_name}"),
        _adf_para(f"Matches: {match_count}"),
        _adf_para(f"Time: {timestamp}"),
        {"type": "rule"},
        _adf_para("Recommended Response:"),
        _adf_para(playbook),
    ]

    if alert_id:
        content.append(_adf_para(f"Alert ID: {alert_id}"))

    return {
        "fields": {
            "project": {"key": project_key},
            "summary": summary,
            "description": {"type": "doc", "version": 1, "content": content},
            "issuetype": {"name": issue_type},
            "priority": {"name": priority},
            "labels": ["opencdr"],
        }
    }


_VALID_CHANNELS = ("slack", "discord", "email", "securityhub", "jira", "webhook")


def _route_channels(item: dict[str, Any], settings: dict[str, Any]) -> list[str]:
    """
    Returns a list of channels to send to.

    Routing order:
      1) env NOTIFIER_DEFAULT_CHANNEL if slack/discord/email (explicit override => single channel)
      2) settings.routing[severity]
         - can be "slack" | "discord" | "email"
         - or ["slack", "discord", "email"]
      3) auto fan-out: all enabled channels with required config present
    """
    chs = _safe_dict(settings.get("channels"))
    slack = _safe_dict(chs.get("slack"))
    discord = _safe_dict(chs.get("discord"))
    email = _safe_dict(chs.get("email"))
    securityhub = _safe_dict(chs.get("securityhub"))
    jira = _safe_dict(chs.get("jira"))
    webhook = _safe_dict(chs.get("webhook"))
    routing = _safe_dict(settings.get("routing"))

    # 1) explicit override
    if DEFAULT_CHANNEL in _VALID_CHANNELS:
        return [DEFAULT_CHANNEL]

    # 2) severity routing
    sev = _s(item.get("severity", "UNKNOWN")).upper()
    route = routing.get(sev)

    if isinstance(route, str):
        r = route.lower().strip()
        if r in _VALID_CHANNELS:
            return [r]

    if isinstance(route, list):
        out: list[str] = []
        for r in route:
            rr = _s(r).lower().strip()
            if rr in _VALID_CHANNELS:
                out.append(rr)
        if out:
            # de-dup while keeping order
            seen = set()
            dedup = []
            for x in out:
                if x not in seen:
                    seen.add(x)
                    dedup.append(x)
            return dedup

    # 3) auto fan-out (send to all enabled)
    out = []
    if bool(slack.get("enabled")) and _s(slack.get("webhook_url")).strip():
        out.append("slack")
    if bool(discord.get("enabled")) and _s(discord.get("webhook_url")).strip():
        out.append("discord")
    if bool(email.get("enabled")) and (_s(email.get("topic_arn")).strip() or ALERTS_SNS_TOPIC_ARN):
        out.append("email")
    if bool(securityhub.get("enabled")):
        out.append("securityhub")
    if (
        bool(jira.get("enabled"))
        and _s(jira.get("base_url")).strip()
        and _s(jira.get("project_key")).strip()
        and _s(jira.get("user_email")).strip()
        and _s(jira.get("api_token")).strip()
    ):
        out.append("jira")
    if bool(webhook.get("enabled")) and _safe_list(webhook.get("targets")):
        out.append("webhook")
    return out


# ----------------------------
# Lambda handler
# ----------------------------


def lambda_handler(event, context):
    request_id = context.aws_request_id if context else None

    base_logger = Logger(
        service="OCDR-NOTIFIER",
        source="ocdr.notifier",
        request_id=request_id,
    )

    aws = AwsHandler(logger=base_logger)
    settings = load_global_settings(aws=aws, logger=base_logger)

    # Derive Security Hub product ARN from Lambda execution context (no extra env var needed).
    # Lambda function ARN format: arn:aws:lambda:{region}:{account_id}:function:{name}
    _account_id = context.invoked_function_arn.split(":")[4] if context else ""
    _region = os.getenv("AWS_REGION", "")
    _securityhub_product_arn = (
        f"arn:aws:securityhub:{_region}:{_account_id}:product/{_account_id}/default"
    )

    global_enabled = bool(settings.get("notifications_enabled", False))
    channels = _safe_dict(settings.get("channels"))
    slack = _safe_dict(channels.get("slack"))
    discord = _safe_dict(channels.get("discord"))
    email_cfg = _safe_dict(channels.get("email"))

    records = event.get("Records", []) or []
    base_logger.info(
        event_name="NOTIFIER_START",
        event_type="PROCESSING",
        message="Processing SQS batch",
        details={
            "records": len(records),
            "global_enabled": global_enabled,
            "setting_id": DEFAULT_SETTING_ID,
        },
    )

    processed = 0
    sent = 0
    skipped = 0
    failed = 0

    for record in records:
        processed += 1
        body = record.get("body", "")

        # Parse message (handles publisher wrappers)
        try:
            msg = _json_loads_maybe(body)
            msg = _json_loads_maybe(msg)  # handle nested wrapper once more
            if not isinstance(msg, dict):
                raise ValueError("Message body is not a JSON object")
        except Exception as e:
            failed += 1
            base_logger.error(
                event_name="NOTIFIER_PARSE_FAIL",
                event_type="PROCESSING",
                message="Failed to parse SQS message body as JSON dict",
                details={"error": repr(e)},
            )
            continue

        item = msg

        # bind event_id (only if present & non-empty)
        eid = _pick_event_id(item).strip()
        logger = base_logger.bind(event_id=eid) if eid else base_logger

        # per-item notify
        if item.get("notify") is False:
            skipped += 1
            logger.info(
                event_name="NOTIFIER_SKIP_ITEM_NOTIFY_FALSE",
                event_type="PROCESSING",
                message="notify=false on item; skipping",
                details={"rule_id": item.get("rule_id")},
            )
            continue

        # global toggle
        if not global_enabled:
            skipped += 1
            logger.info(
                event_name="NOTIFIER_SKIP_GLOBAL_DISABLED",
                event_type="PROCESSING",
                message="Global notifications disabled; skipping",
                details={"rule_id": item.get("rule_id")},
            )
            continue
        channels_to_send = _route_channels(item, settings)

        if not channels_to_send:
            skipped += 1
            logger.warning(
                event_name="NOTIFIER_SKIP_NO_CHANNEL",
                event_type="PROCESSING",
                message="No enabled channel configured; skipping",
                details={
                    "rule_id": item.get("rule_id"),
                    "channels_selected": [],
                    "slack_enabled": bool(slack.get("enabled")),
                    "discord_enabled": bool(discord.get("enabled")),
                    "email_enabled": bool(email_cfg.get("enabled")),
                },
            )
            continue

        is_remediation = item.get("type") == "remediation_success"

        for channel in channels_to_send:
            try:
                if is_remediation and channel in ("securityhub", "jira", "webhook"):
                    # These builders assume the full alert shape (severity,
                    # primary_signal, etc.) that a remediation-success item
                    # doesn't have -- scoped to slack/discord/email for now.
                    logger.info(
                        event_name="NOTIFIER_SKIP_REMEDIATION_UNSUPPORTED_CHANNEL",
                        event_type="PROCESSING",
                        message="Remediation-success notifications aren't supported on this channel yet",
                        details={"channel": channel, "rule_id": item.get("rule_id")},
                    )
                    continue

                if channel == "slack":
                    url = _s(slack.get("webhook_url")).strip()
                    if not (bool(slack.get("enabled")) and url):
                        raise RuntimeError("Slack selected but not enabled or webhook_url missing")

                    payload = (
                        build_remediation_success_slack_payload(item)
                        if is_remediation
                        else build_slack_payload(item)
                    )
                    status, resp_body = _post_json(url, payload)
                    if status >= 400:
                        raise RuntimeError(f"Webhook HTTP {status}: {resp_body}")

                    sent += 1
                    logger.info(
                        event_name="NOTIFIER_SENT_SLACK",
                        event_type="PROCESSING",
                        message="Sent notification to Slack",
                        details={"http_status": status, "rule_id": item.get("rule_id")},
                    )

                elif channel == "discord":
                    url = _s(discord.get("webhook_url")).strip()
                    if not (bool(discord.get("enabled")) and url):
                        raise RuntimeError(
                            "Discord selected but not enabled or webhook_url missing"
                        )

                    payload = (
                        build_remediation_success_discord_payload(item)
                        if is_remediation
                        else build_discord_payload(item)
                    )
                    status, resp_body = _post_json(url, payload)
                    if status >= 400:
                        raise RuntimeError(f"Webhook HTTP {status}: {resp_body}")

                    sent += 1
                    logger.info(
                        event_name="NOTIFIER_SENT_DISCORD",
                        event_type="PROCESSING",
                        message="Sent notification to Discord",
                        details={"http_status": status, "rule_id": item.get("rule_id")},
                    )

                elif channel == "email":
                    topic_arn = _s(email_cfg.get("topic_arn")).strip() or ALERTS_SNS_TOPIC_ARN
                    if not (bool(email_cfg.get("enabled")) and topic_arn):
                        raise RuntimeError(
                            "Email selected but not enabled or topic_arn/ALERTS_SNS_TOPIC_ARN missing"
                        )

                    subject, body = (
                        build_remediation_success_email_message(item)
                        if is_remediation
                        else build_email_message(item)
                    )
                    aws._sns.publish(TopicArn=topic_arn, Subject=subject, Message=body)

                    sent += 1
                    logger.info(
                        event_name="NOTIFIER_SENT_EMAIL",
                        event_type="PROCESSING",
                        message="Sent notification to email via SNS",
                        details={"topic_arn": topic_arn, "rule_id": item.get("rule_id")},
                    )

                elif channel == "securityhub":
                    sh_cfg = _safe_dict(channels.get("securityhub"))
                    if not bool(sh_cfg.get("enabled")):
                        raise RuntimeError("Security Hub selected but not enabled in settings")
                    if not _securityhub_product_arn:
                        raise RuntimeError("Cannot derive Security Hub product ARN (missing account/region)")

                    finding = build_securityhub_finding(
                        item,
                        product_arn=_securityhub_product_arn,
                        account_id=_account_id,
                    )
                    resp = aws._securityhub.batch_import_findings(Findings=[finding])
                    failed_count = resp.get("FailedCount", 0)
                    if failed_count:
                        failures = resp.get("FailedFindings", [])
                        raise RuntimeError(
                            f"Security Hub rejected finding: {failures[0].get('ErrorMessage', 'unknown error')}"
                        )

                    sent += 1
                    logger.info(
                        event_name="NOTIFIER_SENT_SECURITYHUB",
                        event_type="PROCESSING",
                        message="Sent finding to Security Hub",
                        details={
                            "finding_id": finding["Id"],
                            "rule_id": item.get("rule_id"),
                        },
                    )

                elif channel == "jira":
                    jira_cfg = _safe_dict(channels.get("jira"))
                    if not bool(jira_cfg.get("enabled")):
                        raise RuntimeError("Jira selected but not enabled in settings")

                    base_url = _s(jira_cfg.get("base_url")).rstrip("/")
                    project_key = _s(jira_cfg.get("project_key")).strip()
                    user_email = _s(jira_cfg.get("user_email")).strip()
                    api_token = _s(jira_cfg.get("api_token")).strip()
                    issue_type = _s(jira_cfg.get("issue_type"), "Bug").strip() or "Bug"

                    if not all([base_url, project_key, user_email, api_token]):
                        raise RuntimeError(
                            "Jira channel missing required config: base_url, project_key, user_email, api_token"
                        )

                    issue_payload = build_jira_issue(
                        item, project_key=project_key, issue_type=issue_type
                    )
                    status, resp_body = _post_json_basic_auth(
                        f"{base_url}/rest/api/3/issue",
                        issue_payload,
                        email=user_email,
                        token=api_token,
                    )
                    if status >= 400:
                        raise RuntimeError(f"Jira API HTTP {status}: {resp_body}")

                    try:
                        issue_key = json.loads(resp_body).get("key", "unknown")
                    except Exception:
                        issue_key = "unknown"

                    sent += 1
                    logger.info(
                        event_name="NOTIFIER_SENT_JIRA",
                        event_type="PROCESSING",
                        message="Created Jira issue",
                        details={"issue_key": issue_key, "rule_id": item.get("rule_id")},
                    )

                elif channel == "webhook":
                    webhook_cfg = _safe_dict(channels.get("webhook"))
                    if not bool(webhook_cfg.get("enabled")):
                        raise RuntimeError("Webhook channel selected but not enabled in settings")
                    targets = _safe_list(webhook_cfg.get("targets"))
                    if not targets:
                        raise RuntimeError("Webhook channel has no targets configured")

                    # Each target is counted independently — partial failures are visible.
                    for target in targets:
                        target_name = _s(target.get("name"), "unnamed")
                        target_url = _s(target.get("url")).strip()
                        target_headers = _safe_dict(target.get("headers")) or None

                        if not target_url:
                            logger.warning(
                                event_name="NOTIFIER_WEBHOOK_TARGET_SKIP",
                                event_type="PROCESSING",
                                message="Webhook target has no URL; skipping",
                                details={"webhook_name": target_name, "rule_id": item.get("rule_id")},
                            )
                            continue

                        try:
                            t_status, t_body = _post_json(
                                target_url, item, extra_headers=target_headers
                            )
                            if t_status >= 400:
                                raise RuntimeError(f"HTTP {t_status}: {t_body}")
                            sent += 1
                            logger.info(
                                event_name="NOTIFIER_SENT_WEBHOOK",
                                event_type="PROCESSING",
                                message="Sent alert to custom webhook",
                                details={
                                    "webhook_name": target_name,
                                    "http_status": t_status,
                                    "rule_id": item.get("rule_id"),
                                },
                            )
                        except Exception as target_err:
                            failed += 1
                            logger.error(
                                event_name="NOTIFIER_WEBHOOK_TARGET_FAIL",
                                event_type="PROCESSING",
                                message="Failed to send alert to custom webhook",
                                details={
                                    "webhook_name": target_name,
                                    "error": repr(target_err),
                                    "rule_id": item.get("rule_id"),
                                },
                            )

                else:
                    skipped += 1
                    logger.warning(
                        event_name="NOTIFIER_SKIP_UNKNOWN_CHANNEL",
                        event_type="PROCESSING",
                        message="Unknown channel selected; skipping",
                        details={"rule_id": item.get("rule_id"), "channel_selected": channel},
                    )

            except Exception as e:
                failed += 1
                logger.error(
                    event_name="NOTIFIER_SEND_FAIL",
                    event_type="PROCESSING",
                    message="Failed to send notification",
                    details={"error": repr(e), "rule_id": item.get("rule_id"), "channel": channel},
                )
    base_logger.info(
        event_name="NOTIFIER_DONE",
        event_type="PROCESSING",
        message="Finished processing SQS batch",
        details={"processed": processed, "sent": sent, "skipped": skipped, "failed": failed},
    )

    return {"processed": processed, "sent": sent, "skipped": skipped, "failed": failed}

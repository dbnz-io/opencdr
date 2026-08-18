#!/usr/bin/env python3
"""
opencdr — OpenCDR management CLI

Usage:
  opencdr.py config set --url <api_url> --key <api_key>
  opencdr.py config show

  opencdr.py status

  opencdr.py rules load    [--dry-run]
  opencdr.py rules list    [--kind signal|correlation|list] [--page-size N]
  opencdr.py rules get     <rule_id> --kind signal|correlation
  opencdr.py rules delete  <rule_id> --kind signal|correlation

  opencdr.py lists create <list_id> [--description <desc>] [--values v1 v2 ...]
  opencdr.py lists list
  opencdr.py lists show   <list_id>
  opencdr.py lists add    <list_id> <value>
  opencdr.py lists remove <list_id> <value>
  opencdr.py lists delete <list_id>

  opencdr.py settings get    [<setting_id>]
  opencdr.py settings set    [<setting_id>] (--file <json> | --slack-webhook <url> | --discord-webhook <url> | --email-topic-arn <arn> | --enable-securityhub | --jira-url <url> --jira-project <key> --jira-email <email> --jira-token <token> | --webhook-url <url> [--webhook-name <name>] [--webhook-header key=value]... | --guardduty-notify-default <true|false> | --guardduty-notify-severity <SEVERITY=true|false>... | --guardduty-notify-service <SERVICE=true|false>... | --guardduty-notify-severity-service <SEVERITY:SERVICE=true|false>...)
  opencdr.py settings delete [<setting_id>]

  opencdr.py signals list  --severity <sev> | --event-id <id> | --category <cat>
  opencdr.py logs    list  --service  <svc> | --event-id <id> | --event-name  <name>

  opencdr.py ir-actions list     [--page-size N]
  opencdr.py ir-actions get      <detection_id>
  opencdr.py ir-actions rollback <detection_id>

  opencdr.py test local    [--event <filter>] [--rule <filter>]
  opencdr.py test deployed [--stage <stage>] [--region <region>] [--event <filter>]

Config is stored in .opencdr.json at the project root.
Override with OPENCDR_API_URL / OPENCDR_API_KEY environment variables.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

ROOT = Path(__file__).parent.parent
RULES_DIR = ROOT / "support_files" / "detection_rules"
EVENTS_DIR = ROOT / "support_files" / "test_events"
CONFIG_FILE = ROOT / ".opencdr.json"

# ---------------------------------------------------------------------------
# ANSI colours
# ---------------------------------------------------------------------------

_NO_COLOR = not sys.stdout.isatty() or os.getenv("NO_COLOR")

_RESET = "\033[0m"
_RED = "\033[31m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_CYAN = "\033[36m"
_BOLD = "\033[1m"
_DIM = "\033[2m"

_SEV_COLOR: dict[str, str] = {
    "CRITICAL": _RED + _BOLD,
    "HIGH": _RED,
    "MEDIUM": _YELLOW,
    "LOW": _CYAN,
}


def _c(text: str, code: str) -> str:
    return text if _NO_COLOR else f"{code}{text}{_RESET}"


def ok(t: str) -> str:    return _c(t, _GREEN)
def err(t: str) -> str:   return _c(t, _RED)
def warn(t: str) -> str:  return _c(t, _YELLOW)
def info(t: str) -> str:  return _c(t, _CYAN)
def bold(t: str) -> str:  return _c(t, _BOLD)
def dim(t: str) -> str:   return _c(t, _DIM)


def color_sev(sev: str) -> str:
    return _c(sev, _SEV_COLOR.get(sev.upper(), ""))


def _banner(title: str) -> None:
    print(f"\n{bold('OpenCDR')} — {title}")
    print("─" * 54)


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

def _load_config() -> dict:
    if CONFIG_FILE.exists():
        return json.loads(CONFIG_FILE.read_text())
    return {}


def _save_config(data: dict) -> None:
    CONFIG_FILE.write_text(json.dumps(data, indent=2) + "\n")


def _require_api(cfg: dict) -> tuple[str, str]:
    url = os.getenv("OPENCDR_API_URL") or cfg.get("url", "")
    key = os.getenv("OPENCDR_API_KEY") or cfg.get("key", "")
    missing = []
    if not url:
        missing.append("url")
    if not key:
        missing.append("key")
    if missing:
        print(err(f"  Missing config: {', '.join(missing)}"))
        print(f"  Run: {bold('opencdr.py config set --url <url> --key <key>')}")
        sys.exit(1)
    return url.rstrip("/"), key


# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------

def _request(method: str, path: str, url: str, key: str, **kwargs: Any) -> tuple[int, Any]:
    try:
        import requests as _r
    except ImportError:
        print(err("  requests is not installed — pip install requests"))
        sys.exit(1)

    headers = {"x-api-key": key, "Content-Type": "application/json"}
    resp = _r.request(method, f"{url}{path}", headers=headers, timeout=15, **kwargs)
    try:
        return resp.status_code, resp.json()
    except Exception:
        return resp.status_code, resp.text


def _die_on_error(status: int, body: Any, context: str = "") -> None:
    if status >= 400:
        msg = body.get("message", body) if isinstance(body, dict) else body
        prefix = f"  {context}: " if context else "  "
        print(err(f"{prefix}HTTP {status} — {msg}"))
        sys.exit(1)


# ---------------------------------------------------------------------------
# config set / show
# ---------------------------------------------------------------------------

def cmd_config_set(args: argparse.Namespace) -> None:
    if not args.url and not args.key:
        print(err("  Provide at least --url or --key"))
        sys.exit(1)
    cfg = _load_config()
    if args.url:
        cfg["url"] = args.url
    if args.key:
        cfg["key"] = args.key
    _save_config(cfg)
    key_preview = (cfg.get("key") or "")[:8]
    print(ok("  Config saved."))
    print(f"  URL : {cfg.get('url', dim('(not set)'))}")
    print(f"  Key : {key_preview}{'...' if key_preview else dim('(not set)')}")


def cmd_config_show(args: argparse.Namespace) -> None:
    cfg = _load_config()
    if not cfg:
        print(warn("  No config found."))
        print(f"  Run: {bold('opencdr.py config set --url <url> --key <key>')}")
        return
    key = cfg.get("key") or ""
    print(f"  URL : {cfg.get('url') or dim('(not set)')}")
    print(f"  Key : {key[:8]}{'...' if key else dim('(not set)')}")


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------

def cmd_status(args: argparse.Namespace) -> None:
    cfg = _load_config()
    url, key = _require_api(cfg)
    status, body = _request("GET", "/status", url, key)
    _die_on_error(status, body, "status")
    print(ok(f"  API online"))
    print(f"  Service    : {body.get('service', '')}")
    print(f"  Time       : {body.get('time', '')}")
    print(f"  Request ID : {body.get('request_id', '')}")


# ---------------------------------------------------------------------------
# rules load / list / get / delete
# ---------------------------------------------------------------------------

_SKIP_RULE_FILES = {
    "test_atomic_rule.json",
    "test_correlation_rule.json",
    "test_detection_rule.json",
}


def cmd_rules_load(args: argparse.Namespace) -> None:
    cfg = _load_config()
    url, key = _require_api(cfg)
    _banner("Load Detection Rules")

    # Recursive: rule files live in per-source subfolders (cloudtrail/,
    # guardduty/, and any future source folder added the same way -- see
    # docs/detection-rules.md#authoring-testing-and-loading) rather than
    # flat in RULES_DIR itself.
    files = sorted(RULES_DIR.rglob("*.json"))
    if not files:
        print(warn(f"  No rule files found in {RULES_DIR.relative_to(ROOT)}"))
        return

    loaded = skipped = failed = 0

    for path in files:
        label = path.relative_to(RULES_DIR)
        if path.name in _SKIP_RULE_FILES:
            print(f"  {warn('[SKIP]')}  {label} (test stub)")
            skipped += 1
            continue

        try:
            rule = json.loads(path.read_text())
        except json.JSONDecodeError as e:
            print(f"  {err('[ERROR]')} {label} — invalid JSON: {e}")
            failed += 1
            continue

        rule_id = rule.get("rule_id") or ""
        rule_kind = rule.get("rule_kind") or ""
        if not rule_id or not rule_kind:
            print(f"  {err('[ERROR]')} {label} — missing rule_id or rule_kind")
            failed += 1
            continue

        if args.dry_run:
            print(f"  {info('[DRY]')}   {label}  ({rule_kind} / {rule_id})")
            loaded += 1
            continue

        # PUT = upsert — safe to re-run
        status, body = _request(
            "PUT", f"/rules/{rule_id}?rule_kind={rule_kind}", url, key, json=rule
        )
        if status in (200, 201):
            print(f"  {ok('[OK]')}    {label}  ({rule_kind} / {rule_id})")
            loaded += 1
        else:
            msg = body.get("message", body) if isinstance(body, dict) else body
            print(f"  {err('[ERROR]')} {label} — HTTP {status}: {msg}")
            failed += 1

    print()
    print(f"  Loaded  : {ok(str(loaded))}")
    print(f"  Skipped : {str(skipped)}")
    print(f"  Failed  : {err(str(failed)) if failed else str(failed)}")
    print()
    if failed:
        sys.exit(1)


def cmd_rules_list(args: argparse.Namespace) -> None:
    cfg = _load_config()
    url, key = _require_api(cfg)

    qs: dict[str, Any] = {"page_size": args.page_size}
    if args.kind:
        qs["rule_kind"] = args.kind
    if args.next_token:
        qs["next_token"] = args.next_token
    query = "&".join(f"{k}={v}" for k, v in qs.items())

    status, body = _request("GET", f"/rules?{query}", url, key)
    _die_on_error(status, body, "rules list")

    items = body.get("items", [])
    if not items:
        print(warn("  No rules found."))
        return

    print(f"\n  {'RULE_ID':<45} {'KIND':<15} {'SEVERITY':<10} ENABLED")
    print("  " + "─" * 82)
    for r in items:
        sev = r.get("severity") or ""
        enabled_label = ok("yes") if r.get("enabled") else err("no")
        print(
            f"  {r.get('rule_id', ''):<45} "
            f"{r.get('rule_kind', ''):<15} "
            f"{color_sev(sev):<10} "
            f"{enabled_label}"
        )

    if body.get("has_next"):
        print(f"\n  {dim('More pages — use --next-token ' + str(body.get('next_token')))}")
    print()


def cmd_rules_get(args: argparse.Namespace) -> None:
    cfg = _load_config()
    url, key = _require_api(cfg)
    status, body = _request(
        "GET", f"/rules/{args.rule_id}?rule_kind={args.kind}", url, key
    )
    if status == 404:
        print(warn(f"  Rule not found: {args.rule_id}"))
        sys.exit(1)
    _die_on_error(status, body)
    print(json.dumps(body, indent=2, default=str))


def cmd_rules_delete(args: argparse.Namespace) -> None:
    cfg = _load_config()
    url, key = _require_api(cfg)
    status, body = _request(
        "DELETE", f"/rules/{args.rule_id}?rule_kind={args.kind}", url, key
    )
    if status == 404:
        print(warn(f"  Rule not found: {args.rule_id}"))
        sys.exit(1)
    _die_on_error(status, body)
    print(ok(f"  Deleted: {args.rule_id}"))


# ---------------------------------------------------------------------------
# settings get / set / delete
# ---------------------------------------------------------------------------

def cmd_settings_get(args: argparse.Namespace) -> None:
    cfg = _load_config()
    url, key = _require_api(cfg)
    status, body = _request("GET", f"/settings/{args.setting_id}", url, key)
    if status == 404:
        print(warn(f"  Settings '{args.setting_id}' not found."))
        return
    _die_on_error(status, body)
    print(json.dumps(body, indent=2, default=str))


def _merge_channels(existing: dict, new_channels: dict) -> dict:
    """
    Merge new channel config into the existing one without clobbering untouched channels.

    Rules:
    - Slack / Discord / Email / Security Hub / Jira: new config replaces that channel only.
    - webhook.targets: new targets are appended; if a target with the same name already
      exists it is replaced in-place so duplicates never accumulate.
    """
    merged = dict(existing)
    for channel, new_cfg in new_channels.items():
        if channel == "webhook" and "webhook" in existing:
            existing_targets = existing["webhook"].get("targets") or []
            new_targets = new_cfg.get("targets") or []
            new_names = {t.get("name") for t in new_targets}
            kept = [t for t in existing_targets if t.get("name") not in new_names]
            merged["webhook"] = {
                **existing["webhook"],
                **new_cfg,
                "targets": kept + new_targets,
            }
        else:
            merged[channel] = new_cfg
    return merged


def _build_channels_from_args(args: argparse.Namespace) -> dict:
    """Turn CLI flags into a channels dict (only the channels explicitly provided)."""
    channels: dict = {}
    if args.slack_webhook:
        channels["slack"] = {"enabled": True, "webhook_url": args.slack_webhook}
    if args.discord_webhook:
        channels["discord"] = {"enabled": True, "webhook_url": args.discord_webhook}
    if args.email_topic_arn:
        channels["email"] = {"enabled": True, "topic_arn": args.email_topic_arn}
    if args.enable_securityhub:
        channels["securityhub"] = {"enabled": True}
    jira_fields = [args.jira_url, args.jira_project, args.jira_email, args.jira_token]
    if any(jira_fields):
        if not all(jira_fields):
            print(err("  Jira requires all four flags: --jira-url, --jira-project, --jira-email, --jira-token"))
            sys.exit(1)
        channels["jira"] = {
            "enabled": True,
            "base_url": args.jira_url,
            "project_key": args.jira_project,
            "user_email": args.jira_email,
            "api_token": args.jira_token,
        }
        if args.jira_issue_type:
            channels["jira"]["issue_type"] = args.jira_issue_type
    if args.webhook_url:
        headers: dict = {}
        for h in args.webhook_headers or []:
            if "=" not in h:
                print(err(f"  Invalid header format '{h}' — expected key=value"))
                sys.exit(1)
            k, _, v = h.partition("=")
            headers[k.strip()] = v.strip()
        channels["webhook"] = {
            "enabled": True,
            "targets": [
                {
                    "name": args.webhook_name or "default",
                    "url": args.webhook_url,
                    "headers": headers,
                }
            ],
        }
    return channels


def _parse_bool_flag(value: str, flag_name: str) -> bool:
    v = value.strip().lower()
    if v in ("true", "1", "yes"):
        return True
    if v in ("false", "0", "no"):
        return False
    print(err(f"  Invalid value for {flag_name}: '{value}' — expected true or false"))
    sys.exit(1)


def _parse_key_bool_pairs(pairs: list[str] | None, flag_name: str) -> dict:
    """Parse repeated `<key>=<true|false>` flags (e.g. --guardduty-notify-severity CRITICAL=true)."""
    out: dict = {}
    for pair in pairs or []:
        if "=" not in pair:
            print(err(f"  Invalid format '{pair}' for {flag_name} — expected key=true|false"))
            sys.exit(1)
        k, _, v = pair.partition("=")
        out[k.strip()] = _parse_bool_flag(v, flag_name)
    return out


def _build_guardduty_notify_from_args(args: argparse.Namespace) -> dict:
    """
    Turn --guardduty-notify-* flags into a partial guardduty_notify dict
    (only the fields explicitly provided). See docs/notifications.md#guardduty-notifications
    for the schema and lookup precedence (by_severity_and_service > by_service >
    by_severity > default).
    """
    gd: dict = {}
    if args.guardduty_notify_default is not None:
        gd["default"] = _parse_bool_flag(args.guardduty_notify_default, "--guardduty-notify-default")
    by_severity = _parse_key_bool_pairs(args.guardduty_notify_severity, "--guardduty-notify-severity")
    if by_severity:
        gd["by_severity"] = by_severity
    by_service = _parse_key_bool_pairs(args.guardduty_notify_service, "--guardduty-notify-service")
    if by_service:
        gd["by_service"] = by_service
    by_severity_and_service = _parse_key_bool_pairs(
        args.guardduty_notify_severity_service, "--guardduty-notify-severity-service"
    )
    if by_severity_and_service:
        gd["by_severity_and_service"] = by_severity_and_service
    return gd


def _merge_guardduty_notify(existing: dict, new: dict) -> dict:
    """
    Merge new guardduty_notify fields into the existing config.

    Rules:
    - default: new value replaces if provided.
    - by_severity / by_service / by_severity_and_service: merged key-by-key
      (same philosophy as _merge_channels's webhook.targets) so setting one
      severity/service doesn't wipe out others configured earlier.
    """
    merged = dict(existing)
    if "default" in new:
        merged["default"] = new["default"]
    for sub_key in ("by_severity", "by_service", "by_severity_and_service"):
        if sub_key in new:
            merged[sub_key] = {**(existing.get(sub_key) or {}), **new[sub_key]}
    return merged


def _fetch_existing_settings(url: str, key: str, setting_id: str) -> tuple[dict, dict]:
    """
    GET current settings and return (base_payload, existing_channels).
    base_payload contains all top-level fields except 'channels'.
    Returns empty dicts if the settings don't exist yet.
    """
    status, body = _request("GET", f"/settings/{setting_id}", url, key)
    if status == 404 or not isinstance(body, dict):
        return {"notifications_enabled": True}, {}
    existing_channels = body.get("channels") or {}
    base_payload = {k: v for k, v in body.items() if k != "channels"}
    base_payload.setdefault("notifications_enabled", True)
    return base_payload, existing_channels


def cmd_settings_set(args: argparse.Namespace) -> None:
    cfg = _load_config()
    url, key = _require_api(cfg)

    # --file: full payload replace, no merging
    if args.file:
        payload = json.loads(Path(args.file).read_text())
        status, body = _request("PUT", f"/settings/{args.setting_id}", url, key, json=payload)
        _die_on_error(status, body)
        print(ok(f"  Settings '{args.setting_id}' saved."))
        print(json.dumps(body, indent=2, default=str))
        return

    new_channels = _build_channels_from_args(args)
    new_guardduty_notify = _build_guardduty_notify_from_args(args)
    if not new_channels and not new_guardduty_notify:
        print(err(
            "  Provide --file, --slack-webhook, --discord-webhook, --email-topic-arn, --enable-securityhub, "
            "--jira-url/--jira-project/--jira-email/--jira-token, --webhook-url, or one of "
            "--guardduty-notify-default/--guardduty-notify-severity/--guardduty-notify-service/"
            "--guardduty-notify-severity-service"
        ))
        sys.exit(1)

    base_payload, existing_channels = _fetch_existing_settings(url, key, args.setting_id)
    merged_channels = _merge_channels(existing_channels, new_channels)
    payload = {**base_payload, "channels": merged_channels}
    if new_guardduty_notify:
        payload["guardduty_notify"] = _merge_guardduty_notify(
            base_payload.get("guardduty_notify") or {}, new_guardduty_notify
        )

    status, body = _request("PUT", f"/settings/{args.setting_id}", url, key, json=payload)
    _die_on_error(status, body)
    print(ok(f"  Settings '{args.setting_id}' saved."))
    print(json.dumps(body, indent=2, default=str))


def cmd_settings_delete(args: argparse.Namespace) -> None:
    cfg = _load_config()
    url, key = _require_api(cfg)
    status, body = _request("DELETE", f"/settings/{args.setting_id}", url, key)
    if status == 404:
        print(warn(f"  Settings '{args.setting_id}' not found."))
        return
    _die_on_error(status, body)
    print(ok(f"  Deleted settings: {args.setting_id}"))


# ---------------------------------------------------------------------------
# signals list
# ---------------------------------------------------------------------------

def cmd_signals_list(args: argparse.Namespace) -> None:
    cfg = _load_config()
    url, key = _require_api(cfg)

    provided = [x for x in (args.severity, args.event_id, args.category) if x]
    if len(provided) != 1:
        print(err("  Provide exactly one of --severity, --event-id, or --category"))
        sys.exit(1)

    qs: dict[str, Any] = {"page_size": args.page_size, "order": args.order}
    if args.severity:
        qs["severity"] = args.severity.upper()
    elif args.event_id:
        qs["event_id"] = args.event_id
    elif args.category:
        qs["category"] = args.category
    if args.next_token:
        qs["next_token"] = args.next_token
    query = "&".join(f"{k}={v}" for k, v in qs.items())

    status, body = _request("GET", f"/signals?{query}", url, key)
    _die_on_error(status, body, "signals list")

    items = body.get("items", [])
    if not items:
        print(warn("  No signals found."))
        return

    print(f"\n  {'TIMESTAMP':<30} {'RULE_ID':<42} SEV")
    print("  " + "─" * 82)
    for s in items:
        sev = s.get("severity") or ""
        print(
            f"  {s.get('timestamp', ''):<30} "
            f"{s.get('rule_id', ''):<42} "
            f"{color_sev(sev)}"
        )

    if body.get("has_next"):
        print(f"\n  {dim('More pages — use --next-token ' + str(body.get('next_token')))}")
    print()


# ---------------------------------------------------------------------------
# logs list
# ---------------------------------------------------------------------------

def cmd_logs_list(args: argparse.Namespace) -> None:
    cfg = _load_config()
    url, key = _require_api(cfg)

    provided = [x for x in (args.service, args.event_id, args.event_name) if x]
    if len(provided) != 1:
        print(err("  Provide exactly one of --service, --event-id, or --event-name"))
        sys.exit(1)

    qs: dict[str, Any] = {"page_size": args.page_size, "order": args.order}
    if args.service:
        qs["service"] = args.service
    elif args.event_id:
        qs["event_id"] = args.event_id
    elif args.event_name:
        qs["event_name"] = args.event_name
    if args.next_token:
        qs["next_token"] = args.next_token
    query = "&".join(f"{k}={v}" for k, v in qs.items())

    status, body = _request("GET", f"/logs?{query}", url, key)
    _die_on_error(status, body, "logs list")

    items = body.get("items", [])
    if not items:
        print(warn("  No logs found."))
        return

    print(f"\n  {'TIMESTAMP':<30} {'EVENT_NAME':<36} LEVEL")
    print("  " + "─" * 76)
    for lg in items:
        level = (lg.get("details") or {}).get("level") or ""
        print(
            f"  {lg.get('timestamp', ''):<30} "
            f"{lg.get('event_name', ''):<36} "
            f"{level}"
        )

    if body.get("has_next"):
        print(f"\n  {dim('More pages — use --next-token ' + str(body.get('next_token')))}")
    print()


# ---------------------------------------------------------------------------
# lists create / list / show / add / remove / delete
# ---------------------------------------------------------------------------

def _get_list(url: str, key: str, list_id: str) -> dict:
    status, body = _request("GET", f"/rules/{list_id}?rule_kind=list", url, key)
    if status == 404:
        print(err(f"  List not found: {list_id}"))
        sys.exit(1)
    _die_on_error(status, body)
    return body


def cmd_lists_create(args: argparse.Namespace) -> None:
    cfg = _load_config()
    url, key = _require_api(cfg)

    payload = {
        "rule_id": args.list_id,
        "rule_kind": "list",
        "description": args.description or "",
        "values": args.values or [],
    }
    status, body = _request("PUT", f"/rules/{args.list_id}?rule_kind=list", url, key, json=payload)
    _die_on_error(status, body)
    count = len(payload["values"])
    print(ok(f"  created  {args.list_id}") + f"  ({count} value{'s' if count != 1 else ''})")


def cmd_lists_list(args: argparse.Namespace) -> None:
    cfg = _load_config()
    url, key = _require_api(cfg)

    status, body = _request("GET", "/rules?rule_kind=list&page_size=100", url, key)
    _die_on_error(status, body, "lists list")

    items = body.get("items", [])
    if not items:
        print(warn("  No lists found."))
        return

    print(f"\n  {'LIST_ID':<45} {'VALUES':>6}  DESCRIPTION")
    print("  " + "─" * 78)
    for item in items:
        values = item.get("values") or []
        desc = item.get("description") or ""
        print(
            f"  {item.get('rule_id', ''):<45} "
            f"{str(len(values)):>6}  "
            f"{dim(desc)}"
        )
    print()


def cmd_lists_show(args: argparse.Namespace) -> None:
    cfg = _load_config()
    url, key = _require_api(cfg)
    item = _get_list(url, key, args.list_id)

    values = item.get("values") or []
    desc = item.get("description") or ""
    print(f"\n  {bold(args.list_id)}  {dim('— ' + desc) if desc else ''}")
    print(f"  {len(values)} value{'s' if len(values) != 1 else ''}")
    if values:
        print()
        for v in sorted(values):
            print(f"    {v}")
    print()


def cmd_lists_add(args: argparse.Namespace) -> None:
    cfg = _load_config()
    url, key = _require_api(cfg)
    item = _get_list(url, key, args.list_id)

    values = list(item.get("values") or [])
    if args.value in values:
        print(warn(f"  {args.value} is already in {args.list_id}"))
        return

    values.append(args.value)
    item["values"] = values
    status, body = _request("PUT", f"/rules/{args.list_id}?rule_kind=list", url, key, json=item)
    _die_on_error(status, body)
    print(ok(f"  updated  {args.list_id}") + f"  ({len(values)} value{'s' if len(values) != 1 else ''})")


def cmd_lists_remove(args: argparse.Namespace) -> None:
    cfg = _load_config()
    url, key = _require_api(cfg)
    item = _get_list(url, key, args.list_id)

    values = list(item.get("values") or [])
    if args.value not in values:
        print(warn(f"  {args.value} not found in {args.list_id}"))
        return

    values.remove(args.value)
    item["values"] = values
    status, body = _request("PUT", f"/rules/{args.list_id}?rule_kind=list", url, key, json=item)
    _die_on_error(status, body)
    print(ok(f"  updated  {args.list_id}") + f"  ({len(values)} value{'s' if len(values) != 1 else ''})")


def cmd_lists_delete(args: argparse.Namespace) -> None:
    cfg = _load_config()
    url, key = _require_api(cfg)
    status, body = _request("DELETE", f"/rules/{args.list_id}?rule_kind=list", url, key)
    if status == 404:
        print(warn(f"  List not found: {args.list_id}"))
        sys.exit(1)
    _die_on_error(status, body)
    print(ok(f"  deleted  {args.list_id}"))


# ---------------------------------------------------------------------------
# ir-actions list / get / rollback
# ---------------------------------------------------------------------------

def cmd_ir_actions_list(args: argparse.Namespace) -> None:
    cfg = _load_config()
    url, key = _require_api(cfg)

    qs: dict[str, Any] = {"page_size": args.page_size}
    if args.next_token:
        qs["next_token"] = args.next_token
    query = "&".join(f"{k}={v}" for k, v in qs.items())

    status, body = _request("GET", f"/ir-actions?{query}", url, key)
    _die_on_error(status, body, "ir-actions list")

    items = body.get("items", [])
    if not items:
        print(warn("  No IR actions recorded."))
        return

    print(f"\n  {'DETECTION_ID':<38} {'RESPONSE_MODULE':<32} {'ROLLBACK':<10} STATUS")
    print("  " + "─" * 96)
    for a in items:
        rollback_label = ok("yes") if a.get("rollback_supported") else dim("no")
        # rollback_status is absent until a rollback is first attempted --
        # "succeeded" mirrors rolled_back=true (both set together);
        # "pending"/"failed" have no rolled_back equivalent and previously
        # both collapsed into this same "active" label.
        rb_status = a.get("rollback_status")
        if rb_status == "pending":
            status_label = warn("pending")
        elif rb_status == "failed":
            status_label = err("failed")
        elif rb_status == "succeeded" or a.get("rolled_back"):
            status_label = ok("rolled back")
        else:
            status_label = dim("active")
        print(
            f"  {a.get('detection_id', ''):<38} "
            f"{a.get('response_module', ''):<32} "
            f"{rollback_label:<10} "
            f"{status_label}"
        )

    if body.get("has_next"):
        print(f"\n  {dim('More pages — use --next-token ' + str(body.get('next_token')))}")
    print()


def cmd_ir_actions_get(args: argparse.Namespace) -> None:
    cfg = _load_config()
    url, key = _require_api(cfg)
    status, body = _request("GET", f"/ir-actions/{args.detection_id}", url, key)
    if status == 404:
        print(warn(f"  No IR action recorded for detection: {args.detection_id}"))
        sys.exit(1)
    _die_on_error(status, body)
    print(json.dumps(body, indent=2, default=str))


def cmd_ir_actions_rollback(args: argparse.Namespace) -> None:
    cfg = _load_config()
    url, key = _require_api(cfg)
    status, body = _request("POST", f"/ir-actions/{args.detection_id}/rollback", url, key)
    if status == 404:
        print(warn(f"  No IR action recorded for detection: {args.detection_id}"))
        sys.exit(1)
    if status == 400:
        print(err(f"  {body.get('message', body) if isinstance(body, dict) else body}"))
        sys.exit(1)
    if status == 409:
        print(warn(f"  {body.get('message', body) if isinstance(body, dict) else body}"))
        sys.exit(1)
    _die_on_error(status, body, "ir-actions rollback")
    print(ok(f"  Rollback enqueued for detection: {args.detection_id}"))


# ---------------------------------------------------------------------------
# test local
# ---------------------------------------------------------------------------

def cmd_test_local(args: argparse.Namespace) -> None:
    sys.path.insert(0, str(ROOT))
    try:
        from src.domain.detection_engine import run_detection
        from src.domain.ocsf_min_parser import build_default_router
    except ImportError as e:
        print(err(f"  Cannot import src modules: {e}"))
        print(f"  Run from the project root directory.")
        sys.exit(1)

    _banner("Local Rule Tester")

    all_rules = []
    all_lists: dict[str, list] = {}
    for p in sorted(RULES_DIR.rglob("*.json")):
        try:
            r = json.loads(p.read_text())
            if r.get("rule_kind") == "signal":
                all_rules.append(r)
            elif r.get("rule_kind") == "list":
                all_lists[r["rule_id"]] = r.get("values", [])
        except json.JSONDecodeError:
            pass

    all_events = []
    for p in sorted(EVENTS_DIR.glob("*.json")):
        try:
            all_events.append({"_filename": p.name, **json.loads(p.read_text())})
        except json.JSONDecodeError:
            pass

    rules = [r for r in all_rules if not args.rule or args.rule in r.get("rule_id", "")]
    events = [e for e in all_events if not args.event or args.event in e["_filename"]]

    if not rules:
        print(err("  No rules matched."))
        sys.exit(1)
    if not events:
        print(err("  No events matched."))
        sys.exit(1)

    lists_note = f"   Lists: {len(all_lists)}" if all_lists else ""
    print(f"  Rules : {len(rules)}   Events: {len(events)}{lists_note}\n")

    router = build_default_router()
    fired: set[str] = set()
    total = 0

    for event_data in events:
        filename = event_data.pop("_filename")
        normalized = router.parse(event_data)

        if not normalized:
            print(f"  {warn('[SKIP]')}  {filename}")
            continue

        detections = run_detection(normalized, rules, lists=all_lists)

        if not detections:
            actor = normalized.actor.user_name or "unknown"
            print(f"  {warn('[MISS]')}  {filename}")
            print(f"          ↳ {dim(normalized.activity_name)}  (actor: {actor})")
            continue

        actor = normalized.actor.user_name or "unknown"
        print(f"  {ok('[HIT] ')}  {filename}")
        print(f"          ↳ {dim(normalized.activity_name)}  (actor: {actor})")
        for d in detections:
            sev = d.get("severity") or ""
            rule_id = d.get("rule_id") or ""
            fired.add(rule_id)
            total += 1
            print(f"          ↳ {ok('FIRED')}  [{color_sev(sev)}]  {rule_id}")
        print()

    print("─" * 54)
    print(f"\n  {bold('Summary')}")
    print(f"  Matches : {ok(str(total))}")
    print(f"  Rules   : {ok(str(len(fired)))}/{len(rules)} fired")

    unfired = [r["rule_id"] for r in rules if r["rule_id"] not in fired]
    if unfired:
        print(f"\n  {warn('Rules with no matching test event:')}")
        for rid in unfired:
            print(f"    {dim('- ' + rid)}")
    print()


# ---------------------------------------------------------------------------
# test deployed
# ---------------------------------------------------------------------------

def cmd_test_deployed(args: argparse.Namespace) -> None:
    try:
        import boto3
        from boto3.dynamodb.conditions import Key as DDBKey
    except ImportError:
        print(err("  boto3 is required. pip install boto3"))
        sys.exit(1)

    stage = args.stage
    region = args.region
    fn_name = f"opencdr-{stage}-processor"
    # -v2: signals-table's own low-cardinality `severity` HASH key was
    # replaced by a day-bucketed severity_bucket key -- see
    # docs/architecture.md#dynamodb-tables. Nothing writes to the legacy
    # signals-table anymore.
    table_name = f"opencdr-{stage}-signals-table-v2"

    _banner(f"Integration Test — {stage} / {region}")
    print(f"  Function : {fn_name}")
    print(f"  Table    : {table_name}\n")

    lambda_client = boto3.client("lambda", region_name=region)
    signals_table = boto3.resource("dynamodb", region_name=region).Table(table_name)

    try:
        lambda_client.get_function(FunctionName=fn_name)
    except Exception:
        print(err(f"  Lambda '{fn_name}' not found in {region}."))
        print(f"  Have you deployed?  serverless deploy --stage {stage}")
        sys.exit(1)

    files = sorted(EVENTS_DIR.glob("*.json"))
    if args.event:
        files = [f for f in files if args.event in f.name]

    passed = failed = skipped = 0

    for path in files:
        try:
            event_data = json.loads(path.read_text())
        except json.JSONDecodeError:
            print(f"  {warn('[SKIP]')}  {path.name} — invalid JSON")
            skipped += 1
            continue

        # CloudTrail fixtures carry their id at detail.eventID; GuardDuty
        # Finding fixtures use detail.id instead (GuardDutyEventBridgeParser's
        # own convention -- finding_id becomes the normalized event_id, the
        # same field signals_table is queried by below regardless of
        # source). Without this fallback every GuardDuty fixture silently
        # hit this skip branch instead of actually being tested.
        detail = event_data.get("detail") or {}
        event_id = detail.get("eventID") or detail.get("id")
        if not event_id:
            print(f"  {warn('[SKIP]')}  {path.name} — no eventID/id in detail")
            skipped += 1
            continue

        try:
            resp = lambda_client.invoke(
                FunctionName=fn_name,
                InvocationType="RequestResponse",
                Payload=json.dumps(event_data).encode(),
            )
            http_status = resp.get("StatusCode", 0)
        except Exception as e:
            print(f"  {err('[ERROR]')} {path.name} — invocation failed: {e}")
            failed += 1
            continue

        if http_status != 200:
            print(f"  {err('[ERROR]')} {path.name} — Lambda HTTP {http_status}")
            failed += 1
            continue

        try:
            proc_status = json.loads(resp["Payload"].read()).get("status", "unknown")
        except Exception:
            proc_status = "unknown"

        if proc_status == "ignored":
            print(f"  {warn('[SKIP]')}  {path.name} — event not supported by parser")
            skipped += 1
            continue

        if proc_status == "no_detection":
            print(f"  {warn('[MISS]')}  {path.name} — no rules matched")
            skipped += 1
            continue

        if proc_status == "no_rules":
            print(f"  {warn('[WARN]')}  {path.name} — no rules loaded (run: opencdr.py rules load)")
            failed += 1
            continue

        if proc_status != "processed":
            print(f"  {err('[ERROR]')} {path.name} — unexpected status: {proc_status}")
            failed += 1
            continue

        # processor enqueues to signalWriter (SQS) rather than writing
        # signals-table-v2 directly (see docs/architecture.md#dynamodb-tables)
        # -- a single short sleep isn't enough headroom for that extra
        # SQS-trigger + Lambda-invoke hop, especially a cold one. Retry
        # briefly instead of a single fixed wait.
        count = 0
        try:
            for _ in range(5):
                time.sleep(1)
                result = signals_table.query(
                    IndexName="gsi_signal_event_id",
                    KeyConditionExpression=DDBKey("event_id").eq(event_id),
                    Select="COUNT",
                )
                count = result.get("Count", 0)
                if count:
                    break
        except Exception as e:
            print(f"  {warn('[WARN]')}  {path.name} — could not query signals: {e}")
            skipped += 1
            continue

        if count > 0:
            print(f"  {ok('[PASS]')}  {path.name}  signals={count}")
            passed += 1
        else:
            print(f"  {warn('[WARN]')}  {path.name} — processed but 0 signals found")
            failed += 1

    print()
    print("─" * 54)
    print(f"  Passed  : {ok(str(passed))}")
    print(f"  Failed  : {err(str(failed)) if failed else str(failed)}")
    print(f"  Skipped : {str(skipped)}")
    print()

    if failed:
        sys.exit(1)


# ---------------------------------------------------------------------------
# Interactive setup wizard
# ---------------------------------------------------------------------------

def _prompt(message: str, default: str = "", secret: bool = False) -> str:
    """Prompt the user for input, returning default on empty enter."""
    import getpass

    suffix = f" [{dim(default)}]" if default and not secret else ""
    try:
        if secret:
            value = getpass.getpass(f"  {message}: ").strip()
        else:
            value = input(f"  {message}{suffix}: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        raise

    return value or default


def _confirm(message: str, default: bool = True) -> bool:
    hint = "[Y/n]" if default else "[y/N]"
    try:
        ans = input(f"  {message} {dim(hint)}: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        raise
    if not ans:
        return default
    return ans in ("y", "yes")


def _step(n: int, title: str) -> None:
    print(f"\n{bold(f'Step {n}:')} {title}")
    print("  " + "─" * 50)


def cmd_setup(args: argparse.Namespace) -> None:  # noqa: C901
    print(f"""
{bold('╔══════════════════════════════════════════════════╗')}
{bold('║')}        {bold('OpenCDR')} — Interactive Setup Wizard        {bold('║')}
{bold('╚══════════════════════════════════════════════════╝')}

  This wizard will help you connect to your deployed
  OpenCDR API and get everything configured.

  Press {dim('Ctrl+C')} at any time to quit.
""")

    try:
        _run_setup_wizard()
    except (KeyboardInterrupt, EOFError):
        print(f"\n\n  {warn('Setup cancelled.')}\n")
        sys.exit(0)


def _run_setup_wizard() -> None:  # noqa: C901
    cfg = _load_config()

    # ── Step 1: API connection ────────────────────────────────────────────
    _step(1, "API Connection")

    if cfg.get("url") or cfg.get("key"):
        print(f"  {info('Existing config found:')}")
        print(f"    URL : {cfg.get('url', dim('(not set)'))}")
        key_preview = (cfg.get("key") or "")[:8]
        print(f"    Key : {key_preview}{'...' if key_preview else dim('(not set)')}")
        print()
        if not _confirm("Reconfigure API connection?", default=False):
            url = cfg["url"]
            key = cfg["key"]
        else:
            url, key = _prompt_api_credentials(cfg)
    else:
        print(f"  You can find your API URL and key after running:")
        print(f"  {dim('serverless deploy')}  (look for the endpoint and API key output)\n")
        url, key = _prompt_api_credentials(cfg)

    # ── Step 2: Test connection ───────────────────────────────────────────
    _step(2, "Testing Connection")
    print(f"  Connecting to {dim(url)} …")

    try:
        status, body = _request("GET", "/status", url, key)
    except Exception as e:
        print(err(f"  Connection failed: {e}"))
        print(f"  Check the URL and key and try again.\n")
        sys.exit(1)

    if status != 200:
        print(err(f"  API returned HTTP {status}"))
        if isinstance(body, dict):
            print(f"  {body.get('message', body)}")
        sys.exit(1)

    print(ok(f"  Connected!  Service: {body.get('service', '')}"))

    # ── Step 3: Load rules ────────────────────────────────────────────────
    _step(3, "Detection Rules")

    rule_files = [
        p for p in sorted(RULES_DIR.rglob("*.json"))
        if p.name not in _SKIP_RULE_FILES
    ]
    print(f"  Found {len(rule_files)} rule file(s) in {dim(str(RULES_DIR.relative_to(ROOT)))}")
    print()

    if rule_files and _confirm("Load rules into your deployment now?", default=True):
        print()
        loaded = skipped = failed = 0
        for path in rule_files:
            label = path.relative_to(RULES_DIR)
            try:
                rule = json.loads(path.read_text())
            except json.JSONDecodeError:
                print(f"    {err('[ERROR]')} {label} — invalid JSON")
                failed += 1
                continue

            rule_id = rule.get("rule_id") or ""
            rule_kind = rule.get("rule_kind") or ""
            if not rule_id or not rule_kind:
                print(f"    {err('[ERROR]')} {label} — missing rule_id or rule_kind")
                failed += 1
                continue

            s, b = _request("PUT", f"/rules/{rule_id}?rule_kind={rule_kind}", url, key, json=rule)
            if s in (200, 201):
                print(f"    {ok('[OK]')}  {label}")
                loaded += 1
            else:
                # CodeQL flags this as clear-text logging of sensitive data --
                # a generic taint match on "HTTP response body reaches print",
                # not a real finding here: this is api.py's own /rules PUT
                # validation error text (e.g. "unknown response_module"). The
                # rule schema (rule_id/rule_kind/severity/conditions/
                # response_module/playbook) has no secret field for this
                # message to ever echo back.
                msg = b.get("message", b) if isinstance(b, dict) else b  # lgtm[py/clear-text-logging-sensitive-data]
                print(f"    {err('[ERROR]')} {label} — {msg}")
                failed += 1

        print()
        print(f"  Loaded: {ok(str(loaded))}  Failed: {err(str(failed)) if failed else str(failed)}")
    else:
        print(f"  {dim('Skipped. Run later with:')}  opencdr.py rules load")

    # ── Step 4: Notifications ─────────────────────────────────────────────
    _step(4, "Notification Channels")
    print("  OpenCDR can send alerts to Slack, Discord, and/or Email (via SNS).\n")

    channels: dict = {}

    if _confirm("Configure a Slack webhook?", default=False):
        print()
        slack_url = _prompt("Slack webhook URL", secret=True)
        if slack_url:
            if not slack_url.startswith("https://"):
                print(warn("  Warning: URL does not start with https://"))
            channels["slack"] = {"enabled": True, "webhook_url": slack_url}
            print(ok("  Slack configured."))

    if _confirm("\n  Configure a Discord webhook?", default=False):
        print()
        discord_url = _prompt("Discord webhook URL", secret=True)
        if discord_url:
            if not discord_url.startswith("https://"):
                print(warn("  Warning: URL does not start with https://"))
            channels["discord"] = {"enabled": True, "webhook_url": discord_url}
            print(ok("  Discord configured."))

    if _confirm("\n  Configure email notifications via SNS?", default=False):
        print()
        print(f"  {dim('The SNS topic was created by the stack as: opencdr-<stage>-alerts')}")
        print(f"  {dim('Look it up with:')}  aws sns list-topics --query \"Topics[?contains(TopicArn, `opencdr`) && contains(TopicArn, `alerts`)]\" --output text")
        print(f"  {warn('Remember to subscribe to the topic to receive emails!')}")
        topic_arn = _prompt("SNS topic ARN")
        if topic_arn:
            if not topic_arn.startswith("arn:aws:sns:"):
                print(warn("  Warning: value does not look like an SNS topic ARN (expected arn:aws:sns:...)"))
            channels["email"] = {"enabled": True, "topic_arn": topic_arn}
            print(ok("  Email notifications configured."))

    if _confirm("\n  Create Jira tickets for alerts?", default=False):
        print()
        print(f"  {dim('You need a Jira API token — generate one at: id.atlassian.com/manage-profile/security/api-tokens')}")
        jira_url = _prompt("Jira base URL (e.g. https://yourco.atlassian.net)")
        jira_project = _prompt("Jira project key (e.g. SEC)")
        jira_email = _prompt("Jira user email")
        jira_token = _prompt("Jira API token", secret=True)
        if all([jira_url, jira_project, jira_email, jira_token]):
            if not jira_url.startswith("https://"):
                print(warn("  Warning: URL does not start with https://"))
            channels["jira"] = {
                "enabled": True,
                "base_url": jira_url,
                "project_key": jira_project,
                "user_email": jira_email,
                "api_token": jira_token,
            }
            print(ok("  Jira configured."))
        else:
            print(warn("  Skipped — all four Jira fields are required."))

    if _confirm("\n  Send findings to AWS Security Hub?", default=False):
        print()
        print(f"  {dim('Security Hub must be enabled in your account and region.')}")
        print(f"  {dim('Check with:')}  aws securityhub describe-hub")
        channels["securityhub"] = {"enabled": True}
        print(ok("  Security Hub configured."))

    if _confirm("\n  Configure a custom webhook?", default=False):
        print()
        print(f"  {dim('POST the raw alert JSON to any HTTPS endpoint — PagerDuty, OpsGenie, Teams, etc.')}")
        print(f"  {dim('For custom payload shapes, point this at a Lambda or proxy that transforms it.')}")
        webhook_url = _prompt("Webhook URL")
        if webhook_url:
            if not webhook_url.startswith("https://"):
                print(warn("  Warning: URL does not start with https://"))
            webhook_name = _prompt("Webhook name (e.g. pagerduty)", default="default") or "default"
            auth_header = _prompt("Authorization header value (leave blank if none)", secret=True)
            target: dict = {"name": webhook_name, "url": webhook_url, "headers": {}}
            if auth_header:
                target["headers"]["Authorization"] = auth_header
            channels["webhook"] = {"enabled": True, "targets": [target]}
            print(ok("  Custom webhook configured."))

    if channels:
        base_payload, existing_channels = _fetch_existing_settings(url, key, "global")
        merged = _merge_channels(existing_channels, channels)
        payload = {**base_payload, "channels": merged, "notifications_enabled": True}
        s, b = _request("PUT", "/settings/global", url, key, json=payload)
        if s in (200, 201):
            print(ok("\n  Notification settings saved."))
        else:
            msg = b.get("message", b) if isinstance(b, dict) else b
            print(warn(f"\n  Could not save notification settings: {msg}"))
    else:
        print(f"  {dim('Skipped. Configure later with:')}  opencdr.py settings set --slack-webhook <url> / --enable-securityhub")

    # ── Done ──────────────────────────────────────────────────────────────
    print(f"""
{bold('╔══════════════════════════════════════════════════╗')}
{bold('║')}                  {ok('Setup complete!')}                  {bold('║')}
{bold('╚══════════════════════════════════════════════════╝')}

  {bold('Quick reference:')}

    {dim('Check API health')}
    opencdr.py status

    {dim('List loaded rules')}
    opencdr.py rules list --kind signal

    {dim('View recent signals')}
    opencdr.py signals list --severity HIGH

    {dim('Test rules locally')}
    opencdr.py test local

    {dim('Run integration test against deployed stack')}
    opencdr.py test deployed --stage dev
""")


def _prompt_api_credentials(cfg: dict) -> tuple[str, str]:
    url = _prompt("API base URL", default=cfg.get("url", ""))
    if not url:
        print(err("  URL is required."))
        sys.exit(1)
    if not url.startswith("http"):
        print(warn("  Warning: URL does not start with http/https"))

    key = _prompt("API key", secret=True)
    if not key:
        print(err("  API key is required."))
        sys.exit(1)

    _save_config({**cfg, "url": url.rstrip("/"), "key": key})
    print(ok("  Credentials saved."))
    return url.rstrip("/"), key



# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="opencdr.py",
        description="OpenCDR management CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = p.add_subparsers(dest="command", metavar="<command>")
    sub.required = False  # no-arg invocation launches the wizard

    # ── setup (wizard) ────────────────────────────────────────────────────
    sw = sub.add_parser("setup", help="Interactive setup wizard")
    sw.set_defaults(func=cmd_setup)

    # ── config ────────────────────────────────────────────────────────────
    cfg_p = sub.add_parser("config", help="Manage CLI configuration")
    cfg_sub = cfg_p.add_subparsers(dest="subcommand", metavar="<subcommand>")
    cfg_sub.required = True

    cs = cfg_sub.add_parser("set", help="Set API URL and/or key")
    cs.add_argument("--url", help="API base URL")
    cs.add_argument("--key", help="API key")
    cs.set_defaults(func=cmd_config_set)

    csh = cfg_sub.add_parser("show", help="Show current config")
    csh.set_defaults(func=cmd_config_show)

    # ── status ────────────────────────────────────────────────────────────
    st = sub.add_parser("status", help="Check API health")
    st.set_defaults(func=cmd_status)

    # ── rules ─────────────────────────────────────────────────────────────
    rl_p = sub.add_parser("rules", help="Manage detection rules")
    rl_sub = rl_p.add_subparsers(dest="subcommand", metavar="<subcommand>")
    rl_sub.required = True

    rll = rl_sub.add_parser("load", help="Load local rule files via API")
    rll.add_argument("--dry-run", action="store_true", help="Preview without writing")
    rll.set_defaults(func=cmd_rules_load)

    rls = rl_sub.add_parser("list", help="List rules")
    rls.add_argument("--kind", choices=["signal", "correlation", "list"], help="Filter by kind")
    rls.add_argument("--page-size", type=int, default=50, dest="page_size", metavar="N")
    rls.add_argument("--next-token", dest="next_token", metavar="TOKEN")
    rls.set_defaults(func=cmd_rules_list)

    rlg = rl_sub.add_parser("get", help="Get a rule by ID")
    rlg.add_argument("rule_id")
    rlg.add_argument("--kind", required=True, choices=["signal", "correlation"])
    rlg.set_defaults(func=cmd_rules_get)

    rld = rl_sub.add_parser("delete", help="Delete a rule")
    rld.add_argument("rule_id")
    rld.add_argument("--kind", required=True, choices=["signal", "correlation"])
    rld.set_defaults(func=cmd_rules_delete)

    # ── settings ──────────────────────────────────────────────────────────
    sg_p = sub.add_parser("settings", help="Manage notification settings")
    sg_sub = sg_p.add_subparsers(dest="subcommand", metavar="<subcommand>")
    sg_sub.required = True

    sgg = sg_sub.add_parser("get", help="Get settings")
    sgg.add_argument("setting_id", nargs="?", default="global", metavar="<setting_id>")
    sgg.set_defaults(func=cmd_settings_get)

    sgs = sg_sub.add_parser("set", help="Create or update settings")
    sgs.add_argument("setting_id", nargs="?", default="global", metavar="<setting_id>")
    sgs.add_argument("--file", metavar="<json_file>", help="JSON file with full payload")
    sgs.add_argument("--slack-webhook", dest="slack_webhook", metavar="<url>")
    sgs.add_argument("--discord-webhook", dest="discord_webhook", metavar="<url>")
    sgs.add_argument("--email-topic-arn", dest="email_topic_arn", metavar="<arn>", help="SNS topic ARN for email notifications")
    sgs.add_argument("--enable-securityhub", dest="enable_securityhub", action="store_true", default=False, help="Enable Security Hub findings")
    sgs.add_argument("--jira-url", dest="jira_url", metavar="<url>", help="Jira base URL (e.g. https://yourco.atlassian.net)")
    sgs.add_argument("--jira-project", dest="jira_project", metavar="<key>", help="Jira project key (e.g. SEC)")
    sgs.add_argument("--jira-email", dest="jira_email", metavar="<email>", help="Jira user email for Basic Auth")
    sgs.add_argument("--jira-token", dest="jira_token", metavar="<token>", help="Jira API token")
    sgs.add_argument("--jira-issue-type", dest="jira_issue_type", metavar="<type>", default="", help="Jira issue type (default: Bug)")
    sgs.add_argument("--webhook-url", dest="webhook_url", metavar="<url>", help="Custom webhook URL (HTTPS)")
    sgs.add_argument("--webhook-name", dest="webhook_name", metavar="<name>", default="", help="Name for the webhook target (default: default)")
    sgs.add_argument("--webhook-header", dest="webhook_headers", metavar="<key=value>", action="append", help="Extra request header (repeatable, e.g. Authorization=Bearer token)")
    sgs.add_argument("--guardduty-notify-default", dest="guardduty_notify_default", metavar="<true|false>", help="Default GuardDuty notify eligibility when nothing more specific matches (default: false / off)")
    sgs.add_argument("--guardduty-notify-severity", dest="guardduty_notify_severity", metavar="<SEVERITY=true|false>", action="append", help="Notify eligibility for a GuardDuty severity (repeatable, e.g. CRITICAL=true)")
    sgs.add_argument("--guardduty-notify-service", dest="guardduty_notify_service", metavar="<SERVICE=true|false>", action="append", help="Notify eligibility for a GuardDuty gd_resource_type (repeatable, e.g. IAMUser=true)")
    sgs.add_argument("--guardduty-notify-severity-service", dest="guardduty_notify_severity_service", metavar="<SEVERITY:SERVICE=true|false>", action="append", help="Notify eligibility for a specific severity+service combo (repeatable, e.g. HIGH:EC2=true) -- takes precedence over the other --guardduty-notify-* flags")
    sgs.set_defaults(func=cmd_settings_set)

    sgd = sg_sub.add_parser("delete", help="Delete settings")
    sgd.add_argument("setting_id", nargs="?", default="global", metavar="<setting_id>")
    sgd.set_defaults(func=cmd_settings_delete)

    # ── signals ────────────────────────────────────────────────────────────
    si_p = sub.add_parser("signals", help="Query detection signals")
    si_sub = si_p.add_subparsers(dest="subcommand", metavar="<subcommand>")
    si_sub.required = True

    sil = si_sub.add_parser("list", help="List signals")
    sil.add_argument("--severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "INFORMATIONAL"])
    sil.add_argument("--event-id", dest="event_id", metavar="<id>")
    sil.add_argument("--category", metavar="<cat>")
    sil.add_argument("--order", choices=["asc", "desc"], default="desc")
    sil.add_argument("--page-size", type=int, default=20, dest="page_size", metavar="N")
    sil.add_argument("--next-token", dest="next_token", metavar="TOKEN")
    sil.set_defaults(func=cmd_signals_list)

    # ── logs ───────────────────────────────────────────────────────────────
    lg_p = sub.add_parser("logs", help="Query audit logs")
    lg_sub = lg_p.add_subparsers(dest="subcommand", metavar="<subcommand>")
    lg_sub.required = True

    lgl = lg_sub.add_parser("list", help="List logs")
    lgl.add_argument("--service", metavar="<service>")
    lgl.add_argument("--event-id", dest="event_id", metavar="<id>")
    lgl.add_argument("--event-name", dest="event_name", metavar="<name>")
    lgl.add_argument("--order", choices=["asc", "desc"], default="desc")
    lgl.add_argument("--page-size", type=int, default=20, dest="page_size", metavar="N")
    lgl.add_argument("--next-token", dest="next_token", metavar="TOKEN")
    lgl.set_defaults(func=cmd_logs_list)

    # ── lists ──────────────────────────────────────────────────────────────
    ls_p = sub.add_parser("lists", help="Manage detection lists (IoCs, critical assets)")
    ls_sub = ls_p.add_subparsers(dest="subcommand", metavar="<subcommand>")
    ls_sub.required = True

    lsc = ls_sub.add_parser("create", help="Create a new list")
    lsc.add_argument("list_id", metavar="<list_id>")
    lsc.add_argument("--description", metavar="<desc>", default="")
    lsc.add_argument("--values", nargs="*", metavar="<value>", default=[])
    lsc.set_defaults(func=cmd_lists_create)

    lsl = ls_sub.add_parser("list", help="List all lists")
    lsl.set_defaults(func=cmd_lists_list)

    lss = ls_sub.add_parser("show", help="Show list contents")
    lss.add_argument("list_id", metavar="<list_id>")
    lss.set_defaults(func=cmd_lists_show)

    lsa = ls_sub.add_parser("add", help="Add a value to a list")
    lsa.add_argument("list_id", metavar="<list_id>")
    lsa.add_argument("value", metavar="<value>")
    lsa.set_defaults(func=cmd_lists_add)

    lsr = ls_sub.add_parser("remove", help="Remove a value from a list")
    lsr.add_argument("list_id", metavar="<list_id>")
    lsr.add_argument("value", metavar="<value>")
    lsr.set_defaults(func=cmd_lists_remove)

    lsd = ls_sub.add_parser("delete", help="Delete a list")
    lsd.add_argument("list_id", metavar="<list_id>")
    lsd.set_defaults(func=cmd_lists_delete)

    # ── ir-actions ─────────────────────────────────────────────────────────
    ira_p = sub.add_parser("ir-actions", help="Executed IR actions + rollback")
    ira_sub = ira_p.add_subparsers(dest="subcommand", metavar="<subcommand>")
    ira_sub.required = True

    ical = ira_sub.add_parser("list", help="List executed, rollback-eligible IR actions")
    ical.add_argument("--page-size", type=int, default=20, dest="page_size", metavar="N")
    ical.add_argument("--next-token", dest="next_token", metavar="TOKEN")
    ical.set_defaults(func=cmd_ir_actions_list)

    icag = ira_sub.add_parser("get", help="Get a specific IR action")
    icag.add_argument("detection_id", metavar="<detection_id>")
    icag.set_defaults(func=cmd_ir_actions_get)

    icar = ira_sub.add_parser("rollback", help="Enqueue rollback of a specific IR action")
    icar.add_argument("detection_id", metavar="<detection_id>")
    icar.set_defaults(func=cmd_ir_actions_rollback)

    # ── test ────────────────────────────────────────────────────────────────
    ts_p = sub.add_parser("test", help="Test detection rules")
    ts_sub = ts_p.add_subparsers(dest="subcommand", metavar="<subcommand>")
    ts_sub.required = True

    tsl = ts_sub.add_parser("local", help="Run rules against local test events (no AWS)")
    tsl.add_argument("--event", metavar="<filter>", help="Filter by event filename substring")
    tsl.add_argument("--rule", metavar="<filter>", help="Filter by rule_id substring")
    tsl.set_defaults(func=cmd_test_local)

    tsd = ts_sub.add_parser("deployed", help="Invoke deployed Lambda and verify signals in DynamoDB")
    tsd.add_argument("--stage", default="dev", metavar="<stage>")
    tsd.add_argument("--region", default="us-east-1", metavar="<region>")
    tsd.add_argument("--event", metavar="<filter>", help="Filter by event filename substring")
    tsd.set_defaults(func=cmd_test_deployed)

    return p


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    # No subcommand → launch interactive wizard
    if not args.command:
        cmd_setup(args)
        return

    args.func(args)


if __name__ == "__main__":
    main()

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
  opencdr.py settings set    [<setting_id>] (--file <json> | --slack-webhook <url> | --discord-webhook <url> | --email-topic-arn <arn> | --enable-securityhub | --jira-url <url> --jira-project <key> --jira-email <email> --jira-token <token> | --webhook-url <url> [--webhook-name <name>] [--webhook-header key=value]...)
  opencdr.py settings delete [<setting_id>]

  opencdr.py signals list  --severity <sev> | --event-id <id> | --category <cat>
  opencdr.py logs    list  --service  <svc> | --event-id <id> | --event-name  <name>

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

    files = sorted(RULES_DIR.glob("*.json"))
    if not files:
        print(warn(f"  No rule files found in {RULES_DIR.relative_to(ROOT)}"))
        return

    loaded = skipped = failed = 0

    for path in files:
        if path.name in _SKIP_RULE_FILES:
            print(f"  {warn('[SKIP]')}  {path.name} (test stub)")
            skipped += 1
            continue

        try:
            rule = json.loads(path.read_text())
        except json.JSONDecodeError as e:
            print(f"  {err('[ERROR]')} {path.name} — invalid JSON: {e}")
            failed += 1
            continue

        rule_id = rule.get("rule_id") or ""
        rule_kind = rule.get("rule_kind") or ""
        if not rule_id or not rule_kind:
            print(f"  {err('[ERROR]')} {path.name} — missing rule_id or rule_kind")
            failed += 1
            continue

        if args.dry_run:
            print(f"  {info('[DRY]')}   {path.name}  ({rule_kind} / {rule_id})")
            loaded += 1
            continue

        # PUT = upsert — safe to re-run
        status, body = _request(
            "PUT", f"/rules/{rule_id}?rule_kind={rule_kind}", url, key, json=rule
        )
        if status in (200, 201):
            print(f"  {ok('[OK]')}    {path.name}  ({rule_kind} / {rule_id})")
            loaded += 1
        else:
            msg = body.get("message", body) if isinstance(body, dict) else body
            print(f"  {err('[ERROR]')} {path.name} — HTTP {status}: {msg}")
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
    if not new_channels:
        print(err("  Provide --file, --slack-webhook, --discord-webhook, --email-topic-arn, --enable-securityhub, --jira-url/--jira-project/--jira-email/--jira-token, or --webhook-url"))
        sys.exit(1)

    base_payload, existing_channels = _fetch_existing_settings(url, key, args.setting_id)
    merged_channels = _merge_channels(existing_channels, new_channels)
    payload = {**base_payload, "channels": merged_channels}

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
    for p in sorted(RULES_DIR.glob("*.json")):
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
    table_name = f"opencdr-{stage}-signals-table"

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

        event_id = (event_data.get("detail") or {}).get("eventID")
        if not event_id:
            print(f"  {warn('[SKIP]')}  {path.name} — no eventID in detail")
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

        time.sleep(0.5)  # allow DynamoDB eventual consistency

        try:
            result = signals_table.query(
                IndexName="gsi_signal_event_id",
                KeyConditionExpression=DDBKey("event_id").eq(event_id),
                Select="COUNT",
            )
            count = result.get("Count", 0)
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
        p for p in sorted(RULES_DIR.glob("*.json"))
        if p.name not in _SKIP_RULE_FILES
    ]
    print(f"  Found {len(rule_files)} rule file(s) in {dim(str(RULES_DIR.relative_to(ROOT)))}")
    print()

    if rule_files and _confirm("Load rules into your deployment now?", default=True):
        print()
        loaded = skipped = failed = 0
        for path in rule_files:
            try:
                rule = json.loads(path.read_text())
            except json.JSONDecodeError:
                print(f"    {err('[ERROR]')} {path.name} — invalid JSON")
                failed += 1
                continue

            rule_id = rule.get("rule_id") or ""
            rule_kind = rule.get("rule_kind") or ""
            if not rule_id or not rule_kind:
                print(f"    {err('[ERROR]')} {path.name} — missing rule_id or rule_kind")
                failed += 1
                continue

            s, b = _request("PUT", f"/rules/{rule_id}?rule_kind={rule_kind}", url, key, json=rule)
            if s in (200, 201):
                print(f"    {ok('[OK]')}  {path.name}")
                loaded += 1
            else:
                msg = b.get("message", b) if isinstance(b, dict) else b
                print(f"    {err('[ERROR]')} {path.name} — {msg}")
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

"""
OpenCDR MCP server -- the default management plane for the platform:
rules, lists, signals, logs, settings, and IR-role assignments.

Run: python mcp_server/server.py  (stdio transport)
Register with Claude Code:
  claude mcp add opencdr -- python /path/to/mcp_server/server.py

Configure with OPENCDR_API_URL / OPENCDR_API_KEY (same precedence as
scripts/opencdr.py's config), using the all-scopes key minted for this
server -- see docs/api-reference.md's "API key scopes" section for the
exact key name and why it's a separate, independently revocable key from
the original bare one, even though both carry every scope.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

import opencdr  # noqa: E402  (after sys.path manipulation)
from mcp.server.fastmcp import FastMCP  # noqa: E402

mcp = FastMCP("opencdr")


class OpenCDRConfigError(Exception):
    pass


def _resolve_api() -> tuple[str, str]:
    """
    Same OPENCDR_API_URL/OPENCDR_API_KEY-over-.opencdr.json precedence as
    opencdr.py's _require_api, but raises instead of sys.exit -- an MCP
    tool call should return a tool error, not kill the server process.
    """
    cfg = opencdr._load_config()
    url = os.getenv("OPENCDR_API_URL") or cfg.get("url", "")
    key = os.getenv("OPENCDR_API_KEY") or cfg.get("key", "")
    missing = [name for name, value in (("OPENCDR_API_URL", url), ("OPENCDR_API_KEY", key)) if not value]
    if missing:
        raise OpenCDRConfigError(
            f"Missing config: {', '.join(missing)}. Set OPENCDR_API_URL/OPENCDR_API_KEY "
            "or run `opencdr.py config set --url <url> --key <key>`."
        )
    return url.rstrip("/"), key


def _raise_on_error(status: int, body: Any, context: str) -> None:
    if status >= 400:
        msg = body.get("message", body) if isinstance(body, dict) else body
        raise RuntimeError(f"{context}: HTTP {status} — {msg}")


@mcp.tool()
def opencdr_status() -> dict:
    """Check OpenCDR API health."""
    url, key = _resolve_api()
    status, body = opencdr._request("GET", "/status", url, key)
    _raise_on_error(status, body, "status")
    return body


# ---------------------------------------------------------------------------
# Rules (detection + correlation). Lists (rule_kind="list") have their own
# tool group below -- same underlying /rules resource, different shape and
# merge semantics, same split scripts/opencdr.py's CLI already makes.
# ---------------------------------------------------------------------------


@mcp.tool()
def opencdr_rules_list(kind: str | None = None, page_size: int = 50, next_token: str | None = None) -> dict:
    """List rules. kind: "signal" or "correlation" (omit for both; lists use opencdr_lists_list)."""
    url, key = _resolve_api()
    qs: dict[str, Any] = {"page_size": page_size}
    if kind:
        qs["rule_kind"] = kind
    if next_token:
        qs["next_token"] = next_token
    query = "&".join(f"{k}={v}" for k, v in qs.items())
    status, body = opencdr._request("GET", f"/rules?{query}", url, key)
    _raise_on_error(status, body, "rules list")
    return body


@mcp.tool()
def opencdr_rules_get(rule_id: str, kind: str) -> dict:
    """Get a rule by id. kind must be "signal" or "correlation"."""
    url, key = _resolve_api()
    status, body = opencdr._request("GET", f"/rules/{rule_id}?rule_kind={kind}", url, key)
    if status == 404:
        return {"found": False, "rule_id": rule_id}
    _raise_on_error(status, body, "rules get")
    return body


@mcp.tool()
def opencdr_rules_upsert(rule_id: str, kind: str, rule: dict) -> dict:
    """Create or update a rule (PUT -- upsert, safe to call again).

    `rule` is the full rule body (conditions, severity, notify,
    response_module, etc.) -- see docs/detection-rules.md for the schema.
    rule_id/rule_kind in the body are overwritten to match the rule_id/kind
    arguments so the item's key stays stable across edits. kind must be
    "signal" or "correlation".
    """
    url, key = _resolve_api()
    status, body = opencdr._request("PUT", f"/rules/{rule_id}?rule_kind={kind}", url, key, json=rule)
    _raise_on_error(status, body, "rules upsert")
    return body


@mcp.tool()
def opencdr_rules_delete(rule_id: str, kind: str) -> dict:
    """Delete a rule by id. kind must be "signal" or "correlation"."""
    url, key = _resolve_api()
    status, body = opencdr._request("DELETE", f"/rules/{rule_id}?rule_kind={kind}", url, key)
    if status == 404:
        return {"found": False, "rule_id": rule_id}
    _raise_on_error(status, body, "rules delete")
    return {"deleted": True, "rule_id": rule_id}


# ---------------------------------------------------------------------------
# Lists (IoCs, critical assets, etc.) -- rule_kind="list" items, referenced
# by in_list/not_in_list rule conditions.
# ---------------------------------------------------------------------------


def _get_list_or_raise(url: str, key: str, list_id: str) -> dict:
    status, body = opencdr._request("GET", f"/rules/{list_id}?rule_kind=list", url, key)
    if status == 404:
        raise RuntimeError(f"List not found: {list_id}")
    _raise_on_error(status, body, "lists get")
    return body


@mcp.tool()
def opencdr_lists_list() -> dict:
    """List all detection lists."""
    url, key = _resolve_api()
    status, body = opencdr._request("GET", "/rules?rule_kind=list&page_size=100", url, key)
    _raise_on_error(status, body, "lists list")
    return body


@mcp.tool()
def opencdr_lists_show(list_id: str) -> dict:
    """Show a list's values."""
    url, key = _resolve_api()
    return _get_list_or_raise(url, key, list_id)


@mcp.tool()
def opencdr_lists_create(list_id: str, description: str = "", values: list[str] | None = None) -> dict:
    """Create (or fully replace) a list."""
    url, key = _resolve_api()
    payload = {"rule_id": list_id, "rule_kind": "list", "description": description, "values": values or []}
    status, body = opencdr._request("PUT", f"/rules/{list_id}?rule_kind=list", url, key, json=payload)
    _raise_on_error(status, body, "lists create")
    return body


@mcp.tool()
def opencdr_lists_add(list_id: str, value: str) -> dict:
    """Add a single value to an existing list (no-op if already present)."""
    url, key = _resolve_api()
    item = _get_list_or_raise(url, key, list_id)
    values = list(item.get("values") or [])
    if value in values:
        return {"changed": False, "list_id": list_id, "values": values}
    values.append(value)
    item["values"] = values
    status, body = opencdr._request("PUT", f"/rules/{list_id}?rule_kind=list", url, key, json=item)
    _raise_on_error(status, body, "lists add")
    return body


@mcp.tool()
def opencdr_lists_remove(list_id: str, value: str) -> dict:
    """Remove a single value from a list (no-op if not present)."""
    url, key = _resolve_api()
    item = _get_list_or_raise(url, key, list_id)
    values = list(item.get("values") or [])
    if value not in values:
        return {"changed": False, "list_id": list_id, "values": values}
    values.remove(value)
    item["values"] = values
    status, body = opencdr._request("PUT", f"/rules/{list_id}?rule_kind=list", url, key, json=item)
    _raise_on_error(status, body, "lists remove")
    return body


@mcp.tool()
def opencdr_lists_delete(list_id: str) -> dict:
    """Delete a list."""
    url, key = _resolve_api()
    status, body = opencdr._request("DELETE", f"/rules/{list_id}?rule_kind=list", url, key)
    if status == 404:
        return {"found": False, "list_id": list_id}
    _raise_on_error(status, body, "lists delete")
    return {"deleted": True, "list_id": list_id}


# ---------------------------------------------------------------------------
# Signals / logs (read-only queries)
# ---------------------------------------------------------------------------


@mcp.tool()
def opencdr_signals_list(
    severity: str | None = None,
    event_id: str | None = None,
    category: str | None = None,
    page_size: int = 25,
    order: str = "desc",
    next_token: str | None = None,
) -> dict:
    """List detection signals. Provide exactly one of severity, event_id, or category."""
    provided = [x for x in (severity, event_id, category) if x]
    if len(provided) != 1:
        raise ValueError("Provide exactly one of severity, event_id, or category")
    url, key = _resolve_api()
    qs: dict[str, Any] = {"page_size": page_size, "order": order}
    if severity:
        qs["severity"] = severity.upper()
    elif event_id:
        qs["event_id"] = event_id
    elif category:
        qs["category"] = category
    if next_token:
        qs["next_token"] = next_token
    query = "&".join(f"{k}={v}" for k, v in qs.items())
    status, body = opencdr._request("GET", f"/signals?{query}", url, key)
    _raise_on_error(status, body, "signals list")
    return body


@mcp.tool()
def opencdr_signals_stats(date_from: str | None = None, date_to: str | None = None) -> dict:
    """Signal counts by severity for a date range -- for a dashboard/summary view,
    not a substitute for opencdr_signals_list's paginated item listing.

    Defaults to the last 7 days if neither date is given (YYYY-MM-DD, max
    range 31 days -- same bound as opencdr_signals_list). Returns
    {date_from, date_to, counts: {<severity>: <count>, ...}, total}.
    """
    url, key = _resolve_api()
    qs: dict[str, Any] = {}
    if date_from:
        qs["date_from"] = date_from
    if date_to:
        qs["date_to"] = date_to
    query = "&".join(f"{k}={v}" for k, v in qs.items())
    path = "/signals/stats" + (f"?{query}" if query else "")
    status, body = opencdr._request("GET", path, url, key)
    _raise_on_error(status, body, "signals stats")
    return body


@mcp.tool()
def opencdr_logs_list(
    service: str | None = None,
    event_id: str | None = None,
    event_name: str | None = None,
    page_size: int = 25,
    order: str = "desc",
    next_token: str | None = None,
) -> dict:
    """List audit logs. Provide exactly one of service, event_id, or event_name."""
    provided = [x for x in (service, event_id, event_name) if x]
    if len(provided) != 1:
        raise ValueError("Provide exactly one of service, event_id, or event_name")
    url, key = _resolve_api()
    qs: dict[str, Any] = {"page_size": page_size, "order": order}
    if service:
        qs["service"] = service
    elif event_id:
        qs["event_id"] = event_id
    elif event_name:
        qs["event_name"] = event_name
    if next_token:
        qs["next_token"] = next_token
    query = "&".join(f"{k}={v}" for k, v in qs.items())
    status, body = opencdr._request("GET", f"/logs?{query}", url, key)
    _raise_on_error(status, body, "logs list")
    return body


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


@mcp.tool()
def opencdr_settings_get(setting_id: str = "global") -> dict:
    """Get an OpenCDR settings document by id (default: the global settings doc)."""
    url, key = _resolve_api()
    status, body = opencdr._request("GET", f"/settings/{setting_id}", url, key)
    if status == 404:
        return {"found": False, "setting_id": setting_id}
    _raise_on_error(status, body, "settings get")
    return body


@mcp.tool()
def opencdr_settings_set(
    setting_id: str = "global",
    channels: dict | None = None,
    guardduty_notify: dict | None = None,
    notifications_enabled: bool | None = None,
) -> dict:
    """Update an OpenCDR settings document.

    Only the fields provided are changed: an omitted channel (slack/
    discord/email/securityhub/jira/webhook) is left untouched, and
    guardduty_notify is merged key-by-key (default/by_severity/by_service/
    by_severity_and_service) rather than replaced wholesale -- same
    read-modify-write semantics as `opencdr.py settings set`, see
    docs/notifications.md.
    """
    url, key = _resolve_api()
    base_payload, existing_channels = opencdr._fetch_existing_settings(url, key, setting_id)

    payload = dict(base_payload)
    if notifications_enabled is not None:
        payload["notifications_enabled"] = notifications_enabled
    payload["channels"] = opencdr._merge_channels(existing_channels, channels) if channels else existing_channels
    if guardduty_notify:
        payload["guardduty_notify"] = opencdr._merge_guardduty_notify(
            base_payload.get("guardduty_notify") or {}, guardduty_notify
        )

    status, body = opencdr._request("PUT", f"/settings/{setting_id}", url, key, json=payload)
    _raise_on_error(status, body, "settings set")
    return body


@mcp.tool()
def opencdr_settings_delete(setting_id: str = "global") -> dict:
    """Delete an OpenCDR settings document by id."""
    url, key = _resolve_api()
    status, body = opencdr._request("DELETE", f"/settings/{setting_id}", url, key)
    if status == 404:
        return {"found": False, "setting_id": setting_id}
    _raise_on_error(status, body, "settings delete")
    return {"deleted": True, "setting_id": setting_id}


# ---------------------------------------------------------------------------
# IR roles -- which IAM role responder assumes to take automated response
# actions, per AWS account. No scripts/opencdr.py CLI equivalent exists yet
# (see docs/api-reference.md) -- written directly against the API.
# ---------------------------------------------------------------------------


@mcp.tool()
def opencdr_ir_roles_list(page_size: int = 20, next_token: str | None = None) -> dict:
    """List IR role mappings (which IAM role responder assumes per AWS account)."""
    url, key = _resolve_api()
    qs: dict[str, Any] = {"page_size": page_size}
    if next_token:
        qs["next_token"] = next_token
    query = "&".join(f"{k}={v}" for k, v in qs.items())
    status, body = opencdr._request("GET", f"/ir-roles?{query}", url, key)
    _raise_on_error(status, body, "ir-roles list")
    return body


@mcp.tool()
def opencdr_ir_roles_get(aws_account_id: str) -> dict:
    """Get the IR role mapping for a 12-digit AWS account id."""
    url, key = _resolve_api()
    status, body = opencdr._request("GET", f"/ir-roles/{aws_account_id}", url, key)
    if status == 404:
        return {"found": False, "aws_account_id": aws_account_id}
    _raise_on_error(status, body, "ir-roles get")
    return body


@mcp.tool()
def opencdr_ir_roles_upsert(aws_account_id: str, role_arn: str, enabled: bool = True) -> dict:
    """Create or update the IR role mapping for an AWS account (PUT -- upsert).

    role_arn must be an IAM role ARN (arn:aws:iam::...) that responder will
    assume to take automated response actions in that account.
    """
    url, key = _resolve_api()
    payload = {"aws_account_id": aws_account_id, "role_arn": role_arn, "enabled": enabled}
    status, body = opencdr._request("PUT", f"/ir-roles/{aws_account_id}", url, key, json=payload)
    _raise_on_error(status, body, "ir-roles upsert")
    return body


@mcp.tool()
def opencdr_ir_roles_delete(aws_account_id: str) -> dict:
    """Delete the IR role mapping for an AWS account."""
    url, key = _resolve_api()
    status, body = opencdr._request("DELETE", f"/ir-roles/{aws_account_id}", url, key)
    if status == 404:
        return {"found": False, "aws_account_id": aws_account_id}
    _raise_on_error(status, body, "ir-roles delete")
    return {"deleted": True, "aws_account_id": aws_account_id}


# ---------------------------------------------------------------------------
# IR actions -- executed, rollback-eligible IR actions and their undo. See
# scripts/opencdr.py's ir-actions subcommand and docs/api-reference.md's
# "IR actions" section.
# ---------------------------------------------------------------------------


@mcp.tool()
def opencdr_ir_actions_list(page_size: int = 20, next_token: str | None = None) -> dict:
    """List executed, rollback-eligible IR actions."""
    url, key = _resolve_api()
    qs: dict[str, Any] = {"page_size": page_size}
    if next_token:
        qs["next_token"] = next_token
    query = "&".join(f"{k}={v}" for k, v in qs.items())
    status, body = opencdr._request("GET", f"/ir-actions?{query}", url, key)
    _raise_on_error(status, body, "ir-actions list")
    return body


@mcp.tool()
def opencdr_ir_actions_get(detection_id: str) -> dict:
    """Get a specific executed IR action.

    Includes rollback_supported and, once a rollback has been attempted,
    rollback_status ("pending"/"succeeded"/"failed"), rollback_error (set
    only on failure), and rollback_updated_at. rolled_back mirrors
    rollback_status == "succeeded" for back-compat; absent rollback_status
    means no rollback has been attempted yet.
    """
    url, key = _resolve_api()
    status, body = opencdr._request("GET", f"/ir-actions/{detection_id}", url, key)
    if status == 404:
        return {"found": False, "detection_id": detection_id}
    _raise_on_error(status, body, "ir-actions get")
    return body


@mcp.tool()
def opencdr_ir_actions_rollback(detection_id: str) -> dict:
    """Enqueue the rollback of a specific IR action for async execution.

    Returns as soon as the rollback is enqueued, not once it has run --
    rollbackHandler executes it separately; poll opencdr_ir_actions_get for
    the outcome. Raises if rollback isn't supported for this action (400),
    or on a 409 if a rollback is already in flight (rollback_status ==
    "pending") -- a previously failed rollback can be retried, a
    currently-pending one cannot.
    """
    url, key = _resolve_api()
    status, body = opencdr._request("POST", f"/ir-actions/{detection_id}/rollback", url, key)
    if status == 404:
        return {"found": False, "detection_id": detection_id}
    _raise_on_error(status, body, "ir-actions rollback")
    return body


if __name__ == "__main__":
    mcp.run()

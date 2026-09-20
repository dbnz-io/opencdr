"""
OpenCDR MCP server -- the default management plane for the platform:
rules, lists, signals, logs, settings, and IR-role assignments.

Run: python mcp_server/server.py  (stdio transport)
Register with Claude Code:
  claude mcp add opencdr -- python /path/to/mcp_server/server.py

Configure with OPENCDR_API_URL / OPENCDR_API_KEY (same precedence as
scripts/opencdr.py's config). See docs/api-reference.md's "API key scopes"
section for how to mint a *scoped* key.

Capability profiles (OPENCDR_MCP_PROFILE)
-----------------------------------------
This server exposes a reduced tool set depending on the profile it runs
under. The profile controls *which tools an MCP client can discover/call*:

  observer  (default) -- read-only: status, rules/lists read, signals &
                         logs search, settings read, IR roles & actions read.
  operator            -- observer + rules/lists write and settings write.
  responder           -- operator + IR-role management and IR-action rollback.

IMPORTANT: the profile is a client-side capability *reduction*, not the
security boundary. Authorization is enforced by the OpenCDR API against the
scopes encoded in the API key (read / rules / settings / ir_roles /
ir_actions -- see src/handlers/api.py `_required_scope_for`). Run each
profile with an API key whose scopes match the profile, so the MCP tool set
and the backend enforcement agree. A responder profile pointed at a
read-only key will simply get 403s from the API; an observer profile pointed
at an all-scopes key still cannot mutate anything because the destructive
tools are never registered.
"""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal
from urllib.parse import quote, urlencode

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

import opencdr  # noqa: E402  (after sys.path manipulation)
from mcp.server.fastmcp import FastMCP  # noqa: E402
from mcp.types import ToolAnnotations  # noqa: E402

mcp = FastMCP("opencdr")


class OpenCDRConfigError(Exception):
    pass


# ---------------------------------------------------------------------------
# Typed domain values -- so an MCP client sees the valid inputs from the tool
# schema instead of a bare `str` (and an out-of-domain value is rejected
# before it ever reaches the API). Kept in sync with src/handlers/api.py's
# ALLOWED_RULE_KINDS / ALLOWED_SEVERITIES.
# ---------------------------------------------------------------------------

RuleKind = Literal["signal", "correlation"]
Order = Literal["asc", "desc"]
Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "INFORMATIONAL", "UNKNOWN"]

_ACCOUNT_ID_RE = re.compile(r"^\d{12}$")
# arn:aws:iam::<12-digit-account>:role/<path/name>
_ROLE_ARN_RE = re.compile(r"^arn:aws:iam::(\d{12}):role/.+$")

# Compare-and-set retries for the read-modify-write tools (lists add/remove,
# settings set). The API owns the concurrency guarantee via `expected_rev`;
# this is just a bounded client retry on a 409, NOT a lock.
_CAS_MAX_ATTEMPTS = 4


# ---------------------------------------------------------------------------
# Capability profiles.
#
# Each tool declares the capability it needs. A tool is only *registered*
# (and therefore only discoverable/callable) when the active profile grants
# that capability. `allowed_tools()` is a pure policy function so the mapping
# can be asserted in tests without re-importing the module per profile.
# ---------------------------------------------------------------------------

# Capability -> backend API-key scope it corresponds to (documentation/parity
# only; the backend, not this map, does the enforcing).
CAP_READ = "read"
CAP_RULES = "rules"
CAP_SETTINGS = "settings"
CAP_IR_ROLES = "ir_roles"
CAP_IR_ACTIONS_WRITE = "ir_actions"

_OBSERVER_CAPS = frozenset({CAP_READ})
_OPERATOR_CAPS = _OBSERVER_CAPS | {CAP_RULES, CAP_SETTINGS}
_RESPONDER_CAPS = _OPERATOR_CAPS | {CAP_IR_ROLES, CAP_IR_ACTIONS_WRITE}

_PROFILE_CAPS: dict[str, frozenset[str]] = {
    "observer": _OBSERVER_CAPS,
    "operator": _OPERATOR_CAPS,
    "responder": _RESPONDER_CAPS,
}


def _resolve_profile() -> str:
    raw = (os.getenv("OPENCDR_MCP_PROFILE") or "observer").strip().lower()
    return raw if raw in _PROFILE_CAPS else "observer"


PROFILE = _resolve_profile()
_ACTIVE_CAPS = _PROFILE_CAPS[PROFILE]

# tool name -> required capability, populated by @_tool at import time.
_TOOL_CAPS: dict[str, str] = {}


def allowed_tools(profile: str) -> set[str]:
    """Names of the tools a given profile may discover/call. Pure policy."""
    caps = _PROFILE_CAPS.get(profile, _OBSERVER_CAPS)
    return {name for name, cap in _TOOL_CAPS.items() if cap in caps}


def _tool(cap: str, *, annotations: ToolAnnotations) -> Callable[[Callable], Callable]:
    """Register a FastMCP tool only if the active profile grants `cap`.

    The decorated function is always returned unchanged (so it stays
    importable/unit-testable regardless of profile); it is only *registered*
    with FastMCP -- i.e. exposed to MCP clients -- when the profile allows it.
    """

    def deco(fn: Callable) -> Callable:
        _TOOL_CAPS[fn.__name__] = cap
        # Stash for introspection/testing so the classification can be
        # asserted regardless of which profile happens to be active.
        fn._mcp_capability = cap  # type: ignore[attr-defined]
        fn._mcp_annotations = annotations  # type: ignore[attr-defined]
        if cap in _ACTIVE_CAPS:
            mcp.tool(annotations=annotations)(fn)
        return fn

    return deco


# Annotation presets. Every tool talks to the external OpenCDR API, so
# openWorldHint is True everywhere.
_READ_ONLY = ToolAnnotations(
    readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True
)
# Idempotent, non-destructive write (PUT upsert / no-op-safe add/remove).
_MUTATING = ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=True
)
# Destructive or security-sensitive write.
_DESTRUCTIVE = ToolAnnotations(
    readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=True
)
# Rollback: security-sensitive AND not idempotent (409 if one is in flight).
_ROLLBACK = ToolAnnotations(
    readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True
)


# ---------------------------------------------------------------------------
# HTTP / config helpers
# ---------------------------------------------------------------------------


def _resolve_api() -> tuple[str, str]:
    """
    Same OPENCDR_API_URL/OPENCDR_API_KEY-over-.opencdr.json precedence as
    opencdr.py's _require_api, but raises instead of sys.exit -- an MCP
    tool call should return a tool error, not kill the server process.
    """
    cfg = opencdr._load_config()
    url = os.getenv("OPENCDR_API_URL") or cfg.get("url", "")
    key = os.getenv("OPENCDR_API_KEY") or cfg.get("key", "")
    missing = [
        name for name, value in (("OPENCDR_API_URL", url), ("OPENCDR_API_KEY", key)) if not value
    ]
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


def _qs(**params: Any) -> str:
    """URL-encoded query string from keyword params, dropping None values.

    Uses urllib so opaque values (base64 next_token cursors with `=`/`+`,
    principals/ARNs with `:` and `/`, etc.) are percent-encoded correctly
    instead of being spliced in raw.
    """
    clean = {k: v for k, v in params.items() if v is not None}
    return urlencode(clean)


def _seg(value: str, name: str) -> str:
    """Encode a single path segment, rejecting empty/whitespace ids.

    `safe=""` means a value containing `/`, `?`, `#` or whitespace cannot
    break out of its segment and forge a different path.
    """
    if value is None or str(value).strip() == "":
        raise ValueError(f"{name} is required")
    return quote(str(value), safe="")


def _require_account_id(aws_account_id: str) -> str:
    if not isinstance(aws_account_id, str) or not _ACCOUNT_ID_RE.match(aws_account_id):
        raise ValueError("aws_account_id must be a 12-digit AWS account ID")
    return aws_account_id


@_tool(CAP_READ, annotations=_READ_ONLY)
def opencdr_status() -> dict:
    """Check OpenCDR API health. Read-only."""
    url, key = _resolve_api()
    status, body = opencdr._request("GET", "/status", url, key)
    _raise_on_error(status, body, "status")
    return body


# ---------------------------------------------------------------------------
# Rules (detection + correlation). Lists (rule_kind="list") have their own
# tool group below -- same underlying /rules resource, different shape and
# merge semantics, same split scripts/opencdr.py's CLI already makes.
# ---------------------------------------------------------------------------


@_tool(CAP_READ, annotations=_READ_ONLY)
def opencdr_rules_list(
    kind: RuleKind | None = None, page_size: int = 50, next_token: str | None = None
) -> dict:
    """List detection/correlation rules. Read-only.

    kind: "signal" or "correlation" (omit for both; detection lists use
    opencdr_lists_list). Paginated: pass the returned next_token to continue.
    """
    url, key = _resolve_api()
    query = _qs(page_size=page_size, rule_kind=kind, next_token=next_token)
    status, body = opencdr._request("GET", f"/rules?{query}", url, key)
    _raise_on_error(status, body, "rules list")
    return body


@_tool(CAP_READ, annotations=_READ_ONLY)
def opencdr_rules_get(rule_id: str, kind: RuleKind) -> dict:
    """Get a rule by id. Read-only. kind must be "signal" or "correlation"."""
    url, key = _resolve_api()
    query = _qs(rule_kind=kind)
    status, body = opencdr._request("GET", f"/rules/{_seg(rule_id, 'rule_id')}?{query}", url, key)
    if status == 404:
        return {"found": False, "rule_id": rule_id}
    _raise_on_error(status, body, "rules get")
    return body


@_tool(CAP_RULES, annotations=_MUTATING)
def opencdr_rules_upsert(
    rule_id: str, kind: RuleKind, rule: dict, expected_rev: int | None = None
) -> dict:
    """Create or update a rule (PUT -- idempotent upsert, safe to call again).

    `rule` is the full rule body (conditions, severity, notify,
    response_module, etc.) -- see docs/detection-rules.md for the schema.

    The explicit rule_id/kind arguments are AUTHORITATIVE: any rule_id or
    rule_kind inside the `rule` object is overwritten with them before the
    request is sent, so a contradictory id/kind embedded in the body can
    never reach the API. kind must be "signal" or "correlation".

    Optional optimistic concurrency: pass `expected_rev` (the `rev` you read
    from opencdr_rules_get) to make the write conditional -- if the rule was
    changed since you read it, the API returns 409 rather than silently
    clobbering that change. Omit it for a plain upsert.
    """
    url, key = _resolve_api()
    payload = {**rule, "rule_id": rule_id, "rule_kind": kind}
    if expected_rev is not None:
        payload["expected_rev"] = expected_rev
    query = _qs(rule_kind=kind)
    status, body = opencdr._request(
        "PUT", f"/rules/{_seg(rule_id, 'rule_id')}?{query}", url, key, json=payload
    )
    _raise_on_error(status, body, "rules upsert")
    return body


@_tool(CAP_RULES, annotations=_DESTRUCTIVE)
def opencdr_rules_delete(rule_id: str, kind: RuleKind) -> dict:
    """Delete a rule by id. DESTRUCTIVE and irreversible.

    kind must be "signal" or "correlation".
    """
    url, key = _resolve_api()
    query = _qs(rule_kind=kind)
    status, body = opencdr._request(
        "DELETE", f"/rules/{_seg(rule_id, 'rule_id')}?{query}", url, key
    )
    if status == 404:
        return {"found": False, "rule_id": rule_id}
    _raise_on_error(status, body, "rules delete")
    return {"deleted": True, "rule_id": rule_id}


# ---------------------------------------------------------------------------
# Lists (IoCs, critical assets, etc.) -- rule_kind="list" items, referenced
# by in_list/not_in_list rule conditions.
# ---------------------------------------------------------------------------


def _get_list_or_raise(url: str, key: str, list_id: str) -> dict:
    query = _qs(rule_kind="list")
    status, body = opencdr._request("GET", f"/rules/{_seg(list_id, 'list_id')}?{query}", url, key)
    if status == 404:
        raise RuntimeError(f"List not found: {list_id}")
    _raise_on_error(status, body, "lists get")
    return body


@_tool(CAP_READ, annotations=_READ_ONLY)
def opencdr_lists_list() -> dict:
    """List all detection lists. Read-only."""
    url, key = _resolve_api()
    query = _qs(rule_kind="list", page_size=100)
    status, body = opencdr._request("GET", f"/rules?{query}", url, key)
    _raise_on_error(status, body, "lists list")
    return body


@_tool(CAP_READ, annotations=_READ_ONLY)
def opencdr_lists_show(list_id: str) -> dict:
    """Show a list's values. Read-only."""
    url, key = _resolve_api()
    return _get_list_or_raise(url, key, list_id)


@_tool(CAP_RULES, annotations=_DESTRUCTIVE)
def opencdr_lists_replace(
    list_id: str, description: str = "", values: list[str] | None = None
) -> dict:
    """Create a list, or COMPLETELY REPLACE an existing one. DESTRUCTIVE.

    This is a whole-object PUT: `values` becomes the list's entire contents
    and any values not present in `values` are permanently dropped
    (`description` is likewise overwritten). To change membership
    incrementally without clobbering existing values, use opencdr_lists_add /
    opencdr_lists_remove instead. Creates the list if it does not exist.
    """
    url, key = _resolve_api()
    payload = {
        "rule_id": list_id,
        "rule_kind": "list",
        "description": description,
        "values": values or [],
    }
    query = _qs(rule_kind="list")
    status, body = opencdr._request(
        "PUT", f"/rules/{_seg(list_id, 'list_id')}?{query}", url, key, json=payload
    )
    _raise_on_error(status, body, "lists replace")
    return body


def _list_compare_and_set(list_id: str, value: str, *, add: bool, context: str) -> dict:
    """Read-modify-write a single list value under optimistic concurrency.

    Reads the list, applies the add/remove, and PUTs it back guarded by the
    `rev` it read (`expected_rev`). If a concurrent writer changed the list in
    between, the API returns 409 and we re-read and retry (bounded compare-and-
    set -- the API owns the guarantee; this is not a lock). No-ops (value
    already present / already absent) short-circuit without a write.
    """
    url, key = _resolve_api()
    query = _qs(rule_kind="list")
    for _ in range(_CAS_MAX_ATTEMPTS):
        item = _get_list_or_raise(url, key, list_id)
        values = list(item.get("values") or [])
        present = value in values
        if add and present:
            return {"changed": False, "list_id": list_id, "values": values}
        if not add and not present:
            return {"changed": False, "list_id": list_id, "values": values}
        if add:
            values.append(value)
        else:
            values.remove(value)
        item["values"] = values
        item["expected_rev"] = int(item.get("rev") or 0)
        status, body = opencdr._request(
            "PUT", f"/rules/{_seg(list_id, 'list_id')}?{query}", url, key, json=item
        )
        if status == 409:
            continue  # concurrent write -- re-read the current rev and retry
        _raise_on_error(status, body, context)
        return body
    raise RuntimeError(
        f"{context}: list {list_id} is being modified concurrently -- retried "
        f"{_CAS_MAX_ATTEMPTS} times, give up and retry the operation"
    )


@_tool(CAP_RULES, annotations=_MUTATING)
def opencdr_lists_add(list_id: str, value: str) -> dict:
    """Add a single value to an existing list (no-op if already present).

    Concurrency-safe: the write is guarded by the list's `rev` (optimistic
    concurrency, enforced by the API), so a simultaneous edit by another
    writer cannot be silently lost. The list must already exist.
    """
    return _list_compare_and_set(list_id, value, add=True, context="lists add")


@_tool(CAP_RULES, annotations=_MUTATING)
def opencdr_lists_remove(list_id: str, value: str) -> dict:
    """Remove a single value from a list (no-op if not present).

    Concurrency-safe: the write is guarded by the list's `rev` (optimistic
    concurrency, enforced by the API).
    """
    return _list_compare_and_set(list_id, value, add=False, context="lists remove")


@_tool(CAP_RULES, annotations=_DESTRUCTIVE)
def opencdr_lists_delete(list_id: str) -> dict:
    """Delete a list entirely. DESTRUCTIVE and irreversible."""
    url, key = _resolve_api()
    query = _qs(rule_kind="list")
    status, body = opencdr._request(
        "DELETE", f"/rules/{_seg(list_id, 'list_id')}?{query}", url, key
    )
    if status == 404:
        return {"found": False, "list_id": list_id}
    _raise_on_error(status, body, "lists delete")
    return {"deleted": True, "list_id": list_id}


# ---------------------------------------------------------------------------
# Signals / logs (read-only investigation queries)
#
# NOTE ON FILTERS: the backend serves these from single-partition GSI
# queries, so exactly ONE indexed selector is supported per call
# (severity|event_id|category for signals; service|event_id|event_name for
# logs). It cannot AND-combine selectors, nor filter by source_ip / principal
# / resource / account_id / region -- those require new backend indexes. The
# richer multi-filter search described in the MCP hardening brief is a
# documented backend gap, deliberately NOT faked here by client-side scanning.
# date_from/date_to apply only to the day-bucketed selector (severity /
# service).
# ---------------------------------------------------------------------------


@_tool(CAP_READ, annotations=_READ_ONLY)
def opencdr_signals_search(
    severity: Severity | None = None,
    event_id: str | None = None,
    category: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    limit: int = 25,
    order: Order = "desc",
    next_token: str | None = None,
    integration_id: str | None = None,
) -> dict:
    """Search detection signals. Read-only.

    Provide exactly ONE selector: severity, event_id, category, or integration_id (the
    backend serves each from a dedicated index and cannot AND-combine them).
    date_from/date_to (YYYY-MM-DD, UTC, inclusive, max 31-day range) apply
    ONLY to the severity selector and default to the last 7 days; they are
    ignored for event_id/category. Paginated via next_token.

    Correlating by source_ip / principal / resource / account / region is not
    yet supported by the backend -- use event_id to pivot on a specific event.
    """
    provided = [x for x in (severity, event_id, category, integration_id) if x]
    if len(provided) != 1:
        raise ValueError("Provide exactly one of severity, event_id, category, or integration_id")
    url, key = _resolve_api()
    query = _qs(
        limit=limit,
        order=order,
        severity=severity.upper() if severity else None,
        event_id=event_id,
        category=category,
        integration_id=integration_id,
        date_from=date_from if severity else None,
        date_to=date_to if severity else None,
        next_token=next_token,
    )
    status, body = opencdr._request("GET", f"/signals?{query}", url, key)
    _raise_on_error(status, body, "signals search")
    return body


@_tool(CAP_READ, annotations=_READ_ONLY)
def opencdr_signals_stats(date_from: str | None = None, date_to: str | None = None) -> dict:
    """Signal counts by severity for a date range. Read-only.

    A dashboard/summary view, not a substitute for opencdr_signals_search's
    paginated item listing. Defaults to the last 7 days if neither date is
    given (YYYY-MM-DD, UTC, inclusive; max range 31 days -- the same
    date-range bound the severity selector of opencdr_signals_search uses).
    Returns {date_from, date_to, counts: {<severity>: <count>, ...}, total}.
    """
    url, key = _resolve_api()
    query = _qs(date_from=date_from, date_to=date_to)
    path = "/signals/stats" + (f"?{query}" if query else "")
    status, body = opencdr._request("GET", path, url, key)
    _raise_on_error(status, body, "signals stats")
    return body


@_tool(CAP_READ, annotations=_READ_ONLY)
def opencdr_logs_search(
    service: str | None = None,
    event_id: str | None = None,
    event_name: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    limit: int = 25,
    order: Order = "desc",
    next_token: str | None = None,
) -> dict:
    """Search audit/CloudTrail logs. Read-only.

    Provide exactly ONE selector: service, event_id, or event_name (the
    backend serves each from a dedicated index and cannot AND-combine them).
    date_from/date_to (YYYY-MM-DD, UTC, inclusive, max 31-day range) apply
    ONLY to the service selector and default to the last 7 days; they are
    ignored for event_id/event_name. Paginated via next_token.

    Correlating by source_ip / principal / access_key_id / user_agent /
    resource / account is not yet supported by the backend -- use event_id to
    pivot on a specific event.
    """
    provided = [x for x in (service, event_id, event_name) if x]
    if len(provided) != 1:
        raise ValueError("Provide exactly one of service, event_id, or event_name")
    url, key = _resolve_api()
    query = _qs(
        limit=limit,
        order=order,
        service=service,
        event_id=event_id,
        event_name=event_name,
        date_from=date_from if service else None,
        date_to=date_to if service else None,
        next_token=next_token,
    )
    status, body = opencdr._request("GET", f"/logs?{query}", url, key)
    _raise_on_error(status, body, "logs search")
    return body


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


@_tool(CAP_READ, annotations=_READ_ONLY)
def opencdr_integrations_get(integration_id: str = "", jobs: bool = False, job_id: str = "") -> dict:
    """Get the parser catalog, integration binding, or ingestion job diagnostics."""
    url, key = _resolve_api()
    path = "/integrations"
    if integration_id:
        path += "/" + _seg(integration_id, "integration_id")
        if jobs:
            path += "/jobs"
            if job_id:
                path += "/" + _seg(job_id, "job_id")
    status, body = opencdr._request("GET", path, url, key)
    _raise_on_error(status, body, "integrations get")
    return body


@_tool(CAP_SETTINGS, annotations=_MUTATING)
def opencdr_integrations_put(integration_id: str, configuration: dict) -> dict:
    """Create/update a binding; configuration must include expected_rev (0 for create)."""
    url, key = _resolve_api()
    status, body = opencdr._request("PUT", "/integrations/" + _seg(integration_id, "integration_id"), url, key, json=configuration)
    _raise_on_error(status, body, "integration put")
    return body


@_tool(CAP_SETTINGS, annotations=_MUTATING)
def opencdr_integrations_preview(integration_id: str, configuration: dict, record: dict | str) -> dict:
    """Execute the selected parser on one sample; does not activate or emit detections."""
    url, key = _resolve_api()
    status, body = opencdr._request("POST", "/integrations/" + _seg(integration_id, "integration_id") + "/preview", url, key,
                                  json={"config": configuration, "record": record})
    _raise_on_error(status, body, "integration preview")
    return body


@_tool(CAP_READ, annotations=_READ_ONLY)
def opencdr_settings_get(setting_id: str = "global") -> dict:
    """Get an OpenCDR settings document by id (default: global). Read-only."""
    url, key = _resolve_api()
    status, body = opencdr._request("GET", f"/settings/{_seg(setting_id, 'setting_id')}", url, key)
    if status == 404:
        return {"found": False, "setting_id": setting_id}
    _raise_on_error(status, body, "settings get")
    return body


@_tool(CAP_SETTINGS, annotations=_MUTATING)
def opencdr_settings_set(
    setting_id: str = "global",
    channels: dict | None = None,
    guardduty_notify: dict | None = None,
    notifications_enabled: bool | None = None,
) -> dict:
    """Update an OpenCDR settings document (idempotent merge upsert).

    Only the fields provided are changed: an omitted channel (slack/
    discord/email/securityhub/jira/webhook) is left untouched, and
    guardduty_notify is merged key-by-key (default/by_severity/by_service/
    by_severity_and_service) rather than replaced wholesale -- same
    read-modify-write semantics as `opencdr.py settings set`, see
    docs/notifications.md. Concurrency-safe: the merge+write is guarded by the
    document's `rev` (optimistic concurrency enforced by the API), so a
    simultaneous edit cannot be silently lost; on a conflict the fetch+merge is
    re-run against the latest state (bounded compare-and-set, not a lock).

    `channels` shape (all keys optional):
      {"slack": {"webhook_url": str},
       "discord": {"webhook_url": str},
       "email": {"topic_arn": str},
       "securityhub": {"enabled": bool},
       "jira": {"url": str, "project": str, "email": str, "token": str},
       "webhook": {"targets": [{"name": str, "url": str, "headers": {..}}]}}
    `guardduty_notify` shape:
      {"default": bool, "by_severity": {"HIGH": bool, ...},
       "by_service": {"<svc>": bool, ...},
       "by_severity_and_service": {"HIGH:<svc>": bool, ...}}
    """
    url, key = _resolve_api()
    for _ in range(_CAS_MAX_ATTEMPTS):
        base_payload, existing_channels = opencdr._fetch_existing_settings(url, key, setting_id)

        payload = dict(base_payload)
        if notifications_enabled is not None:
            payload["notifications_enabled"] = notifications_enabled
        payload["channels"] = (
            opencdr._merge_channels(existing_channels, channels) if channels else existing_channels
        )
        if guardduty_notify:
            payload["guardduty_notify"] = opencdr._merge_guardduty_notify(
                base_payload.get("guardduty_notify") or {}, guardduty_notify
            )
        payload["expected_rev"] = int(base_payload.get("rev") or 0)

        status, body = opencdr._request(
            "PUT", f"/settings/{_seg(setting_id, 'setting_id')}", url, key, json=payload
        )
        if status == 409:
            continue  # concurrent write -- re-fetch, re-merge against latest, retry
        _raise_on_error(status, body, "settings set")
        return body
    raise RuntimeError(
        f"settings set: {setting_id} is being modified concurrently -- retried "
        f"{_CAS_MAX_ATTEMPTS} times, give up and retry the operation"
    )


@_tool(CAP_SETTINGS, annotations=_DESTRUCTIVE)
def opencdr_settings_delete(setting_id: str = "global") -> dict:
    """Delete an OpenCDR settings document by id. DESTRUCTIVE and irreversible."""
    url, key = _resolve_api()
    status, body = opencdr._request(
        "DELETE", f"/settings/{_seg(setting_id, 'setting_id')}", url, key
    )
    if status == 404:
        return {"found": False, "setting_id": setting_id}
    _raise_on_error(status, body, "settings delete")
    return {"deleted": True, "setting_id": setting_id}


# ---------------------------------------------------------------------------
# IR roles -- which IAM role responder assumes to take automated response
# actions, per AWS account. Privileged security configuration: a write here
# directly controls which role the responder may assume.
# ---------------------------------------------------------------------------


@_tool(CAP_READ, annotations=_READ_ONLY)
def opencdr_ir_roles_list(page_size: int = 20, next_token: str | None = None) -> dict:
    """List IR role mappings (which IAM role responder assumes per AWS account). Read-only."""
    url, key = _resolve_api()
    query = _qs(page_size=page_size, next_token=next_token)
    status, body = opencdr._request("GET", f"/ir-roles?{query}", url, key)
    _raise_on_error(status, body, "ir-roles list")
    return body


@_tool(CAP_READ, annotations=_READ_ONLY)
def opencdr_ir_roles_get(aws_account_id: str) -> dict:
    """Get the IR role mapping for a 12-digit AWS account id. Read-only."""
    _require_account_id(aws_account_id)
    url, key = _resolve_api()
    status, body = opencdr._request(
        "GET", f"/ir-roles/{_seg(aws_account_id, 'aws_account_id')}", url, key
    )
    if status == 404:
        return {"found": False, "aws_account_id": aws_account_id}
    _raise_on_error(status, body, "ir-roles get")
    return body


@_tool(CAP_IR_ROLES, annotations=_DESTRUCTIVE)
def opencdr_ir_roles_upsert(aws_account_id: str, role_arn: str, enabled: bool = True) -> dict:
    """Create/update the IR role mapping for an AWS account (PUT upsert).

    PRIVILEGED, security-sensitive: this controls which IAM role the
    responder assumes to take automated response actions in that account.

    role_arn must be an IAM role ARN (arn:aws:iam::<account>:role/<name>) and
    the account embedded in the ARN MUST equal aws_account_id -- a mapping
    whose ARN points at a different account is refused here (and by the API)
    to prevent introducing arbitrary cross-account role assumption. Set
    enabled=False to disable a mapping without deleting it.
    """
    aws_account_id = _require_account_id(aws_account_id)
    m = _ROLE_ARN_RE.match(role_arn or "")
    if not m:
        raise ValueError("role_arn must be an IAM role ARN: arn:aws:iam::<account>:role/<name>")
    if m.group(1) != aws_account_id:
        raise ValueError(
            "role_arn account does not match aws_account_id -- cross-account role mapping refused"
        )
    url, key = _resolve_api()
    payload = {"aws_account_id": aws_account_id, "role_arn": role_arn, "enabled": enabled}
    status, body = opencdr._request(
        "PUT", f"/ir-roles/{_seg(aws_account_id, 'aws_account_id')}", url, key, json=payload
    )
    _raise_on_error(status, body, "ir-roles upsert")
    return body


@_tool(CAP_IR_ROLES, annotations=_DESTRUCTIVE)
def opencdr_ir_roles_delete(aws_account_id: str) -> dict:
    """Delete the IR role mapping for an AWS account. DESTRUCTIVE.

    Removing a mapping means the responder falls back to its default role for
    that account (or can no longer act in it).
    """
    aws_account_id = _require_account_id(aws_account_id)
    url, key = _resolve_api()
    status, body = opencdr._request(
        "DELETE", f"/ir-roles/{_seg(aws_account_id, 'aws_account_id')}", url, key
    )
    if status == 404:
        return {"found": False, "aws_account_id": aws_account_id}
    _raise_on_error(status, body, "ir-roles delete")
    return {"deleted": True, "aws_account_id": aws_account_id}


# ---------------------------------------------------------------------------
# IR actions -- executed, rollback-eligible IR actions and their undo.
# ---------------------------------------------------------------------------


@_tool(CAP_READ, annotations=_READ_ONLY)
def opencdr_ir_actions_list(page_size: int = 20, next_token: str | None = None) -> dict:
    """List executed, rollback-eligible IR actions. Read-only."""
    url, key = _resolve_api()
    query = _qs(page_size=page_size, next_token=next_token)
    status, body = opencdr._request("GET", f"/ir-actions?{query}", url, key)
    _raise_on_error(status, body, "ir-actions list")
    return body


@_tool(CAP_READ, annotations=_READ_ONLY)
def opencdr_ir_actions_get(detection_id: str) -> dict:
    """Get a specific executed IR action. Read-only.

    Includes rollback_supported and, once a rollback has been attempted,
    rollback_status ("pending"/"succeeded"/"failed"), rollback_error (set
    only on failure), and rollback_updated_at. rolled_back mirrors
    rollback_status == "succeeded" for back-compat; absent rollback_status
    means no rollback has been attempted yet.
    """
    url, key = _resolve_api()
    status, body = opencdr._request(
        "GET", f"/ir-actions/{_seg(detection_id, 'detection_id')}", url, key
    )
    if status == 404:
        return {"found": False, "detection_id": detection_id}
    _raise_on_error(status, body, "ir-actions get")
    return body


@_tool(CAP_IR_ACTIONS_WRITE, annotations=_ROLLBACK)
def opencdr_ir_actions_rollback(detection_id: str, reason: str | None = None) -> dict:
    """Enqueue the rollback of a specific IR action for async execution.

    SECURITY-SENSITIVE: this reverses an automated containment action.
    Not idempotent -- a 409 is raised if a rollback is already in flight
    (rollback_status == "pending"); a previously failed rollback can be
    retried, a currently-pending one cannot. Raises on a 400 if rollback
    isn't supported for this action.

    Returns as soon as the rollback is enqueued, not once it has run --
    rollbackHandler executes it separately; poll opencdr_ir_actions_get for
    the outcome.

    `reason` is an optional human-readable justification (e.g. "containment
    determined to be a false positive"); when given it is recorded on the
    action's audit trail alongside the server-authenticated caller identity.
    The actor identity itself is never taken from this call -- it comes from
    the authenticated API key on the server side.
    """
    url, key = _resolve_api()
    payload: dict[str, Any] = {"interface": "mcp"}
    if reason:
        payload["reason"] = reason
    status, body = opencdr._request(
        "POST", f"/ir-actions/{_seg(detection_id, 'detection_id')}/rollback", url, key, json=payload
    )
    if status == 404:
        return {"found": False, "detection_id": detection_id}
    _raise_on_error(status, body, "ir-actions rollback")
    return body


if __name__ == "__main__":
    mcp.run()

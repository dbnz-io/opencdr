# src/handlers/api.py
from __future__ import annotations

import base64
import json
import os
import re
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import boto3
from boto3.dynamodb.conditions import Key

from ..domain.settings_secrets import (
    SECRET_CHANNEL_FIELDS,
    is_ssm_ref,
    iter_secret_locations,
    ssm_param_name,
    ssm_ref,
    ssm_ref_param_name,
)
from ..infra.detection_rules_repository import unpack_rule_body
from ..infra.xray_setup import patch_boto3

patch_boto3()

# ---------------------------------------------------------------------------
# Env / DynamoDB tables
# ---------------------------------------------------------------------------

LAMBDA_NAME = os.getenv("LAMBDA_NAME", "opencdr-api")

SIGNALS_TABLE_NAME = os.getenv("SIGNALS_TABLE_NAME", "")
ALERTS_TABLE_NAME = os.getenv("ALERTS_TABLE_NAME", "")
LOGS_TABLE_NAME = os.getenv("LOGS_TABLE_NAME", "")
DETECTION_RULES_TABLE_NAME = os.getenv("DETECTION_RULES_TABLE_NAME", "")
SETTINGS_TABLE_NAME = os.getenv("SETTINGS_TABLE_NAME", "")
IR_ACCOUNT_ROLES_TABLE_NAME = os.getenv("IR_ACCOUNT_ROLES_TABLE_NAME", "")
IR_ACTIONS_TABLE_NAME = os.getenv("IR_ACTIONS_TABLE_NAME", "")
IR_ROLLBACK_QUEUE_URL = os.getenv("IR_ROLLBACK_QUEUE_URL", "")

ddb = boto3.resource("dynamodb")
ssm = boto3.client("ssm")
apigateway = boto3.client("apigateway")
sqs = boto3.client("sqs")

signals_table = ddb.Table(SIGNALS_TABLE_NAME)
alerts_table = ddb.Table(ALERTS_TABLE_NAME)
logs_table = ddb.Table(LOGS_TABLE_NAME)
detection_rules_table = ddb.Table(DETECTION_RULES_TABLE_NAME)
settings_table = ddb.Table(SETTINGS_TABLE_NAME)
ir_account_roles_table = ddb.Table(IR_ACCOUNT_ROLES_TABLE_NAME)
ir_actions_table = ddb.Table(IR_ACTIONS_TABLE_NAME)


# ---------------------------------------------------------------------------
# Constants / Validation
# ---------------------------------------------------------------------------

SERVICE = os.getenv("SERVICE_NAME", "OPENCDR-API")

ALLOWED_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "INFORMATIONAL"}
ALLOWED_RULE_KINDS = {"signal", "correlation", "list"}

# Every handler src/handlers/responder.py's RESPONSE_MODULE_HANDLERS actually
# registers. Kept in sync by hand -- api.py deliberately doesn't import
# responder.py (that would pull dredge and its transitive closure into the
# api Lambda's cold start for a set of string literals) -- but drifting
# is exactly the ALLOWED_CONDITION_OPS/engine class of bug this repo has
# already hit once, so tests/handlers/test_api.py asserts this set equals
# responder.RESPONSE_MODULE_HANDLERS.keys() exactly.
ALLOWED_RESPONSE_MODULES = {
    "disable_access_key",
    "disable_user",
    "delete_user",
    "disable_role",
    "revoke_active_sessions",
    "delete_inline_policy",
    "block_s3_public_access",
    "block_s3_bucket_public_access",
    "block_s3_object_public_access",
    "quarantine_s3_bucket",
    "isolate_ec2_instances",
    "deauthorize_security_group_rules",
    "disable_lambda_function",
    "disable_secrets_manager_secret",
    "revoke_rds_snapshot_public_access",
    "enable_cloudtrail_logging",
    "enable_guardduty_detector",
    "start_config_recorder",
    "enable_security_hub",
}

# Same hand-synced-and-tested pattern as ALLOWED_RESPONSE_MODULES above, this
# time mirroring responder.ROLLBACK_UNDO_MODULE.keys() -- the subset of
# response modules dredge can actually undo (see dredge/aws_ir/response.py's
# "Rollback / undo actions" section and docs/incident-response.md#rollback).
# tests/handlers/test_api.py asserts this equals that dict's keys exactly.
ROLLBACK_ELIGIBLE_MODULES = {
    "disable_access_key",
    "revoke_active_sessions",
    "deauthorize_security_group_rules",
    "block_s3_public_access",
    "block_s3_bucket_public_access",
    "block_s3_object_public_access",
    "disable_lambda_function",
    "disable_secrets_manager_secret",
    "disable_user",
    "disable_role",
    "quarantine_s3_bucket",
    "isolate_ec2_instances",
    "revoke_rds_snapshot_public_access",
    "delete_inline_policy",
}

# GET /signals?severity=.. / GET /logs?service=.. now query a day-bucketed
# key (see src/infra/partition_keys.py), one Query per day in range --
# bounds how wide a single request's fan-out can get.
MAX_DATE_RANGE_DAYS = 31

# Partitions GET /rules queries when no ?rule_kind filter is given.
# Deliberately excludes "list" -- a list rule is a lookup table other rules
# reference (in_list/not_in_list), not itself something a user browsing
# "all rules" expects to see mixed in. Explicit ?rule_kind=list still works
# via the single-partition branch in _handle_list_rules, which validates
# against ALLOWED_RULE_KINDS directly.
_DEFAULT_RULE_LISTING_KINDS = {"signal", "correlation"}

# Every op detection_engine.evaluate_condition actually implements. Kept in
# sync by hand (INFORME-AUTOR-ES.md §3.1 found this had drifted from the
# engine in both directions: wildcard/in_list/not_in_list were implemented
# but rejected here, not_prefix/not_suffix were accepted here but not
# implemented -- silently never matching, with no error either side).
ALLOWED_CONDITION_OPS = {
    "equals",
    "not_equals",
    "in",
    "not_in",
    "in_list",
    "not_in_list",
    "exists",
    "not_exists",
    "matches",
    "not_matches",
    "contains",
    "not_contains",
    "prefix",
    "not_prefix",
    "suffix",
    "not_suffix",
    "wildcard",
}

# Ops that don't take a "value" at all -- exists/not_exists check presence,
# wildcard always matches.
_NO_VALUE_CONDITION_OPS = {"exists", "not_exists", "wildcard"}
# Ops that reference a rule_kind="list" rule by id instead of an inline value.
_LIST_CONDITION_OPS = {"in_list", "not_in_list"}

_REGEX_CONDITION_OPS = {"matches", "not_matches"}

# Sane, generous bounds for correlation rules -- not business-tuned, just
# enough to catch an obviously-wrong value (e.g. a typo'd extra zero)
# before it reaches production. Defaults in correlation_engine.py are
# threshold=5, time_window_seconds=300.
MIN_THRESHOLD = 1
MAX_THRESHOLD = 1000
MIN_TIME_WINDOW_SECONDS = 1
MAX_TIME_WINDOW_SECONDS = 86400  # 24h

# ---------------------------------------------------------------------------
# API key route scoping
#
# One API key used to control everything (read, rule mutation, settings,
# IR-role assignment) -- see docs/api-reference.md's "API key scopes"
# section. A key's scopes are encoded in its API Gateway key *name*
# (serverless.yml), dash-suffixed: "<...>-api-key-settings" -> {"settings"}.
# The bare, pre-existing key name ("<...>-api-key", no suffix) maps to all
# scopes -- back-compat for the key already deployed/distributed before
# scoping existed.
# ---------------------------------------------------------------------------

# "ir_roles"/"ir_actions" use an underscore, not a dash, deliberately:
# key-name suffixes are dash-joined ("-settings-rules"), so a dash-containing
# scope name would collide with the separator and never parse back out
# correctly.
ALL_SCOPES = frozenset({"read", "rules", "settings", "ir_roles", "ir_actions"})

# Matches serverless.yml's `${self:service}-${self:provider.stage}-api-key`
# ("opencdr" is a hardcoded literal in serverless.yml's top-level `service:`,
# not parameterized -- STAGE is the only piece that varies at deploy time).
_API_KEY_NAME_PREFIX = f"opencdr-{os.getenv('STAGE', 'dev')}-api-key"
_KEY_SCOPE_CACHE_TTL_SECONDS = int(os.getenv("API_KEY_SCOPE_CACHE_TTL_SECONDS", "300"))
_key_scope_cache: dict[str, tuple[frozenset[str], float]] = {}


# ---------------------------------------------------------------------------
# Entry
# ---------------------------------------------------------------------------


def lambda_handler(event, context):
    request_id = getattr(context, "aws_request_id", None)

    method = _get_http_method(event)
    path = _get_path(event)
    qs = event.get("queryStringParameters") or {}
    path_params = event.get("pathParameters") or {}

    required_scope = _required_scope_for(method, path)
    if required_scope and required_scope not in _get_key_scopes(_get_api_key_id(event)):
        return _response(403, {"message": f"API key missing required scope: {required_scope}", "request_id": request_id})

    try:
        # ------------------------------------------------------------------
        # /status
        # ------------------------------------------------------------------
        if path == "/status" and method == "GET":
            return _response(
                200,
                {
                    "status": "ok",
                    "service": SERVICE,
                    "lambda_name": LAMBDA_NAME,
                    "time": datetime.now(UTC).isoformat(),
                    "request_id": request_id,
                },
            )

        # ------------------------------------------------------------------
        # /Docs
        # ------------------------------------------------------------------
        if path == "/help" and method == "GET":
            return _response(200, _help_payload())

        # ------------------------------------------------------------------
        # /signals (list) + optional GSI queries
        #
        # Base table:
        #   PK: severity
        #   SK: timestamp
        #
        # GSIs:
        #   gsi_signal_event_id:    PK=event_id,  SK=timestamp
        #   gsi_signal_category_id: PK=category,  SK=timestamp
        # ------------------------------------------------------------------
        if path == "/signals" and method == "GET":
            return _handle_list_signals(qs)

        # Aggregate counts by severity for a date range -- a dashboard's
        # "signals today / this week / this month" widget has no cheap way
        # to get this from the paginated list endpoint above. An exact
        # match, same as "/signals" itself, so it's not a prefix/ordering
        # concern the way "/rules/{id}" is below -- placed here since it's
        # a sibling concern of the route right above it.
        if path == "/signals/stats" and method == "GET":
            return _handle_signal_stats(qs)

        # ------------------------------------------------------------------
        # /logs (list) + optional GSI queries
        #
        # Base table:
        #   PK: service
        #   SK: timestamp
        #
        # GSIs:
        #   gsi_logs_event_id: PK=event_id,   SK=timestamp
        #   gsi_activity_name: PK=event_name, SK=timestamp
        # ------------------------------------------------------------------
        if path == "/logs" and method == "GET":
            return _handle_list_logs(qs)

        # ------------------------------------------------------------------
        # /rules (list/create)
        #
        # Table:
        #   PK: rule_kind (signal|correlation|list)
        #   SK: rule_id
        #
        # serverless.yml wires GET/POST /rules and GET/PUT/DELETE
        # /rules/{rule_id} -- every method these handlers support is a real,
        # exposed route, not just a subset.
        # ------------------------------------------------------------------
        if path == "/rules" and method == "GET":
            return _handle_list_rules(qs)

        if path == "/rules" and method == "POST":
            body = _parse_json_body(event)
            return _handle_create_rule(body)

        # /rules/{rule_id}
        if path.startswith("/rules/"):
            rule_id = (
                path_params.get("rule_id") or path.split("/")[2]
                if len(path.split("/")) > 2
                else None
            )
            if not rule_id:
                return _response(400, {"message": "Missing rule_id in path"})

            if method == "GET":
                return _handle_get_rule(rule_id, qs)
            if method == "PUT":
                body = _parse_json_body(event)
                return _handle_update_rule(rule_id, body)
            if method == "DELETE":
                return _handle_delete_rule(rule_id, qs)

        # ------------------------------------------------------------------
        # /settings (global + by id)
        # ------------------------------------------------------------------
        if path == "/settings" and method == "GET":
            return _handle_get_settings("global")

        if path == "/settings" and method == "POST":
            body = _parse_json_body(event)
            return _handle_create_settings("global", body)

        if path.startswith("/settings/"):
            setting_id = (
                path_params.get("setting_id") or path.split("/")[2]
                if len(path.split("/")) > 2
                else None
            )
            if not setting_id:
                return _response(400, {"message": "Missing setting_id in path"})

            if method == "GET":
                return _handle_get_settings(setting_id)
            if method == "PUT":
                body = _parse_json_body(event)
                return _handle_upsert_settings(setting_id, body)
            if method == "DELETE":
                return _handle_delete_settings(setting_id)

        # ------------------------------------------------------------------
        # /ir-roles (which IAM role the responder assumes, per AWS account)
        # ------------------------------------------------------------------
        if path == "/ir-roles" and method == "GET":
            return _handle_list_ir_roles(qs)

        if path == "/ir-roles" and method == "POST":
            body = _parse_json_body(event)
            return _handle_create_ir_role(body)

        if path.startswith("/ir-roles/"):
            account_id = (
                path_params.get("aws_account_id") or path.split("/")[2]
                if len(path.split("/")) > 2
                else None
            )
            if not account_id:
                return _response(400, {"message": "Missing aws_account_id in path"})

            if method == "GET":
                return _handle_get_ir_role(account_id)
            if method == "PUT":
                body = _parse_json_body(event)
                return _handle_upsert_ir_role(account_id, body)
            if method == "DELETE":
                return _handle_delete_ir_role(account_id)

        # ------------------------------------------------------------------
        # /ir-actions (executed IR actions + rollback)
        # ------------------------------------------------------------------
        if path == "/ir-actions" and method == "GET":
            return _handle_list_ir_actions(qs)

        if path.startswith("/ir-actions/"):
            parts = path.split("/")
            detection_id = path_params.get("detection_id") or (parts[2] if len(parts) > 2 else None)
            if not detection_id:
                return _response(400, {"message": "Missing detection_id in path"})
            is_rollback_route = len(parts) > 3 and parts[3] == "rollback"

            if method == "GET" and not is_rollback_route:
                return _handle_get_ir_action(detection_id)
            if method == "POST" and is_rollback_route:
                return _handle_rollback_ir_action(detection_id)

        return _response(404, {"message": f"Route {method} {path} not found"})

    except ValueError as ve:
        return _response(400, {"message": str(ve), "request_id": request_id})
    except Exception as e:
        return _response(500, {"message": repr(e), "request_id": request_id})


# ---------------------------------------------------------------------------
# Routing helpers
# ---------------------------------------------------------------------------


def _get_http_method(event: dict) -> str:
    if "httpMethod" in event:
        return str(event["httpMethod"]).upper()
    rc = event.get("requestContext") or {}
    http = rc.get("http") or {}
    return str(http.get("method", "GET")).upper()


def _get_path(event: dict) -> str:
    if "path" in event:
        return str(event["path"])
    return str(event.get("rawPath", "/"))


def _required_scope_for(method: str, path: str) -> str | None:
    """Which scope a route needs, or None if any valid key may call it."""
    if path in ("/status", "/help"):
        return None
    if path == "/rules" or path.startswith("/rules/"):
        return "read" if method == "GET" else "rules"
    if path == "/settings" or path.startswith("/settings/"):
        return "read" if method == "GET" else "settings"
    if path == "/ir-roles" or path.startswith("/ir-roles/"):
        return "read" if method == "GET" else "ir_roles"
    if path == "/ir-actions" or path.startswith("/ir-actions/"):
        return "read" if method == "GET" else "ir_actions"
    if path in ("/signals", "/signals/stats", "/logs"):
        return "read"
    return None  # unrecognized route -- falls through to the 404 below


def _get_api_key_id(event: dict) -> str | None:
    rc = event.get("requestContext") or {}
    identity = rc.get("identity") or {}
    return identity.get("apiKeyId") or None


def _scopes_from_key_name(name: str) -> frozenset[str]:
    if name == _API_KEY_NAME_PREFIX:
        return ALL_SCOPES  # bare key, no suffix -- back-compat, full access
    prefix = _API_KEY_NAME_PREFIX + "-"
    if not name.startswith(prefix):
        return frozenset()  # unrecognized key name -- fail closed
    tokens = frozenset(name[len(prefix):].split("-"))
    return tokens & ALL_SCOPES


def _get_key_scopes(api_key_id: str | None) -> frozenset[str]:
    if not api_key_id:
        return frozenset()

    now = time.time()
    cached = _key_scope_cache.get(api_key_id)
    if cached is not None and (now - cached[1]) < _KEY_SCOPE_CACHE_TTL_SECONDS:
        return cached[0]

    try:
        name = apigateway.get_api_key(apiKey=api_key_id).get("name", "")
    except Exception:
        return frozenset()  # fail closed -- don't cache a transient failure

    scopes = _scopes_from_key_name(name)
    _key_scope_cache[api_key_id] = (scopes, now)
    return scopes


def _parse_json_body(event: dict) -> dict:
    body = event.get("body")
    if not body:
        return {}
    if event.get("isBase64Encoded"):
        body = base64.b64decode(body).decode("utf-8")
    try:
        out = json.loads(body)
    except json.JSONDecodeError as err:
        raise ValueError("Request body is not valid JSON") from err
    if not isinstance(out, dict):
        raise ValueError("Request body must be a JSON object")
    return out


# ---------------------------------------------------------------------------
# Cursor pagination helpers
# ---------------------------------------------------------------------------


def _decode_next_token(token: str | None) -> dict | None:
    if not token:
        return None
    try:
        decoded = base64.urlsafe_b64decode(token.encode()).decode()
        obj = json.loads(decoded)
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


def _encode_next_token(last_evaluated_key: dict | None) -> str | None:
    if not last_evaluated_key:
        return None
    return base64.urlsafe_b64encode(json.dumps(last_evaluated_key).encode()).decode()


def _parse_order(qs: dict[str, str]) -> str:
    order = (qs.get("order") or "desc").lower()
    return order if order in ("asc", "desc") else "desc"


def _parse_limit(qs: dict[str, str], *, default: int = 20, max_limit: int = 200) -> int:
    try:
        n = int(qs.get("page_size") or qs.get("limit") or default)
    except (TypeError, ValueError):
        n = default
    if n < 1:
        n = default
    if n > max_limit:
        n = max_limit
    return n


def _parse_date_range(qs: dict[str, str]) -> tuple[str, str]:
    """
    (date_from, date_to) as "YYYY-MM-DD" strings, UTC, inclusive.
    Defaults to the last 7 days if neither is given -- GET /signals and
    GET /logs's severity/service selectors now query a day-bucketed key
    (see src/infra/partition_keys.py) and can no longer browse unbounded
    history. Raises ValueError on anything malformed, backwards, or
    wider than MAX_DATE_RANGE_DAYS.
    """

    def _parse_day(raw: str):
        try:
            return datetime.strptime(raw, "%Y-%m-%d").date()
        except (TypeError, ValueError):
            raise ValueError(f"Invalid date (expected YYYY-MM-DD): {raw!r}") from None

    today = datetime.now(UTC).date()
    raw_from, raw_to = qs.get("date_from"), qs.get("date_to")

    date_to = _parse_day(raw_to) if raw_to else today
    date_from = _parse_day(raw_from) if raw_from else date_to - timedelta(days=6)

    if date_from > date_to:
        raise ValueError("date_from must be <= date_to")
    if (date_to - date_from).days + 1 > MAX_DATE_RANGE_DAYS:
        raise ValueError(f"date range too wide -- max {MAX_DATE_RANGE_DAYS} days")

    return date_from.strftime("%Y-%m-%d"), date_to.strftime("%Y-%m-%d")


def _date_range_days(date_from: str, date_to: str, *, descending: bool) -> list[str]:
    """["YYYY-MM-DD", ...] for every day in [date_from, date_to], ordered
    newest-first if descending else oldest-first -- matches the
    requested `order` so merge-pagination renders in the right sequence.
    Empty if date_from > date_to (e.g. after cutover-date clamping)."""
    start = datetime.strptime(date_from, "%Y-%m-%d").date()
    end = datetime.strptime(date_to, "%Y-%m-%d").date()
    days = []
    d = start
    while d <= end:
        days.append(d.strftime("%Y-%m-%d"))
        d += timedelta(days=1)
    if descending:
        days.reverse()
    return days


def _query_bucketed_range(
    table,
    hash_attr: str,
    hash_prefix: str,
    days: list[str],
    *,
    scan_forward: bool,
    limit: int,
    cursor: dict[str, Any] | None,
) -> tuple[list[Any], dict[str, Any], bool]:
    """
    Merge-paginate a day-bucketed base-table key (severity_bucket /
    service_bucket) across `days` (already ordered to match the request's
    `order`), draining day N before touching day N+1 within a single
    page. Unlike _list_rules_all_partitions (which caps each partition
    independently and concatenates in a fixed order -- fine for a
    static, order-agnostic rules catalog), /signals and /logs are
    chronological feeds: a burst spanning a UTC-midnight boundary must
    still render in strict order under a strict page_size, not "up to
    len(days) * page_size". Cursor semantics otherwise match
    _list_rules_all_partitions's house style: a day mapped to None was
    already exhausted on a prior page (skip, don't requery); a day
    missing from the cursor hasn't been touched yet (start fresh).
    """
    incoming = cursor or {}
    merged: list[Any] = []
    outgoing: dict[str, Any] = {}
    remaining = limit

    for day in days:
        if remaining <= 0:
            if day in incoming:
                outgoing[day] = incoming[day]  # preserve untouched state
            continue
        if day in incoming and incoming[day] is None:
            outgoing[day] = None  # exhausted on a prior page
            continue

        kwargs: dict[str, Any] = {
            "KeyConditionExpression": Key(hash_attr).eq(f"{hash_prefix}#{day}"),
            "ScanIndexForward": scan_forward,
            "Limit": remaining,
        }
        day_esk = incoming.get(day)
        if day_esk:
            kwargs["ExclusiveStartKey"] = day_esk

        resp = table.query(**kwargs)
        items = resp.get("Items", [])
        merged.extend(items)
        remaining -= len(items)
        day_lek = resp.get("LastEvaluatedKey")
        outgoing[day] = day_lek

        if day_lek is not None:
            # This day isn't exhausted (DynamoDB's own ~1MB per-response
            # cap can return fewer than `Limit` items with a non-null
            # LastEvaluatedKey) -- stop the page here rather than
            # advancing to an older/newer day out of chronological
            # order. One query call per day per page, same convention
            # as this file's other per-partition queries (see
            # _list_rules_all_partitions): a call might not fill the
            # remaining budget; the client's next_token continues from
            # here rather than looping server-side to force a full page.
            break

    has_next = any(v is not None for v in outgoing.values())
    return merged, outgoing, has_next


# ---------------------------------------------------------------------------
# Responses
# ---------------------------------------------------------------------------


def _to_json_safe(x: Any) -> Any:
    """
    Keep it simple: DynamoDB resource API already returns plain Python types
    for common attrs. If you ever get Decimals, convert them.
    """
    try:
        from decimal import Decimal
    except Exception:
        Decimal = None  # type: ignore

    if Decimal is not None and isinstance(x, Decimal):
        # prefer int if whole, else float
        if x % 1 == 0:
            return int(x)
        return float(x)
    if isinstance(x, dict):
        return {k: _to_json_safe(v) for k, v in x.items()}
    if isinstance(x, list):
        return [_to_json_safe(v) for v in x]
    return x


def _response(status: int, body: Any) -> dict:
    safe_body = _to_json_safe(body)
    return {
        "statusCode": status,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
        },
        "body": json.dumps(safe_body),
    }


# ---------------------------------------------------------------------------
# /signals
# ---------------------------------------------------------------------------


def _handle_list_signals(qs: dict[str, str]) -> dict:
    """
    GET /signals

    Supported query shapes (efficient queries with correct pagination):
      1) By severity (base table, day-bucketed under the hood):
         ?severity=HIGH&date_from=2026-08-01&date_to=2026-08-12&order=desc&page_size=20&next_token=...
         date_from/date_to default to the last 7 days if omitted, max
         range MAX_DATE_RANGE_DAYS.

      2) By event_id (GSI: gsi_signal_event_id):
         ?event_id=...&order=desc&page_size=20&next_token=...

      3) By category (GSI: gsi_signal_category_id):
         ?category=...&order=desc&page_size=20&next_token=...

    Exactly one of severity|event_id|category is required.
    """
    severity = qs.get("severity")
    event_id = qs.get("event_id")
    category = qs.get("category")

    provided = [x for x in (severity, event_id, category) if x]
    if len(provided) != 1:
        raise ValueError("Provide exactly one of: severity, event_id, category")

    order = _parse_order(qs)
    scan_forward = order == "asc"
    limit = _parse_limit(qs, default=20, max_limit=200)
    esk = _decode_next_token(qs.get("next_token"))

    if severity:
        sev = str(severity).upper()
        if sev not in ALLOWED_SEVERITIES:
            raise ValueError(f"severity must be one of {sorted(ALLOWED_SEVERITIES)}")

        date_from, date_to = _parse_date_range(qs)
        days = _date_range_days(date_from, date_to, descending=not scan_forward)
        merged, outgoing, has_next = _query_bucketed_range(
            signals_table, "severity_bucket", sev, days,
            scan_forward=scan_forward, limit=limit, cursor=esk,
        )

        return _response(
            200,
            {
                "query": {"severity": sev, "date_from": date_from, "date_to": date_to},
                "order": order,
                "page_size": limit,
                "items": merged,
                "next_token": _encode_next_token(outgoing) if has_next else None,
                "has_next": has_next,
            },
        )

    if event_id:
        kwargs = {
            "IndexName": "gsi_signal_event_id",
            "KeyConditionExpression": Key("event_id").eq(event_id),
            "ScanIndexForward": scan_forward,
            "Limit": limit,
        }
        if esk:
            kwargs["ExclusiveStartKey"] = esk
        resp = signals_table.query(**kwargs)

        lek = resp.get("LastEvaluatedKey")
        return _response(
            200,
            {
                "query": {"event_id": event_id, "index": "gsi_signal_event_id"},
                "order": order,
                "page_size": limit,
                "items": resp.get("Items", []),
                "next_token": _encode_next_token(lek),
                "has_next": lek is not None,
            },
        )

    # category
    kwargs = {
        "IndexName": "gsi_signal_category_id",
        "KeyConditionExpression": Key("category").eq(category),
        "ScanIndexForward": scan_forward,
        "Limit": limit,
    }
    if esk:
        kwargs["ExclusiveStartKey"] = esk
    resp = signals_table.query(**kwargs)

    lek = resp.get("LastEvaluatedKey")
    return _response(
        200,
        {
            "query": {"category": category, "index": "gsi_signal_category_id"},
            "order": order,
            "page_size": limit,
            "items": resp.get("Items", []),
            "next_token": _encode_next_token(lek),
            "has_next": lek is not None,
        },
    )


def _count_signals_for_day(severity: str, day: str) -> int:
    """
    Select=COUNT against one severity_bucket partition ("SEVERITY#DAY").
    Paginates on LastEvaluatedKey rather than trusting a single response's
    Count -- DynamoDB caps a single Query response at ~1MB regardless of
    Select=COUNT, so a genuinely high-volume day would otherwise silently
    under-count instead of erroring, which is worse for a stats endpoint
    than the extra round trips this costs on the rare day that needs them.
    """
    total = 0
    kwargs: dict[str, Any] = {
        "KeyConditionExpression": Key("severity_bucket").eq(f"{severity}#{day}"),
        "Select": "COUNT",
    }
    while True:
        resp = signals_table.query(**kwargs)
        total += resp.get("Count", 0)
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            return total
        kwargs["ExclusiveStartKey"] = lek


def _handle_signal_stats(qs: dict[str, str]) -> dict:
    """
    GET /signals/stats

    Signal counts by severity for a date range (defaults to the last 7
    days, same as GET /signals -- see _parse_date_range). One
    Select=COUNT query per (severity, day): severity_bucket's partition
    key already encodes both severity and day together
    ("CRITICAL#2026-08-17"), so there's no single key shape that could
    answer "how many, across N days" in one call -- same day-fan-out
    shape /signals' own severity queries already use (_query_bucketed_range),
    just without a page-size cap since a count, unlike a page of items,
    has no natural stopping point short of the full range. Sequential, not
    threaded: the api Lambda's 25s timeout already has headroom sized for
    a worst-case MAX_DATE_RANGE_DAYS fan-out (see serverless.yml), and
    threaded boto3 calls from worker threads outside the main invocation's
    X-Ray context would log spuriously (context_missing="LOG_ERROR" in
    xray_setup.py) for every single one of up to 31*6=186 calls.
    """
    date_from, date_to = _parse_date_range(qs)
    days = _date_range_days(date_from, date_to, descending=False)

    counts = {sev: 0 for sev in ALLOWED_SEVERITIES}
    for sev in ALLOWED_SEVERITIES:
        for day in days:
            counts[sev] += _count_signals_for_day(sev, day)

    return _response(
        200,
        {
            "date_from": date_from,
            "date_to": date_to,
            "counts": counts,
            "total": sum(counts.values()),
        },
    )


# ---------------------------------------------------------------------------
# /logs
# ---------------------------------------------------------------------------


def _handle_list_logs(qs: dict[str, str]) -> dict:
    """
    GET /logs

    Supported query shapes (efficient queries with correct pagination):
      1) By service (base table, day-bucketed under the hood):
         ?service=OPENCDR-API&date_from=2026-08-01&date_to=2026-08-12&order=desc&page_size=20&next_token=...
         date_from/date_to default to the last 7 days if omitted, max
         range MAX_DATE_RANGE_DAYS.

      2) By event_id (GSI: gsi_logs_event_id):
         ?event_id=...&order=desc&page_size=20&next_token=...

      3) By event_name (GSI: gsi_activity_name):
         ?event_name=ConsoleLogin&order=desc&page_size=20&next_token=...

    Exactly one of service|event_id|event_name is required.
    """
    service_name = qs.get("service")
    event_id = qs.get("event_id")
    event_name = qs.get("event_name")

    provided = [x for x in (service_name, event_id, event_name) if x]
    if len(provided) != 1:
        raise ValueError("Provide exactly one of: service, event_id, event_name")

    order = _parse_order(qs)
    scan_forward = order == "asc"
    limit = _parse_limit(qs, default=20, max_limit=200)
    esk = _decode_next_token(qs.get("next_token"))

    if service_name:
        date_from, date_to = _parse_date_range(qs)
        days = _date_range_days(date_from, date_to, descending=not scan_forward)
        merged, outgoing, has_next = _query_bucketed_range(
            logs_table, "service_bucket", service_name, days,
            scan_forward=scan_forward, limit=limit, cursor=esk,
        )

        return _response(
            200,
            {
                "query": {"service": service_name, "date_from": date_from, "date_to": date_to},
                "order": order,
                "page_size": limit,
                "items": merged,
                "next_token": _encode_next_token(outgoing) if has_next else None,
                "has_next": has_next,
            },
        )

    if event_id:
        kwargs = {
            "IndexName": "gsi_logs_event_id",
            "KeyConditionExpression": Key("event_id").eq(event_id),
            "ScanIndexForward": scan_forward,
            "Limit": limit,
        }
        if esk:
            kwargs["ExclusiveStartKey"] = esk
        resp = logs_table.query(**kwargs)
        lek = resp.get("LastEvaluatedKey")
        return _response(
            200,
            {
                "query": {"event_id": event_id, "index": "gsi_logs_event_id"},
                "order": order,
                "page_size": limit,
                "items": resp.get("Items", []),
                "next_token": _encode_next_token(lek),
                "has_next": lek is not None,
            },
        )

    # event_name
    kwargs = {
        "IndexName": "gsi_activity_name",
        "KeyConditionExpression": Key("event_name").eq(event_name),
        "ScanIndexForward": scan_forward,
        "Limit": limit,
    }
    if esk:
        kwargs["ExclusiveStartKey"] = esk
    resp = logs_table.query(**kwargs)
    lek = resp.get("LastEvaluatedKey")
    return _response(
        200,
        {
            "query": {"event_name": event_name, "index": "gsi_activity_name"},
            "order": order,
            "page_size": limit,
            "items": resp.get("Items", []),
            "next_token": _encode_next_token(lek),
            "has_next": lek is not None,
        },
    )


# ---------------------------------------------------------------------------
# /rules (new DB model: PK rule_kind, SK rule_id)
# ---------------------------------------------------------------------------


def _handle_list_rules(qs: dict[str, str]) -> dict:
    """
    GET /rules

    Efficient listing is by rule_kind partition:
      ?rule_kind=signal|correlation|list&order=asc|desc&page_size=50&next_token=...

    If rule_kind is omitted, every partition in _DEFAULT_RULE_LISTING_KINDS
    is queried directly (never a Scan) and merged -- see
    _list_rules_all_partitions. This excludes "list" by default; pass
    ?rule_kind=list explicitly to see those.
    """
    rule_kind = qs.get("rule_kind")
    order = _parse_order(qs)
    scan_forward = order == "asc"
    limit = _parse_limit(qs, default=20, max_limit=200)
    esk = _decode_next_token(qs.get("next_token"))

    if rule_kind:
        rk = str(rule_kind).lower()
        if rk not in ALLOWED_RULE_KINDS:
            raise ValueError(f"rule_kind must be one of {sorted(ALLOWED_RULE_KINDS)}")

        kwargs: dict[str, Any] = {
            "KeyConditionExpression": Key("rule_kind").eq(rk),
            "ScanIndexForward": scan_forward,  # asc/desc by rule_id (sort key)
            "Limit": limit,
        }
        if esk:
            kwargs["ExclusiveStartKey"] = esk

        resp = detection_rules_table.query(**kwargs)
        lek = resp.get("LastEvaluatedKey")
        return _response(
            200,
            {
                "query": {"rule_kind": rk},
                "order": order,
                "page_size": limit,
                "items": [unpack_rule_body(item) for item in resp.get("Items", [])],
                "next_token": _encode_next_token(lek),
                "has_next": lek is not None,
                "notes": "Ordered by rule_id (sort key). If you want time-ordering, add a timestamp GSI.",
            },
        )

    return _list_rules_all_partitions(order=order, scan_forward=scan_forward, limit=limit, cursor=esk)


def _list_rules_all_partitions(
    *, order: str, scan_forward: bool, limit: int, cursor: dict[str, Any] | None
) -> dict:
    """
    GET /rules with no rule_kind filter.

    There are only as many partitions as _DEFAULT_RULE_LISTING_KINDS, so
    query each directly instead of scanning the whole table. Paginates via
    a compound cursor -- {rule_kind: ExclusiveStartKey_or_None} -- rather
    than a single ExclusiveStartKey: None means that partition was already
    exhausted on a previous page and is skipped; a missing key means start
    that partition from the beginning.

    Each queried partition is capped at `limit` independently, so the
    merged response can return up to len(_DEFAULT_RULE_LISTING_KINDS) *
    limit items -- not truncated to a single global page_size. Getting a
    strict global cap exactly right across independently-paged partitions
    needs a synthetic ExclusiveStartKey built from the last included item,
    not just DynamoDB's own LastEvaluatedKey -- real extra complexity not
    justified for a table that's realistically a few hundred rows at most,
    authored by hand rather than generated by traffic.
    """
    incoming_cursor = cursor or {}
    partitions = sorted(_DEFAULT_RULE_LISTING_KINDS)

    merged_items: list[Any] = []
    outgoing_cursor: dict[str, Any] = {}

    for rk in partitions:
        if rk in incoming_cursor and incoming_cursor[rk] is None:
            # Already exhausted on a previous page -- don't requery it.
            outgoing_cursor[rk] = None
            continue

        kwargs: dict[str, Any] = {
            "KeyConditionExpression": Key("rule_kind").eq(rk),
            "ScanIndexForward": scan_forward,
            "Limit": limit,
        }
        partition_esk = incoming_cursor.get(rk)
        if partition_esk:
            kwargs["ExclusiveStartKey"] = partition_esk

        resp = detection_rules_table.query(**kwargs)
        merged_items.extend(unpack_rule_body(item) for item in resp.get("Items", []))
        outgoing_cursor[rk] = resp.get("LastEvaluatedKey")

    has_next = any(v is not None for v in outgoing_cursor.values())

    return _response(
        200,
        {
            "query": {"queried_partitions": partitions},
            "order": order,
            "page_size": limit,
            "items": merged_items,
            "next_token": _encode_next_token(outgoing_cursor) if has_next else None,
            "has_next": has_next,
            "notes": (
                f"No rule_kind provided: queried every partition ({', '.join(partitions)}) "
                "directly instead of scanning. Each partition is capped at page_size "
                "independently, so this can return up to "
                f"{len(partitions)} x page_size items, not a single global page_size cap."
            ),
        },
    )


def _handle_get_rule(rule_id: str, qs: dict[str, str]) -> dict:
    """
    GET /rules/{rule_id}

    Requires rule_kind (because PK is rule_kind):
      /rules/{rule_id}?rule_kind=signal
    """
    rule_kind = qs.get("rule_kind")
    if not rule_kind:
        raise ValueError("rule_kind query parameter is required for GET /rules/{rule_id}")
    rk = str(rule_kind).lower()
    if rk not in ALLOWED_RULE_KINDS:
        raise ValueError(f"rule_kind must be one of {sorted(ALLOWED_RULE_KINDS)}")

    resp = detection_rules_table.get_item(Key={"rule_kind": rk, "rule_id": rule_id})
    item = resp.get("Item")
    if not item:
        return _response(404, {"message": "Rule not found", "rule_kind": rk, "rule_id": rule_id})
    return _response(200, unpack_rule_body(item))


def _handle_create_rule(body: dict) -> dict:
    """
    POST /rules

    Creates a new rule item with key (rule_kind, rule_id).
    If rule_id omitted, generates UUID.

    Uses a conditional put to prevent overwriting.
    """
    normalized = _normalize_rule_payload(body, force_rule_id=None)

    try:
        detection_rules_table.put_item(
            Item=normalized,
            ConditionExpression="attribute_not_exists(rule_kind) AND attribute_not_exists(rule_id)",
        )
    except Exception as e:
        if "ConditionalCheckFailed" in repr(e):
            return _response(
                409,
                {
                    "message": "Rule already exists (rule_kind + rule_id)",
                    "key": {"rule_kind": normalized["rule_kind"], "rule_id": normalized["rule_id"]},
                },
            )
        raise

    return _response(201, normalized)


def _handle_update_rule(rule_id: str, body: dict) -> dict:
    """
    PUT /rules/{rule_id}?rule_kind=signal|correlation

    Overwrites the existing item (upsert), preserving the key.
    If you want versioning, do it at the application level (or change schema).
    """
    # must keep key stable
    normalized = _normalize_rule_payload(body, force_rule_id=rule_id)

    detection_rules_table.put_item(Item=normalized)
    return _response(200, normalized)


def _handle_delete_rule(rule_id: str, qs: dict[str, str]) -> dict:
    """
    DELETE /rules/{rule_id}?rule_kind=signal|correlation
    """
    rule_kind = qs.get("rule_kind")
    if not rule_kind:
        raise ValueError("rule_kind query parameter is required for DELETE /rules/{rule_id}")
    rk = str(rule_kind).lower()
    if rk not in ALLOWED_RULE_KINDS:
        raise ValueError(f"rule_kind must be one of {sorted(ALLOWED_RULE_KINDS)}")

    # fetch for response
    resp = detection_rules_table.get_item(Key={"rule_kind": rk, "rule_id": rule_id})
    item = resp.get("Item")
    if not item:
        return _response(404, {"message": "Rule not found", "rule_kind": rk, "rule_id": rule_id})

    detection_rules_table.delete_item(Key={"rule_kind": rk, "rule_id": rule_id})
    return _response(200, {"message": "Rule deleted", "rule": unpack_rule_body(item)})


def _normalize_rule_payload(payload: dict, *, force_rule_id: str | None) -> dict:
    """
    Normalizes to your current OpenCDR rule table key shape:
      PK: rule_kind
      SK: rule_id

    Keeps your earlier “conditions” style compatible with your engine,
    but does NOT assume a timestamp sort key for versioning.
    """
    if not isinstance(payload, dict):
        raise ValueError("Rule payload must be a JSON object")

    data = dict(payload)

    # rule_kind (required)
    rk = str(data.get("rule_kind") or "").lower()
    if rk not in ALLOWED_RULE_KINDS:
        raise ValueError(f"rule_kind is required and must be one of {sorted(ALLOWED_RULE_KINDS)}")
    data["rule_kind"] = rk

    # rule_id
    if force_rule_id:
        data["rule_id"] = force_rule_id
    else:
        data["rule_id"] = str(data.get("rule_id") or uuid.uuid4())

    # optional metadata
    data.setdefault("created_by", "api")
    data["updated_by"] = str(data.get("updated_by") or "api")

    # timestamp is useful for audit (even if not key)
    data["timestamp"] = datetime.now(UTC).isoformat()

    # rule_kind="list" is a different shape entirely -- a static value list
    # referenced by other rules' in_list/not_in_list conditions (list_id ==
    # this rule's rule_id), not a detection rule with conditions/severity/
    # enabled semantics. Previously only loadable via load_rules.sh,
    # bypassing this validation entirely (INFORME-AUTOR-ES.md §3.1).
    if rk == "list":
        values = data.get("values")
        if not isinstance(values, list) or not values:
            raise ValueError("values must be a non-empty list for rule_kind=list")
        return {
            "rule_kind": "list",
            "rule_id": data["rule_id"],
            "created_by": data["created_by"],
            "updated_by": data["updated_by"],
            "timestamp": data["timestamp"],
            "values": [str(v) for v in values],
        }

    # enabled / notify defaults
    if "enabled" not in data:
        data["enabled"] = True
    else:
        data["enabled"] = bool(data["enabled"])

    if "notify" not in data:
        data["notify"] = True
    elif not isinstance(data["notify"], bool):
        raise ValueError("notify must be boolean")

    # severity for signal rules (recommended)
    if "severity" in data and data["severity"] is not None:
        sev = str(data["severity"]).upper()
        if sev not in ALLOWED_SEVERITIES:
            raise ValueError(f"severity must be one of {sorted(ALLOWED_SEVERITIES)}")
        data["severity"] = sev

    # response_module -- empty/absent is valid (visibility-only rule); a
    # non-empty value must be a real, registered handler. Previously
    # unvalidated: a typo was silently accepted here and only surfaced much
    # later as IR_UNKNOWN_RESPONSE_MODULE in responder's logs, if anyone
    # happened to notice -- exactly the kind of setup mistake this exists
    # to catch immediately instead.
    response_module = data.get("response_module")
    if response_module:
        if response_module not in ALLOWED_RESPONSE_MODULES:
            raise ValueError(f"response_module must be one of {sorted(ALLOWED_RESPONSE_MODULES)} or empty")

    # conditions: accept either your newer list-of-conditions (field/op/value) or older formats
    conditions = data.get("conditions")
    if conditions is None:
        conditions = []
    if not isinstance(conditions, list):
        raise ValueError("conditions must be a list")

    norm_conditions = []
    for i, c in enumerate(conditions):
        if not isinstance(c, dict):
            raise ValueError(f"conditions[{i}] must be an object")

        # Accept canonical OpenCDR condition schema from your examples:
        #   { "field": "...", "op": "...", "value": ... }
        field = c.get("field")
        op = c.get("op")
        value = c.get("value")

        if not isinstance(field, str) or not field.strip():
            raise ValueError(f"conditions[{i}].field must be a non-empty string")
        if not isinstance(op, str) or op not in ALLOWED_CONDITION_OPS:
            raise ValueError(f"conditions[{i}].op must be one of {sorted(ALLOWED_CONDITION_OPS)}")

        # value can be str/bool/number/list depending on op
        list_id = c.get("list_id")
        if op in {"in", "not_in"}:
            if not isinstance(value, list) or not value:
                raise ValueError(f"conditions[{i}].value must be a non-empty list for op={op}")
        elif op in _LIST_CONDITION_OPS:
            # References a rule_kind="list" rule by id rather than an
            # inline value -- detection_engine.evaluate_condition looks it
            # up as lists[list_id], not conditions[i].value.
            if not isinstance(list_id, str) or not list_id.strip():
                raise ValueError(f"conditions[{i}].list_id is required for op={op}")
        elif op in _NO_VALUE_CONDITION_OPS:
            # allow value omitted or any
            pass
        else:
            if value is None:
                raise ValueError(f"conditions[{i}].value is required for op={op}")

        if op in _REGEX_CONDITION_OPS:
            try:
                re.compile(value)
            except (re.error, TypeError) as exc:
                raise ValueError(f"conditions[{i}].value is not a valid regex: {exc}") from exc

        norm_condition = {"field": field, "op": op, "value": value}
        if op in _LIST_CONDITION_OPS:
            norm_condition["list_id"] = list_id
        norm_conditions.append(norm_condition)

    data["conditions"] = norm_conditions

    # Correlation-specific sanity bounds -- catches an obviously-wrong
    # threshold/time_window_seconds at rule-creation time instead of
    # letting it reach the correlation engine unchecked.
    if rk == "correlation":
        if "threshold" in data and data["threshold"] is not None:
            try:
                threshold = int(data["threshold"])
            except (TypeError, ValueError) as exc:
                raise ValueError("threshold must be an integer") from exc
            if not (MIN_THRESHOLD <= threshold <= MAX_THRESHOLD):
                raise ValueError(f"threshold must be between {MIN_THRESHOLD} and {MAX_THRESHOLD}")
            data["threshold"] = threshold

        if "time_window_seconds" in data and data["time_window_seconds"] is not None:
            try:
                time_window_seconds = int(data["time_window_seconds"])
            except (TypeError, ValueError) as exc:
                raise ValueError("time_window_seconds must be an integer") from exc
            if not (MIN_TIME_WINDOW_SECONDS <= time_window_seconds <= MAX_TIME_WINDOW_SECONDS):
                raise ValueError(
                    f"time_window_seconds must be between {MIN_TIME_WINDOW_SECONDS} and {MAX_TIME_WINDOW_SECONDS}"
                )
            data["time_window_seconds"] = time_window_seconds

    # Keep payload clean-ish (optional)
    # data.pop("targets", None)
    # data.pop("ips", None)

    return data


# ---------------------------------------------------------------------------
# /settings
# ---------------------------------------------------------------------------

_REDACTED = "***REDACTED***"


def _mask_secret(value: Any) -> Any:
    """Redact a secret value, preserving enough shape to show it's set."""
    if not isinstance(value, str) or not value:
        return value
    return _REDACTED


def _redact_settings(item: dict) -> dict:
    """
    Return a copy of a settings item with plaintext integration secrets
    (Slack/Discord webhook URLs, Jira API tokens, custom webhook headers)
    masked. Never mutates the input or the DynamoDB item.
    """
    redacted = dict(item)
    channels = redacted.get("channels")
    if not isinstance(channels, dict):
        return redacted

    new_channels = {name: dict(cfg) if isinstance(cfg, dict) else cfg for name, cfg in channels.items()}

    for channel_name, field_name in SECRET_CHANNEL_FIELDS:
        cfg = new_channels.get(channel_name)
        if isinstance(cfg, dict) and field_name in cfg:
            cfg[field_name] = _mask_secret(cfg[field_name])

    webhook_cfg = new_channels.get("webhook")
    if isinstance(webhook_cfg, dict) and isinstance(webhook_cfg.get("targets"), list):
        new_targets = []
        for target in webhook_cfg["targets"]:
            if not isinstance(target, dict):
                new_targets.append(target)
                continue
            new_target = dict(target)
            headers = new_target.get("headers")
            if isinstance(headers, dict):
                new_target["headers"] = {k: _mask_secret(v) for k, v in headers.items()}
            new_targets.append(new_target)
        webhook_cfg = dict(webhook_cfg)
        webhook_cfg["targets"] = new_targets
        new_channels["webhook"] = webhook_cfg

    redacted["channels"] = new_channels
    return redacted


def _handle_get_settings(setting_id: str) -> dict:
    resp = settings_table.get_item(Key={"setting_id": setting_id})
    item = resp.get("Item")
    if not item:
        return _response(404, {"message": f"Settings {setting_id} not found"})
    return _response(200, _redact_settings(item))


def _handle_create_settings(setting_id: str, body: dict) -> dict:
    normalized = _normalize_settings_payload(body, setting_id=setting_id)

    try:
        settings_table.put_item(
            Item=normalized,
            ConditionExpression="attribute_not_exists(setting_id)",
        )
    except Exception as e:
        if "ConditionalCheckFailed" in repr(e):
            return _response(409, {"message": f"Settings {setting_id} already exists"})
        raise

    return _response(201, normalized)


def _handle_upsert_settings(setting_id: str, body: dict) -> dict:
    normalized = _normalize_settings_payload(body, setting_id=setting_id)
    settings_table.put_item(Item=normalized)
    return _response(200, normalized)


def _handle_delete_settings(setting_id: str) -> dict:
    resp = settings_table.get_item(Key={"setting_id": setting_id})
    item = resp.get("Item")
    if not item:
        return _response(404, {"message": f"Settings {setting_id} not found"})
    settings_table.delete_item(Key={"setting_id": setting_id})
    _delete_secret_refs(item)
    return _response(200, {"message": "Settings deleted", "settings": item})


def _resolve_redacted_secrets(data: dict, *, setting_id: str) -> None:
    """
    GET always masks secrets to _REDACTED (_mask_secret above), so any
    client that fetches settings, merges in a change, and writes the
    whole document back (scripts/opencdr.py's settings set, and any
    well-behaved UI) will resubmit that sentinel string for every
    untouched secret field -- without this, _externalize_secrets would
    treat "***REDACTED***" as a brand new real secret and write it to
    SSM verbatim, silently corrupting a previously-configured
    integration on any write that so much as touches a sibling field.
    Treat _REDACTED as "leave unchanged": replace it with whatever's
    actually stored today (almost always an existing ssm: ref, which
    _externalize_secrets then correctly leaves alone) before
    externalizing anything.
    """
    locations = iter_secret_locations(data.get("channels"))
    if not any(container.get(key) == _REDACTED for container, key, _ in locations):
        return  # avoid a GetItem when nothing needs resolving

    existing_item = settings_table.get_item(Key={"setting_id": setting_id}).get("Item") or {}
    existing_values = {
        path_parts: container.get(key)
        for container, key, path_parts in iter_secret_locations(existing_item.get("channels"))
    }
    for container, key, path_parts in locations:
        if container.get(key) == _REDACTED:
            container[key] = existing_values.get(path_parts, "")


def _externalize_secrets(data: dict, *, setting_id: str) -> None:
    """
    Replaces real secret values under data["channels"] with `ssm:`
    references, writing the real values to SSM Parameter Store
    (SecureString) as a side effect. A value that's empty or already an
    `ssm:` reference (unchanged from a prior read/write) is left alone.
    """
    for container, key, path_parts in iter_secret_locations(data.get("channels")):
        value = container.get(key)
        if isinstance(value, str) and value and not is_ssm_ref(value):
            param_name = ssm_param_name(setting_id, *path_parts)
            ssm.put_parameter(Name=param_name, Value=value, Type="SecureString", Overwrite=True)
            container[key] = ssm_ref(param_name)


def _delete_secret_refs(item: dict) -> None:
    """Best-effort cleanup of SSM parameters referenced by a deleted
    settings item -- the DynamoDB row is already gone by the time this
    runs, so a failure here is logged-and-swallowed, not raised."""
    names = [
        ssm_ref_param_name(container[key])
        for container, key, _ in iter_secret_locations(item.get("channels"))
        if is_ssm_ref(container.get(key))
    ]
    if not names:
        return
    try:
        for i in range(0, len(names), 10):
            ssm.delete_parameters(Names=names[i : i + 10])
    except Exception:
        pass


def _normalize_settings_payload(payload: dict, *, setting_id: str) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("Settings payload must be a JSON object")

    data = dict(payload)
    data["setting_id"] = setting_id
    data["timestamp"] = datetime.now(UTC).isoformat()

    if "notifications_enabled" not in data:
        data["notifications_enabled"] = True
    else:
        data["notifications_enabled"] = bool(data["notifications_enabled"])

    channels = data.get("channels") or {}
    if not isinstance(channels, dict):
        raise ValueError("channels must be an object")

    # optional shape checks
    for name in ("discord", "slack", "email", "webhook"):
        if name not in channels:
            continue
        ch = channels[name]
        if not isinstance(ch, dict):
            raise ValueError(f"channels.{name} must be an object")
        if "enabled" in ch and not isinstance(ch["enabled"], bool):
            raise ValueError(f"channels.{name}.enabled must be boolean")

    data["channels"] = channels
    _resolve_redacted_secrets(data, setting_id=setting_id)
    _externalize_secrets(data, setting_id=setting_id)
    return data


# ---------------------------------------------------------------------------
# /ir-roles
# ---------------------------------------------------------------------------
#
# Maps an AWS account to the IAM role the responder assumes when acting on a
# detection from that account (src/handlers/responder.py _resolve_role_arn).
# An account with no row here falls back to OPENCDR_IR_ROLE_ARN -- this
# table is how additional (non-home) accounts get onboarded for multi-
# account incident response. NOTE: a write here directly controls which AWS
# role the responder may assume -- treat it as at least as sensitive as the
# settings endpoint's integration secrets.


def _handle_list_ir_roles(qs: dict[str, str]) -> dict:
    """
    GET /ir-roles

    This table is admin-sized (one row per onboarded AWS account), so an
    unfiltered Scan is fine here -- unlike /rules or /signals, there's no
    natural partition-key filter to query on instead.
    """
    limit = _parse_limit(qs, default=20, max_limit=200)
    esk = _decode_next_token(qs.get("next_token"))

    scan_kwargs: dict[str, Any] = {"Limit": limit}
    if esk:
        scan_kwargs["ExclusiveStartKey"] = esk

    resp = ir_account_roles_table.scan(**scan_kwargs)
    lek = resp.get("LastEvaluatedKey")
    return _response(
        200,
        {
            "page_size": limit,
            "items": resp.get("Items", []),
            "next_token": _encode_next_token(lek),
            "has_next": lek is not None,
        },
    )


def _handle_get_ir_role(account_id: str) -> dict:
    resp = ir_account_roles_table.get_item(Key={"aws_account_id": account_id})
    item = resp.get("Item")
    if not item:
        return _response(404, {"message": f"No IR role mapping for account {account_id}"})
    return _response(200, item)


def _handle_create_ir_role(body: dict) -> dict:
    normalized = _normalize_ir_role_payload(body, force_account_id=None)

    try:
        ir_account_roles_table.put_item(
            Item=normalized,
            ConditionExpression="attribute_not_exists(aws_account_id)",
        )
    except Exception as e:
        if "ConditionalCheckFailed" in repr(e):
            return _response(
                409,
                {"message": f"IR role mapping already exists for account {normalized['aws_account_id']}"},
            )
        raise

    return _response(201, normalized)


def _handle_upsert_ir_role(account_id: str, body: dict) -> dict:
    normalized = _normalize_ir_role_payload(body, force_account_id=account_id)
    ir_account_roles_table.put_item(Item=normalized)
    return _response(200, normalized)


def _handle_delete_ir_role(account_id: str) -> dict:
    resp = ir_account_roles_table.get_item(Key={"aws_account_id": account_id})
    item = resp.get("Item")
    if not item:
        return _response(404, {"message": f"No IR role mapping for account {account_id}"})
    ir_account_roles_table.delete_item(Key={"aws_account_id": account_id})
    return _response(200, {"message": "IR role mapping deleted", "ir_role": item})


def _normalize_ir_role_payload(payload: dict, *, force_account_id: str | None) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("IR role payload must be a JSON object")

    data = dict(payload)

    account_id = force_account_id or data.get("aws_account_id")
    if not account_id or not isinstance(account_id, str):
        raise ValueError("aws_account_id is required")
    if not account_id.isdigit() or len(account_id) != 12:
        raise ValueError("aws_account_id must be a 12-digit AWS account ID")
    data["aws_account_id"] = account_id

    role_arn = data.get("role_arn")
    if not role_arn or not isinstance(role_arn, str) or not role_arn.startswith("arn:aws:iam::"):
        raise ValueError("role_arn is required and must be an IAM role ARN (arn:aws:iam::...)")

    if "enabled" not in data:
        data["enabled"] = True
    elif not isinstance(data["enabled"], bool):
        raise ValueError("enabled must be boolean")

    data["updated_at"] = datetime.now(UTC).isoformat()
    return data


def _handle_list_ir_actions(qs: dict[str, str]) -> dict:
    """
    GET /ir-actions

    Same reasoning as _handle_list_ir_roles: admin-sized table (one row per
    executed rollback-eligible IR action, 90-day TTL -- see responder.py's
    ttl_expires_at usage), so an unfiltered Scan is fine here.
    """
    limit = _parse_limit(qs, default=20, max_limit=200)
    esk = _decode_next_token(qs.get("next_token"))

    scan_kwargs: dict[str, Any] = {"Limit": limit}
    if esk:
        scan_kwargs["ExclusiveStartKey"] = esk

    resp = ir_actions_table.scan(**scan_kwargs)
    lek = resp.get("LastEvaluatedKey")
    return _response(
        200,
        {
            "page_size": limit,
            "items": resp.get("Items", []),
            "next_token": _encode_next_token(lek),
            "has_next": lek is not None,
        },
    )


def _handle_get_ir_action(detection_id: str) -> dict:
    resp = ir_actions_table.get_item(Key={"detection_id": detection_id})
    item = resp.get("Item")
    if not item:
        return _response(404, {"message": f"No IR action recorded for detection {detection_id}"})
    return _response(200, item)


def _handle_rollback_ir_action(detection_id: str) -> dict:
    """
    POST /ir-actions/{detection_id}/rollback

    Does not call dredge directly -- enqueues onto ir-rollback-queue and
    lets rollbackHandler (src/handlers/ir_rollback.py) execute it, same
    async/decoupled shape as the original action pipeline (processor ->
    outbox -> responder), which gets the rate-limit/dry-run safety wiring
    for free by going through the same kind of consumer instead of a
    synchronous call from this Lambda.

    Sets rollback_status="pending" here, before the message is even
    consumed -- so a client polling GET /ir-actions/{id} right after this
    202 sees "pending" immediately, not "not started" for however long the
    queue takes to drain. rollbackHandler transitions pending ->
    succeeded/failed once it actually runs. See docs/incident-response.md#rollback.
    """
    resp = ir_actions_table.get_item(Key={"detection_id": detection_id})
    item = resp.get("Item")
    if not item:
        return _response(404, {"message": f"No IR action recorded for detection {detection_id}"})

    if not item.get("rollback_supported"):
        return _response(
            400,
            {"message": f"Rollback is not supported for this action (response_module={item.get('response_module')})"},
        )

    if item.get("rolled_back"):
        return _response(409, {"message": "This action has already been rolled back"})

    if item.get("rollback_status") == "pending":
        return _response(409, {"message": "A rollback for this action is already in progress"})

    if not IR_ROLLBACK_QUEUE_URL:
        return _response(500, {"message": "IR_ROLLBACK_QUEUE_URL not configured"})

    sqs.send_message(QueueUrl=IR_ROLLBACK_QUEUE_URL, MessageBody=json.dumps({"detection_id": detection_id}))

    try:
        ir_actions_table.update_item(
            Key={"detection_id": detection_id},
            UpdateExpression="SET rollback_status = :status, rollback_updated_at = :ts REMOVE rollback_error",
            ExpressionAttributeValues={":status": "pending", ":ts": datetime.now(UTC).isoformat()},
        )
    except Exception:
        # Best-effort -- the rollback is already enqueued and will run
        # regardless; a client that polls before rollbackHandler picks it
        # up just sees the pre-existing status for a bit longer.
        pass

    return _response(202, {"message": "Rollback enqueued", "detection_id": detection_id})


# ---------------------------------------------------------------------------
# Docs
# ---------------------------------------------------------------------------


def _help_payload() -> dict:
    return {
        "service": SERVICE,
        "lambda_name": LAMBDA_NAME,
        "endpoints": {
            "/status": {"method": "GET"},
            "/help": {"method": "GET"},
            "/signals": {
                "method": "GET",
                "description": "List signals using base table or GSIs with cursor pagination.",
                "query_params": {
                    "severity": "Query base table by severity (day-bucketed PK). One of CRITICAL,HIGH,MEDIUM,LOW,INFO,INFORMATIONAL.",
                    "event_id": "Query GSI gsi_signal_event_id by event_id (PK).",
                    "category": "Query GSI gsi_signal_category_id by category (PK).",
                    "date_from": "YYYY-MM-DD, UTC, inclusive. Only applies to the severity selector. Defaults to 6 days before date_to/today.",
                    "date_to": "YYYY-MM-DD, UTC, inclusive. Only applies to the severity selector. Defaults to today.",
                    "order": "asc|desc (default desc). Orders by timestamp sort key.",
                    "page_size": "1..200 (default 20).",
                    "next_token": "Opaque cursor from previous response.",
                },
                "notes": "Exactly one of severity|event_id|category is required. severity queries default to the last 7 days -- see date_from/date_to.",
            },
            "/signals/stats": {
                "method": "GET",
                "description": "Signal counts by severity for a date range -- for a dashboard widget, not a substitute for /signals' paginated item listing.",
                "query_params": {
                    "date_from": "YYYY-MM-DD, UTC, inclusive. Defaults to 6 days before date_to/today.",
                    "date_to": "YYYY-MM-DD, UTC, inclusive. Defaults to today.",
                },
                "notes": f"Defaults to the last 7 days if neither date is given, max range {MAX_DATE_RANGE_DAYS} days (same bound as /signals). Response: {{date_from, date_to, counts: {{<severity>: <count>, ...}}, total}}.",
            },
            "/logs": {
                "method": "GET",
                "description": "List logs using base table or GSIs with cursor pagination.",
                "query_params": {
                    "service": "Query base table by service (day-bucketed PK).",
                    "event_id": "Query GSI gsi_logs_event_id by event_id (PK).",
                    "event_name": "Query GSI gsi_activity_name by event_name (PK).",
                    "date_from": "YYYY-MM-DD, UTC, inclusive. Only applies to the service selector. Defaults to 6 days before date_to/today.",
                    "date_to": "YYYY-MM-DD, UTC, inclusive. Only applies to the service selector. Defaults to today.",
                    "order": "asc|desc (default desc). Orders by timestamp sort key.",
                    "page_size": "1..200 (default 20).",
                    "next_token": "Opaque cursor from previous response.",
                },
                "notes": "Exactly one of service|event_id|event_name is required. service queries default to the last 7 days -- see date_from/date_to.",
            },
            "/rules": {
                "methods": ["GET", "POST"],
                "description": "Rules live in DynamoDB keyed by (rule_kind, rule_id).",
                "query_params": {
                    "rule_kind": "Optional. One of signal|correlation. If omitted, every partition "
                    "is queried directly (never a table scan) and merged -- page_size then caps "
                    "each partition independently, so a response can hold more than page_size items.",
                    "order": "asc|desc affects rule_id ordering within a kind (sort key is rule_id).",
                    "page_size": "1..200 (default 20).",
                    "next_token": "Opaque cursor from previous response.",
                },
            },
            "/rules/{rule_id}": {
                "methods": ["GET", "PUT", "DELETE"],
                "query_params": {
                    "rule_kind": "Required (because PK is rule_kind).",
                },
            },
            "/settings": {
                "methods": ["GET", "POST"],
                "notes": "GET/POST global settings (setting_id=global).",
            },
            "/settings/{setting_id}": {"methods": ["GET", "PUT", "DELETE"]},
            "/ir-roles": {
                "methods": ["GET", "POST"],
                "notes": "Maps an AWS account to the IAM role the responder assumes for detections "
                "from that account. An account with no entry falls back to OPENCDR_IR_ROLE_ARN.",
            },
            "/ir-roles/{aws_account_id}": {"methods": ["GET", "PUT", "DELETE"]},
            "/ir-actions": {
                "methods": ["GET"],
                "notes": "One row per executed, rollback-eligible IR action (see ROLLBACK_ELIGIBLE_MODULES). "
                "rollback_supported=false means the action ran but its prior state couldn't be captured "
                "(rollback not possible for that specific occurrence, still recorded for audit).",
            },
            "/ir-actions/{detection_id}": {
                "methods": ["GET"],
                "notes": "Once a rollback has been attempted, also carries rollback_status "
                "(pending/succeeded/failed), rollback_error, and rollback_updated_at. "
                "rolled_back mirrors rollback_status == succeeded for back-compat.",
            },
            "/ir-actions/{detection_id}/rollback": {
                "methods": ["POST"],
                "notes": "Enqueues the rollback for async execution (mirrors the original action's "
                "processor -> outbox -> responder pipeline) -- returns 202, not the rollback result, "
                "and sets rollback_status=pending. 400 if rollback_supported is false; 409 only if "
                "already pending -- a previously failed rollback can be retried.",
            },
        },
        "schema_notes": [
            "Signals table is time-ordered by timestamp sort key for base queries and GSIs.",
            "Rules table is NOT time-versioned in your current schema (SK is rule_id). If you want version history, add timestamp as SK or add a timestamp/version GSI.",
        ],
    }

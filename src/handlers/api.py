# src/handlers/api.py
from __future__ import annotations

import base64
import json
import os
import re
import uuid
from datetime import UTC, datetime
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

ddb = boto3.resource("dynamodb")
ssm = boto3.client("ssm")

signals_table = ddb.Table(SIGNALS_TABLE_NAME)
alerts_table = ddb.Table(ALERTS_TABLE_NAME)
logs_table = ddb.Table(LOGS_TABLE_NAME)
detection_rules_table = ddb.Table(DETECTION_RULES_TABLE_NAME)
settings_table = ddb.Table(SETTINGS_TABLE_NAME)
ir_account_roles_table = ddb.Table(IR_ACCOUNT_ROLES_TABLE_NAME)


# ---------------------------------------------------------------------------
# Constants / Validation
# ---------------------------------------------------------------------------

SERVICE = os.getenv("SERVICE_NAME", "OPENCDR-API")

ALLOWED_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "INFORMATIONAL"}
ALLOWED_RULE_KINDS = {"signal", "correlation"}

# NOTE: adjust these to your engine’s supported ops
ALLOWED_CONDITION_OPS = {
    "equals",
    "not_equals",
    "in",
    "not_in",
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
}

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
# Entry
# ---------------------------------------------------------------------------


def lambda_handler(event, context):
    request_id = getattr(context, "aws_request_id", None)

    method = _get_http_method(event)
    path = _get_path(event)
    qs = event.get("queryStringParameters") or {}
    path_params = event.get("pathParameters") or {}

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
        #   PK: rule_kind (signal|correlation)
        #   SK: rule_id
        #
        # Your serverless.yml currently wires GET /rules only,
        # but these handlers support POST/PUT/DELETE too (add routes if you want).
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
      1) By severity (base table):
         ?severity=HIGH&order=desc&page_size=20&next_token=...

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
        kwargs: dict[str, Any] = {
            "KeyConditionExpression": Key("severity").eq(sev),
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
                "query": {"severity": sev},
                "order": order,
                "page_size": limit,
                "items": resp.get("Items", []),
                "next_token": _encode_next_token(lek),
                "has_next": lek is not None,
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


# ---------------------------------------------------------------------------
# /logs
# ---------------------------------------------------------------------------


def _handle_list_logs(qs: dict[str, str]) -> dict:
    """
    GET /logs

    Supported query shapes (efficient queries with correct pagination):
      1) By service (base table):
         ?service=OPENCDR-API&order=desc&page_size=20&next_token=...

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
        kwargs: dict[str, Any] = {
            "KeyConditionExpression": Key("service").eq(service_name),
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
                "query": {"service": service_name},
                "order": order,
                "page_size": limit,
                "items": resp.get("Items", []),
                "next_token": _encode_next_token(lek),
                "has_next": lek is not None,
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
      ?rule_kind=signal|correlation&order=asc|desc&page_size=50&next_token=...

    If rule_kind is omitted, every partition in ALLOWED_RULE_KINDS is
    queried directly (never a Scan) and merged -- see
    _list_rules_all_partitions.
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
                "items": resp.get("Items", []),
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

    There are only as many partitions as ALLOWED_RULE_KINDS, so query each
    directly instead of scanning the whole table. Paginates via a compound
    cursor -- {rule_kind: ExclusiveStartKey_or_None} -- rather than a
    single ExclusiveStartKey: None means that partition was already
    exhausted on a previous page and is skipped; a missing key means start
    that partition from the beginning.

    Each queried partition is capped at `limit` independently, so the
    merged response can return up to len(ALLOWED_RULE_KINDS) * limit items
    -- not truncated to a single global page_size. Getting a strict global
    cap exactly right across independently-paged partitions needs a
    synthetic ExclusiveStartKey built from the last included item, not
    just DynamoDB's own LastEvaluatedKey -- real extra complexity not
    justified for a table that's realistically a few hundred rows at most,
    authored by hand rather than generated by traffic.
    """
    incoming_cursor = cursor or {}
    partitions = sorted(ALLOWED_RULE_KINDS)

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
        merged_items.extend(resp.get("Items", []))
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
    return _response(200, item)


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
    return _response(200, {"message": "Rule deleted", "rule": item})


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
        if op in {"in", "not_in"}:
            if not isinstance(value, list) or not value:
                raise ValueError(f"conditions[{i}].value must be a non-empty list for op={op}")
        elif op in {"exists", "not_exists"}:
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

        norm_conditions.append({"field": field, "op": op, "value": value})

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
                    "severity": "Query base table by severity (PK). One of CRITICAL,HIGH,MEDIUM,LOW,INFO,INFORMATIONAL.",
                    "event_id": "Query GSI gsi_signal_event_id by event_id (PK).",
                    "category": "Query GSI gsi_signal_category_id by category (PK).",
                    "order": "asc|desc (default desc). Orders by timestamp sort key.",
                    "page_size": "1..200 (default 20).",
                    "next_token": "Opaque cursor from previous response (LastEvaluatedKey).",
                },
                "notes": "Exactly one of severity|event_id|category is required.",
            },
            "/logs": {
                "method": "GET",
                "description": "List logs using base table or GSIs with cursor pagination.",
                "query_params": {
                    "service": "Query base table by service (PK).",
                    "event_id": "Query GSI gsi_logs_event_id by event_id (PK).",
                    "event_name": "Query GSI gsi_activity_name by event_name (PK).",
                    "order": "asc|desc (default desc). Orders by timestamp sort key.",
                    "page_size": "1..200 (default 20).",
                    "next_token": "Opaque cursor from previous response (LastEvaluatedKey).",
                },
                "notes": "Exactly one of service|event_id|event_name is required.",
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
        },
        "schema_notes": [
            "Signals table is time-ordered by timestamp sort key for base queries and GSIs.",
            "Rules table is NOT time-versioned in your current schema (SK is rule_id). If you want version history, add timestamp as SK or add a timestamp/version GSI.",
        ],
    }

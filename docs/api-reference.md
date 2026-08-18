# API Reference

*The REST API's authentication model and endpoint surface — for exact request/response schemas, [`openapi.yml`](../openapi.yml) is the authoritative machine-readable spec, though see the note below on where it's currently out of sync with the actual code.*

## Authentication

Every endpoint requires an `x-api-key` header. Keys are created automatically by API Gateway on deploy and available in the deploy output, or in SSM — along with the base URL itself, handy for pointing Postman, `curl`, `scripts/opencdr.py`, or the MCP server at a deployed stage directly (see [Deployment](deployment.md)).

### API key scopes

Each key grants one or more of five scopes: **`read`** (every `GET` route), **`rules`** (mutating `/rules`), **`settings`** (mutating `/settings`), **`ir_roles`** (mutating `/ir-roles`), **`ir_actions`** (`POST /ir-actions/{id}/rollback`). `/status` and `/help` need no scope. `ir_roles`/`ir_actions` use an underscore, not a dash, deliberately — see the note below. A key's scopes come from its **name** in `serverless.yml`'s `apiGateway.apiKeys` block, dash-suffixed after the base `${self:service}-${self:provider.stage}-api-key`:

| Key name | Scopes |
|---|---|
| `opencdr-<stage>-api-key` | all five (bare name, back-compat with the key that predates scoping) |
| `opencdr-<stage>-api-key-read-rules-settings-ir_roles-ir_actions` | all five (named explicitly) — used by the MCP server below |

To add another scoped key, add its dash-suffixed name to `serverless.yml`'s `apiKeys` list (e.g. `...-api-key-rules` for a rules-only key) — no other code changes needed. Enforcement is application-level, in `src/handlers/api.py`'s `_required_scope_for`/`_get_key_scopes`: it resolves the caller's key name from `requestContext.identity.apiKeyId` via `apigateway:GetApiKey` (TTL-cached), not a custom Lambda authorizer. Both keys are stored in SSM at deploy time — see [Deployment](deployment.md).

**Scope names are dash-joined in key names, so a scope name can never itself contain a dash** — `ir_roles`/`ir_actions` use an underscore for exactly this reason (`_scopes_from_key_name` splits the suffix on `-`; a name like `ir-roles` would split into two unrecognized tokens and silently resolve to zero scopes). Keep any future scope name dash-free too.

A key presenting a scope it doesn't have gets a `403` with `{"message": "API key missing required scope: <scope>"}`, distinct from API Gateway's own `403` for an invalid/missing key entirely (that never reaches the Lambda). This closes a previously deliberate, documented gap — see [Security](security.md) for the history.

### MCP server (default management plane)

`mcp_server/server.py` exposes the full platform surface as MCP tools — rules (detection + correlation), lists, signals/logs (read), settings, and IR-role assignments — for driving OpenCDR from an MCP-aware client instead of `scripts/opencdr.py`:

| Group | Tools |
|---|---|
| Status | `opencdr_status` |
| Rules | `opencdr_rules_list/get/upsert/delete` |
| Lists | `opencdr_lists_list/show/create/add/remove/delete` |
| Signals / Logs | `opencdr_signals_list`, `opencdr_signals_stats`, `opencdr_logs_list` |
| Settings | `opencdr_settings_get/set/delete` |
| IR roles | `opencdr_ir_roles_list/get/upsert/delete` |
| IR actions | `opencdr_ir_actions_list/get/rollback` |

`rules`/`ir_roles` upserts are single PUT operations (create-or-update, same as `scripts/opencdr.py rules load`'s approach) rather than separate create/update tools — simpler for a caller that doesn't need to distinguish "new" from "edit." Configure it with the **all-scopes MCP key** above, not the original bare key — same privilege level, but a separate, independently revocable key, so leaking one doesn't force rotating the other.

```bash
pip install -r mcp_server/requirements.txt
claude mcp add opencdr \
  --env OPENCDR_API_URL=<from SSM /opencdr-<stage>/api-url> \
  --env OPENCDR_API_KEY=<from SSM /opencdr-<stage>/api-key-mcp> \
  -- python /path/to/mcp_server/server.py
```

## A note on `openapi.yml`

`openapi.yml` documents `/status`, `/help`, `/swagger.json`, `/docs`, `/signals`, `/logs`, `/rules`, and `/settings`. Two things are worth knowing before trusting it as complete:

- It **omits `/ir-roles`, `/ir-actions`, and `/signals/stats` entirely** — all three are fully implemented in `src/handlers/api.py` and wired in `serverless.yml`, added after `openapi.yml` was last regenerated.
- `/swagger.json` and `/docs` are documented but **not implemented** — `api.py`'s routing table has no handler for either path; a request to them returns the same 404 as any unrouted path.

Use it for the endpoints it does cover (query parameters and enums for `/signals`, `/logs`, `/rules`, `/settings` are accurate), but don't rely on it for `/ir-roles`, `/ir-actions`, `/signals/stats`, or assume `/docs`/`/swagger.json` work — this page and direct reading of `src/handlers/api.py` are more current.

## Endpoints

### Health

| Method | Path | Notes |
|---|---|---|
| `GET` | `/status` | Health check — service name, Lambda name, current time, request ID |
| `GET` | `/help` | Endpoint reference, generated from the handler itself |

### Signals

| Method | Path | Notes |
|---|---|---|
| `GET` | `/signals` | Query params: exactly **one** of `severity`, `event_id`, `category` is required (querying the base table or one of two GSIs, respectively) — plus `order` (`asc`/`desc`), `page_size` (1–200), `next_token` for cursor pagination |

The base table's HASH key is a day-bucketed `severity_bucket` (`"HIGH#2026-08-12"`, see [Architecture](architecture.md#dynamodb-tables)), so the `severity` selector additionally takes `date_from`/`date_to` (`YYYY-MM-DD`, UTC, inclusive, defaulting to the last 7 days, capped at 31 days wide). `event_id`/`category` are unaffected — they query GSIs, not this key.

```bash
curl "$OPENCDR_API_URL/signals?severity=HIGH&date_from=2026-08-01&date_to=2026-08-12&page_size=20" \
  -H "x-api-key: $OPENCDR_API_KEY"
```

#### Signal counts (`/signals/stats`)

| Method | Path | Notes |
|---|---|---|
| `GET` | `/signals/stats` | Counts by severity for a date range — for a dashboard widget, not a substitute for `/signals`' paginated item listing |

Same `date_from`/`date_to` defaults and 31-day cap as the `severity` selector above, since it queries the same day-bucketed key — one `Select=COUNT` query per (severity, day) in range, summed server-side. Response shape: `{"date_from", "date_to", "counts": {"CRITICAL": N, "HIGH": N, ...all 6 severities, present even at 0}, "total"}`.

```bash
curl "$OPENCDR_API_URL/signals/stats?date_from=2026-08-01&date_to=2026-08-12" \
  -H "x-api-key: $OPENCDR_API_KEY"
```

### Logs

| Method | Path | Notes |
|---|---|---|
| `GET` | `/logs` | Same shape as `/signals`: exactly one of `service`, `event_id`, `event_name`, plus `order`/`page_size`/`next_token` |

The `service` selector has the identical day-bucketing/`date_from`/`date_to` behavior as `/signals`' `severity` selector above — see [Architecture](architecture.md#dynamodb-tables).

```bash
curl "$OPENCDR_API_URL/logs?service=OPENCDR-PROCESSOR&date_from=2026-08-01&date_to=2026-08-12" \
  -H "x-api-key: $OPENCDR_API_KEY"
```

### Rules

| Method | Path | Notes |
|---|---|---|
| `GET` | `/rules` | Optional `rule_kind` filter (`signal`/`correlation`/`list`); omitted, queries the `signal`+`correlation` partitions and merges (`list` rules are excluded from the unfiltered default — pass `?rule_kind=list` explicitly) |
| `POST` | `/rules` | Create a rule |
| `GET` | `/rules/{rule_id}` | `rule_kind` query param required to know which partition to read |
| `PUT` | `/rules/{rule_id}` | Update a rule |
| `DELETE` | `/rules/{rule_id}` | Delete a rule |

```bash
curl -X POST "$OPENCDR_API_URL/rules" -H "x-api-key: $OPENCDR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
        "rule_id": "030_custom_rule",
        "rule_kind": "signal",
        "enabled": true,
        "severity": "MEDIUM",
        "conditions": [{ "field": "activity_name", "op": "equals", "value": "PutBucketPolicy" }]
      }'
```

See [Detection Rules](detection-rules.md) for the full rule schema.

### Settings

| Method | Path | Notes |
|---|---|---|
| `GET` | `/settings` | Global notification settings (`setting_id=global`); secrets returned as `***REDACTED***` |
| `POST` | `/settings` | Create the global settings document |
| `GET` / `PUT` / `DELETE` | `/settings/{setting_id}` | Same operations against a specific `setting_id` |

Any value under a secret-shaped field (Slack/Discord webhook URL, Jira API token, custom webhook target headers) is transparently externalized to SSM Parameter Store on write — see [Security](security.md#secrets-management) — and masked on every subsequent read, including your own. There's no way to read a secret back through this API once it's set; treat your own write payload as the only copy you'll have.

Full channel configuration reference and routing rules are in [Notifications](notifications.md).

### IR roles

| Method | Path | Notes |
|---|---|---|
| `GET` | `/ir-roles` | List AWS account → IR role mappings |
| `POST` | `/ir-roles` | Add a mapping |
| `GET` / `PUT` / `DELETE` | `/ir-roles/{aws_account_id}` | Read, update, or remove a specific account's mapping |

```bash
curl -X POST "$OPENCDR_API_URL/ir-roles" -H "x-api-key: $OPENCDR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"aws_account_id": "123456789012", "role_arn": "arn:aws:iam::123456789012:role/opencdr-dev-ir-role"}'
```

A write here directly controls which IAM role `responder` assumes in which AWS account — full detail, including the per-account `enabled` kill switch, is in [Incident Response](incident-response.md) and [`docs/ir-role.md`](ir-role.md).

### IR actions

| Method | Path | Notes |
|---|---|---|
| `GET` | `/ir-actions` | List executed, rollback-eligible IR actions (one row per detection responder acted on for one of the modules in `ROLLBACK_ELIGIBLE_MODULES`) |
| `GET` | `/ir-actions/{detection_id}` | Read a specific action, including `rollback_supported` and, once a rollback has been attempted, `rollback_status` (`pending`/`succeeded`/`failed`), `rollback_error`, `rollback_updated_at`. `rolled_back` mirrors `rollback_status == "succeeded"` for back-compat — see [Incident Response](incident-response.md#rollback) for the full state machine |
| `POST` | `/ir-actions/{detection_id}/rollback` | Enqueue the rollback for async execution — returns `202` immediately, not the rollback's result, and sets `rollback_status: "pending"`. `400` if `rollback_supported` is false; `409` only if a rollback is already `pending` — a previously `failed` rollback can be retried |

```bash
curl -X POST "$OPENCDR_API_URL/ir-actions/<detection_id>/rollback" -H "x-api-key: $OPENCDR_API_KEY"
```

A `POST .../rollback` only enqueues onto `ir-rollback-queue` — the actual undo runs in `rollbackHandler` (`src/handlers/ir_rollback.py`), the same async, rate-limited, dry-run-respecting shape as the original action pipeline (`processor` → outbox → `responder`), rather than a synchronous call from this Lambda. Full detail on which modules are rollback-eligible and why: [Incident Response](incident-response.md#rollback).

## Pagination

Every list endpoint (`/signals`, `/logs`, `/rules`) shares the same cursor convention: `page_size` (1–200, default 20), `order` (`asc`/`desc`, default `desc`), and an opaque `next_token` returned in the response — pass it back as a query param to get the next page. `/rules` with no `rule_kind` filter queries both partitions independently and merges, so a single response can return up to `page_size` × 2 items — see the `notes` field in that response for the exact accounting. `/signals`' `severity` and `/logs`' `service` selectors merge-paginate across day-buckets instead (see above) — each page drains one day before moving to the next to preserve chronological order, so unlike `/rules` a single response never exceeds `page_size` items.

## Related pages

- [Detection Rules](detection-rules.md) — `/rules` body schema in full
- [Notifications](notifications.md) — `/settings` channel configuration in full
- [Incident Response](incident-response.md) — `/ir-roles` and how resolution actually works
- [Security](security.md) — the API key's real scope and secrets handling
- [`openapi.yml`](../openapi.yml) — machine-readable spec (partial, see note above)

# API Reference

*The REST API's authentication model and endpoint surface — for exact request/response schemas, [`openapi.yml`](../openapi.yml) is the authoritative machine-readable spec.*

`GET /status` is OpenCDR Core's stable liveness and deployment-identity contract. It reports the Core version, management-contract version, account, home region, stage, and advertised capabilities; see [Management contract](management-contract.md).

## Authentication

Every endpoint requires an `x-api-key` header. Keys are created automatically by API Gateway on deploy and available in the deploy output, or in SSM — along with the base URL itself, handy for pointing Postman, `curl`, `scripts/opencdr.py`, or the MCP server at a deployed stage directly (see [Deployment](deployment.md)).

The named deployment manager can call every route using the correct deployment's
SSM URL and key without persisting another credential copy:

```bash
opencdr-deploy --deployment customer-prod \
  api request GET /help

opencdr-deploy --deployment customer-prod \
  api request POST /rules/validate --file candidate.json
```

`request` accepts `GET`, `POST`, `PUT`, and `DELETE`, repeated
`--query key=value` arguments, and JSON from `--file`, stdin (`--file -`), or
`--data`. It rejects absolute URLs so the selected deployment's key cannot be
redirected to another host.

The Core checkout's own CLI exposes the same generic request shape when direct
environment-based configuration is more appropriate:

```bash
python3 scripts/opencdr.py request GET /help
```

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
| Lists | `opencdr_lists_list/show/replace/add/remove/delete` |
| Signals / Logs | `opencdr_signals_search`, `opencdr_signals_stats`, `opencdr_logs_search` |
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

## Machine-readable contract

`openapi.yml` is the canonical machine-readable API contract and is tested against the routes wired by `serverless.yml`. `src/openapi/swagger.json` is a JSON serialization of the same contract for packaged consumers. Neither `/swagger.json` nor `/docs` is a served management endpoint; use the repository or installed-package artifact for generated clients.

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
| `GET` | `/rules` | Optional `rule_kind` filter (`signal`/`correlation`); legacy `list` reads remain during migration |
| `POST` | `/rules` | Create a rule |
| `GET` | `/rules/{rule_id}` | `rule_kind` query param required to know which partition to read |
| `PUT` | `/rules/{rule_id}` | Update a signal/correlation rule; `rule_kind` is in the body |
| `DELETE` | `/rules/{rule_id}` | Delete a rule; `rule_kind` query parameter required |
| `GET` | `/rules/schema` | Versioned authoring and compatibility contract |
| `POST` | `/rules/validate` | Structured, side-effect-free candidate validation |
| `POST` | `/rules/evaluate` | Candidate evaluation against supplied fixtures; no notifications, response, or writes |
| `GET` | `/rules/runtime-status` | Stored catalog versus signal/correlation evaluator observation |
| `POST` | `/rule-releases/plan` | Preview exact manifest convergence |
| `POST` | `/rule-releases/apply` | Idempotent revision-guarded exact release application |

Rules may use `response_actions` to configure up to ten ordered response modules. Each action maps
the module's fixed argument names to field paths in the triggering detection—for example,
`{"module":"disable_user","target":{"user_name":"actor.user_name"}}`. The accepted target
keys and field-path roots are module-specific and are returned by `GET /rules/schema`. The legacy
single `response_module` field remains readable and writable for compatibility, but it is mutually
exclusive with `response_actions`. See [Incident Response](incident-response.md#response-modules)
for target-resolution and failure behavior.

### Reusable lists

| Method | Path | Notes |
|---|---|---|
| `GET` | `/lists` | Paginated list metadata; values are intentionally omitted |
| `POST` | `/lists` | Create from `list_id`, `matcher`, `values`, and optional metadata |
| `GET` | `/lists/{list_id}` | Read the active version and its values |
| `PUT` | `/lists/{list_id}` | Create or activate a new immutable value snapshot; updates require `expected_rev` |
| `DELETE` | `/lists/{list_id}` | Delete metadata and all stored versions |

`matcher` is `exact` or `cidr`. `value_type` is descriptive metadata (`string`, `ip`, `cidr`,
`iam_user`, `arn`, `aws_account_id`, or `resource_id`). A rule references the stable ID with
`{"field":"actor.user_name","op":"in_list","list_id":"admin-users"}`. List data is not
embedded in rule-release manifests, so a shared list can change without republishing rulesets.
`matcher` and a non-empty `values` array are required. `value_type`, `description`, and `labels`
are optional metadata; `value_type` defaults to `cidr` for CIDR lists and `string` otherwise. Updates become visible to warm evaluators after their cache refresh (normally
within 60 seconds). Each update retains another internal snapshot, so frequently changing very large
lists increases DynamoDB storage. `DELETE` removes the metadata and all stored versions.

Legacy `rule_kind=list` rows can still be read and deleted through `/rules` for migration, but new
legacy writes are rejected. Migrate the complete legacy set before relying on `/lists`; the evaluator
uses legacy rows only while the dedicated table has no list metadata.

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

#### Optimistic concurrency & audit attribution

Rule, list, and settings writes are read-modify-write operations. Rules/settings accept an optional `expected_rev`; when supplied, the write is conditional on the stored revision and returns `409` on a mismatch. Existing list updates require `expected_rev` because every update replaces the complete active value set; creates omit it. The OpenCDR CLI and MCP list add/remove operations read the current revision and use bounded compare-and-set retries so concurrent edits are not silently lost.

Every mutation also stamps `updated_by` from the **server-authenticated API-key id**, never from the request body — a client (or LLM) cannot forge who made a change. A body-supplied `updated_by` is discarded. `POST .../rollback` records the same server-side actor plus an optional `reason` and `interface` tag on the action's audit fields.

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
| `GET` | `/ir-actions/{detection_id}` | Read a specific action (the path value is the action ID for `response_actions`; `source_detection_id` links it to the detection), including `rollback_supported` and, once a rollback has been attempted, `rollback_status` (`pending`/`succeeded`/`failed`), `rollback_error`, `rollback_updated_at`. `rolled_back` mirrors `rollback_status == "succeeded"` for back-compat — see [Incident Response](incident-response.md#rollback) for the full state machine |
| `POST` | `/ir-actions/{detection_id}/rollback` | Enqueue the rollback for async execution — returns `202` immediately, not the rollback's result, and sets `rollback_status: "pending"`. `400` if `rollback_supported` is false; `409` only if a rollback is already `pending` — a previously `failed` rollback can be retried |

```bash
curl -X POST "$OPENCDR_API_URL/ir-actions/<detection_id>/rollback" -H "x-api-key: $OPENCDR_API_KEY"
```

A `POST .../rollback` only enqueues onto `ir-rollback-queue` — the actual undo runs in `rollbackHandler` (`src/handlers/ir_rollback.py`), the same async, rate-limited, dry-run-respecting shape as the original action pipeline (`processor` → outbox → `responder`), rather than a synchronous call from this Lambda. Full detail on which modules are rollback-eligible and why: [Incident Response](incident-response.md#rollback).

## Pagination

The `/signals`, `/logs`, and `/rules` collection endpoints share the same cursor convention: `page_size` (1–200, default 20), `order` (`asc`/`desc`, default `desc`), and an opaque `next_token` returned in the response — pass it back as a query param to get the next page. `/rules` with no `rule_kind` filter queries both partitions independently and merges, so a single response can return up to `page_size` × 2 items — see the `notes` field in that response for the exact accounting. `/signals`' `severity` and `/logs`' `service` selectors merge-paginate across day-buckets instead (see above) — each page drains one day before moving to the next to preserve chronological order, so unlike `/rules` a single response never exceeds `page_size` items. `/lists` uses `page_size` (1–200, default 50) and `next_token`, but has no `order` parameter.

## Related pages

- [Detection Rules](detection-rules.md) — `/rules` body schema in full
- [Notifications](notifications.md) — `/settings` channel configuration in full
- [Incident Response](incident-response.md) — `/ir-roles` and how resolution actually works
- [Security](security.md) — the API key's real scope and secrets handling
- [`openapi.yml`](../openapi.yml) — complete machine-readable API contract

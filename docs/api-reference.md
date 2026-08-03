# API Reference

*The REST API's authentication model and endpoint surface — for exact request/response schemas, [`openapi.yml`](../openapi.yml) is the authoritative machine-readable spec, though see the note below on where it's currently out of sync with the actual code.*

## Authentication

Every endpoint requires an `x-api-key` header. The key is created automatically by API Gateway on deploy and available in the deploy output, or in SSM (see [Deployment](deployment.md)).

**Stated plainly**: there is one API key per stage, and it controls everything — reading signals, mutating detection rules, reading and writing notification settings (including integration secrets), and reassigning which IAM role `responder` assumes per AWS account via `/ir-roles`. There is no route-level scoping today; a leaked key is a full compromise of the deployment's control surface, not just its read path. See [Security](security.md) for the full picture and why this is a known, deliberate gap rather than an oversight.

## A note on `openapi.yml`

`openapi.yml` documents `/status`, `/help`, `/swagger.json`, `/docs`, `/signals`, `/logs`, `/rules`, and `/settings`. Two things are worth knowing before trusting it as complete:

- It **omits `/ir-roles` entirely**, even though that route is fully implemented in `src/handlers/api.py` and wired in `serverless.yml`.
- `/swagger.json` and `/docs` are documented but **not implemented** — `api.py`'s routing table has no handler for either path; a request to them returns the same 404 as any unrouted path.

Use it for the endpoints it does cover (query parameters and enums for `/signals`, `/logs`, `/rules`, `/settings` are accurate), but don't rely on it for `/ir-roles` or assume `/docs`/`/swagger.json` work — this page and direct reading of `src/handlers/api.py` are more current.

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

```bash
curl "$OPENCDR_API_URL/signals?severity=HIGH&page_size=20" \
  -H "x-api-key: $OPENCDR_API_KEY"
```

### Logs

| Method | Path | Notes |
|---|---|---|
| `GET` | `/logs` | Same shape as `/signals`: exactly one of `service`, `event_id`, `event_name`, plus `order`/`page_size`/`next_token` |

```bash
curl "$OPENCDR_API_URL/logs?service=OCDR-PROCESSOR" \
  -H "x-api-key: $OPENCDR_API_KEY"
```

### Rules

| Method | Path | Notes |
|---|---|---|
| `GET` | `/rules` | Optional `rule_kind` filter (`signal`/`correlation`); omitted, queries both partitions and merges |
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

## Pagination

Every list endpoint (`/signals`, `/logs`, `/rules`) shares the same cursor convention: `page_size` (1–200, default 20), `order` (`asc`/`desc`, default `desc`), and an opaque `next_token` returned in the response — pass it back as a query param to get the next page. `/rules` with no `rule_kind` filter queries both partitions independently and merges, so a single response can return up to `page_size` × 2 items — see the `notes` field in that response for the exact accounting.

## Related pages

- [Detection Rules](detection-rules.md) — `/rules` body schema in full
- [Notifications](notifications.md) — `/settings` channel configuration in full
- [Incident Response](incident-response.md) — `/ir-roles` and how resolution actually works
- [Security](security.md) — the API key's real scope and secrets handling
- [`openapi.yml`](../openapi.yml) — machine-readable spec (partial, see note above)

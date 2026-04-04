# REST API

All endpoints require an `x-api-key` header. The key is created automatically by Serverless and printed in the **API Keys** section of `serverless deploy` output.

## Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/status` | Health check |
| `GET` | `/help` | Endpoint reference |
| `GET` | `/signals` | Query signals by `severity`, `event_id`, or `category` |
| `GET` | `/logs` | Query logs by `service`, `event_id`, or `event_name` |
| `GET` | `/rules` | List rules (filter by `rule_kind=signal\|correlation`) |
| `GET` | `/settings` | Get global notification settings |

All list endpoints support `page_size`, `order` (`asc`/`desc`), and cursor-based pagination via `next_token`.

## Example Requests

```bash
API_URL=https://<api-id>.execute-api.<region>.amazonaws.com/dev
API_KEY=<your-api-key>

# Health check
curl -H "x-api-key: $API_KEY" $API_URL/status

# Query HIGH signals
curl -H "x-api-key: $API_KEY" "$API_URL/signals?severity=HIGH"

# List signal rules
curl -H "x-api-key: $API_KEY" "$API_URL/rules?rule_kind=signal"

# Paginate
curl -H "x-api-key: $API_KEY" "$API_URL/signals?page_size=20&order=desc&next_token=<token>"
```

## OpenAPI Spec

A full OpenAPI spec is available at `openapi.yml` in the repository.

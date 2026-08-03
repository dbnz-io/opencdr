# Detection Rules

*How a detection rule is structured, how to author and test one locally, and how it gets loaded into a running deployment.*

## Storage model

Every rule is one row in the `detection-rules-table`: partition key `rule_kind`, sort key `rule_id`, and the actual rule content stored as `rule_body` — a JSON-serialized string, parsed back into a real object by `src/infra/detection_rules_repository.py` when `processor`/`alerter` load rules. This indirection is what makes rules **data, not code**: editing a rule is a DynamoDB write (via the API or `scripts/load_rules.sh`), not a Lambda redeploy.

Three values of `rule_kind` exist in practice, though not all are exposed the same way:

- **`signal`** — matched by `processor` against one normalized event at a time. Mutable via the API (`ALLOWED_RULE_KINDS` in `src/handlers/api.py`).
- **`correlation`** — matched by `alerter` against a window of recent signals. Also mutable via the API.
- **`list`** — reference lists (e.g. allow-lists) that rule conditions can check membership against, loaded via `load_detection_rules(rule_kind="list")` in `processor.py`. Not currently exposed through the `/rules` mutation API (`ALLOWED_RULE_KINDS` only covers `signal`/`correlation`) — manage list rows the same way as the others at the storage layer if you need one, but the API's rule-mutation validation doesn't cover this kind today.

## Signal rules

Matches a single normalized event. When every condition passes, a signal is written.

```json
{
  "rule_id": "001_console_login_no_mfa",
  "rule_kind": "signal",
  "description": "Console login without MFA.",
  "enabled": true,
  "severity": "HIGH",
  "notify": true,
  "response_module": "",
  "playbook": "Verify user and source IP. If suspicious, revoke sessions and enforce MFA.",
  "conditions": [
    { "field": "activity_name", "op": "equals", "value": "ConsoleLogin" },
    { "field": "raw_event.detail.additionalEventData.MFAUsed", "op": "equals", "value": "No" }
  ]
}
```

**Operators**: `exists`, `not_exists`, `equals`, `not_equals`, `in`, `not_in`, `contains`, `not_contains`, `prefix`, `suffix`, `matches` (regex), `wildcard` (matches any event).

**Normalized fields available in conditions** (produced by `src/domain/ocsf_min_parser.py` — see [Glossary](glossary.md#ocsf) for what "normalized" means here):

| Field | Description |
|---|---|
| `activity_name` | CloudTrail event name (e.g. `ConsoleLogin`, `CreateUser`) |
| `category` | Event category derived from service (e.g. `iam`, `s3`, `ec2`, `authn`) |
| `class_name` | Event class (`api_activity`, `authentication`, `security_finding`) |
| `source` | Event source (`cloudtrail`, `guardduty`) |
| `severity` | Normalized severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN`) |
| `actor.type` | Identity type (`Root`, `IAMUser`, `AssumedRole`, `FederatedUser`) |
| `actor.user_name` | IAM principal name |
| `actor.account_id` | AWS account ID of the actor |
| `actor.arn` | Full ARN of the actor |
| `network.source_ip` | Source IP address |
| `network.user_agent` | User agent string |
| `api.service` | AWS service endpoint (e.g. `iam.amazonaws.com`) |
| `api.operation` | API operation name |
| `api.error_code` | CloudTrail error code if the call failed |
| `raw_event.detail.*` | Any field from the raw EventBridge event payload, if you need something not yet normalized |

If `response_module` is set on a signal rule (e.g. `disable_access_key`), a match also queues an automated IR action — see [Incident Response](incident-response.md).

## Correlation rules

Groups signals by a field, counts them within a rolling time window, and fires an alert once the threshold is met. `signal_conditions` optionally restricts which signals count toward the threshold.

```json
{
  "rule_id": "020_correlation_console_login_bruteforce",
  "rule_kind": "correlation",
  "description": "Multiple MFA-less logins from the same user.",
  "enabled": true,
  "severity": "CRITICAL",
  "group_by": "actor.user_name",
  "time_window_seconds": 900,
  "threshold": 5,
  "signal_conditions": [
    { "field": "rule_id", "op": "equals", "value": "001_console_login_no_mfa" }
  ],
  "notify": true,
  "response_module": "disable_user",
  "playbook": "Disable the user and investigate source IPs."
}
```

`group_by` matters for performance, not just logic: the correlation engine queries the signals table's `gsi_signal_actor_user_name` GSI when grouping by `actor.user_name` (every shipped correlation rule does), and falls back to a full table scan for any other `group_by` value — see [Architecture](architecture.md#dynamodb-tables).

## What ships out of the box

19 signal rules and 4 correlation rules, covering initial access, persistence, privilege escalation, defense evasion, credential access, and exfiltration. The full list — rule IDs, severities, and tactics — is in the root [README](../README.md#batteries-included--detection-rules).

## Authoring, testing, and loading

```bash
# Test all rules against sample events, without touching AWS
python3 scripts/test_rules_local.py

# Filter by event or by rule
python3 scripts/test_rules_local.py --event 012
python3 scripts/test_rules_local.py --rule cloudtrail

# Preview what load_rules.sh would write, without writing it
./scripts/load_rules.sh --dry-run

# Load rules into a deployed stack
./scripts/load_rules.sh --stage dev
```

Sample events for all 19 signal rules live in `support_files/test_events/` — one JSON fixture per rule, in the exact normalized-event shape `processor` expects. When adding a new rule, add a matching fixture so `test_rules_local.py` can exercise it, and see [`CONTRIBUTING.md`](../CONTRIBUTING.md) for the review expectations on new rules.

`./scripts/load_rules.sh` does a plain upsert of everything in `support_files/detection_rules/` — no merge logic. Running it against a stage where a rule has since been edited live via the API will silently overwrite that edit back to the file's version. It's meant for initial seeding and intentional bulk updates, not something to wire into a deploy pipeline that runs on every push (this repo's own CI deliberately does not call it on deploy, for exactly that reason).

## Managing rules at runtime

The full CRUD surface is also available over the API — see [API Reference](api-reference.md#rules) — for editing a single rule without touching files, or building your own tooling on top.

## Related pages

- [Architecture](architecture.md) — where rules sit in the overall data flow
- [Incident Response](incident-response.md) — what happens when a rule's `response_module` fires
- [API Reference](api-reference.md) — the `/rules` endpoints

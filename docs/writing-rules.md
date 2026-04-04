# Writing Detection Rules

Rules are stored in DynamoDB. Write them as JSON and load with `load_rules.sh`, or manage them at runtime via the API.

## Signal Rule

Matches a single normalized event. When all conditions pass, a signal is written to the signals table.

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

## Condition Operators

| Operator | Description |
|---|---|
| `exists` | Field is present |
| `not_exists` | Field is absent |
| `equals` | Exact match |
| `not_equals` | Not an exact match |
| `in` | Value is in a list |
| `not_in` | Value is not in a list |
| `contains` | String contains substring |
| `not_contains` | String does not contain substring |
| `prefix` | String starts with value |
| `suffix` | String ends with value |
| `matches` | Regex match |
| `wildcard` | Matches any event |

## Normalized Fields

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
| `raw_event.detail.*` | Any field from the raw EventBridge event payload |

## Correlation Rule

Groups signals by a field, counts them within a time window, and fires an alert when the threshold is reached. `signal_conditions` optionally filters which signals count toward the threshold.

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

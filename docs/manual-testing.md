# Manual Deployment Testing

*A step-by-step runbook for verifying a live OpenCDR deployment actually works end to end — detection, notification, response, rollback, and the management surfaces around them. Written for two audiences: the person who just deployed it (verifying their own work before handing it off) and a client verifying what they were given.*

None of this is a substitute for `pytest tests/` (unit-level correctness) or CI's own `post-deploy-*` jobs (automated, gated on every push to `main`). This is what to run **by hand**, once, against a specific deployment — after first standing it up, after a significant change, or whenever you want independent confirmation that "CI is green" actually means "this works" for the account it's pointed at.

## Prerequisites

- AWS CLI v2, configured with credentials for the target account (`aws sts get-caller-identity` should succeed)
- `jq`
- Python 3.12 with this repo's `requirements-dev.txt` installed, if using `scripts/opencdr.py` (recommended — it's the same logic CI/the MCP server use, just invoked directly)
- The deployment's API URL and at least one API key — see [Complete Setup Guide](setup.md) if you don't have these yet, or pull them from SSM: `/opencdr-<stage>/api-url` and `/opencdr-<stage>/api-key`
- Know the `--stage`/`--region` you're testing (defaults below assume `dev`/`us-east-1`)

Configure the CLI once so you don't have to pass `--url`/`--key` on every command:

```bash
python3 scripts/opencdr.py config set --url "$OPENCDR_API_URL" --key "$OPENCDR_API_KEY"
```

## 1. API is up and the key is valid

```bash
python3 scripts/opencdr.py status
# or: curl "$OPENCDR_API_URL/status" -H "x-api-key: $OPENCDR_API_KEY"
```

Expect `service`, `lambda_name`, and a current `time`. A `403` here means the key is wrong or missing a required scope — see [API key scopes](api-reference.md#api-key-scopes) before going further. `GET /help` (no auth required) lists every route this deployment actually serves; worth a glance to confirm it matches what you expect to be running (e.g. `/signals/stats` present means the dashboard-stats endpoint deployed).

## 2. Detection rules are loaded

```bash
python3 scripts/opencdr.py rules list --rule-kind signal | head -5
```

If empty, rules were never loaded — run `./scripts/load_rules.sh --stage <stage> --dry-run` first to preview, then without `--dry-run` to actually write them. Rule content itself lives in [dbnz-io/opencdr-detection-rules](https://github.com/dbnz-io/opencdr-detection-rules), pulled in here as a git submodule at `support_files/detection_rules` — if that directory looks empty in your checkout, run `git submodule update --init` first.

## 3. Detection actually fires (the core loop)

This is the single most important check — everything else in this doc depends on detections actually reaching the signals table. Prior real bugs (see the [roadmap](https://claude.ai/code/artifact/419ac79c-b8fb-4498-9ccb-4c9d5d09e4fb) methodology log) have shipped past unit tests but failed exactly here, so don't skip it.

```bash
python3 scripts/opencdr.py test deployed --stage <stage>
# or: ./scripts/test_deployed.sh --stage <stage>
```

Sends every fixture in `support_files/test_events/` straight to the deployed `processor` Lambda and polls `signals-table-v2` for the resulting signal. Expect `PASS` for every fixture except `028_guardduty_catchall` (deliberately has no dedicated fixture — see [Detection Rules](detection-rules.md)). A `MISS` ("no rules matched") almost always means step 2 wasn't actually done against this stage/region. Narrow to one rule while debugging: `--event 011`.

## 4. Signals and logs are queryable

```bash
python3 scripts/opencdr.py signals list --severity HIGH --page-size 5
python3 scripts/opencdr.py logs list --service OPENCDR-PROCESSOR --page-size 5
```

Confirms the read path independently of step 3's write path — you should see the signals step 3 just created, plus structured log lines from every handler that ran along the way.

## 5. The dashboard (UI) connects and shows real data

1. Open the UI (opencdr-ui-internal), connect it to the deployment's API URL + key.
2. **Overview** page: Connection panel should show the same `service`/`time` as step 1. Signals-by-severity widget should reflect step 3's signals — switch the Today / Last 7 days / Last 30 days range and confirm the counts change plausibly.
3. **Signals** / **Logs** pages: search, confirm rows appear, click a row to see the detail modal, click a column header to confirm sorting works and defaults to time descending.
4. **Rules** page: confirm the rule count matches step 2.

If the dashboard widget or any list is empty while steps 3/4 show real data via the CLI, that's a UI-side bug (stale API client, wrong route) rather than a deployment problem — worth filing separately rather than assuming the backend is broken.

## 6. Notifications actually deliver

There's no synthetic "send me a test notification" endpoint — the only real proof is a live detection reaching a real channel.

1. Configure at least one channel: `python3 scripts/opencdr.py settings set --channel slack --webhook-url "$SLACK_WEBHOOK_URL"` (or via the UI's Settings page). See [Notifications](notifications.md) for every channel's exact fields.
2. Pick a fixture whose rule has `notify: true` and re-run step 3 filtered to it, e.g. `--event 001` (console login without MFA).
3. Confirm the message actually lands in the configured channel within a few seconds. Check `logs list --service OPENCDR-NOTIFIER` if it doesn't — the notifier logs a distinct event per channel per attempt, including the failure reason for a bad webhook/token.

GuardDuty-sourced findings default to **not** notifying (see [GuardDuty notifications](notifications.md#guardduty-notifications)) — use a CloudTrail fixture for this check unless you've explicitly opted GuardDuty in.

## 7. An automated response fires, and can be rolled back

Only meaningful if at least one rule you loaded has a `response_module` set and you've reviewed [Response modules](incident-response.md#response-modules) — this step takes a real, if synthetic-triggered, action in the target AWS account. Skip it in an account you're not prepared to see IAM/network changes in.

1. Re-run step 3 filtered to a fixture whose rule has a `response_module` (e.g. `--event 011`, security group ingress rule → `deauthorize_security_group_rules`, if wired) — **only after** loading rules with `--with-response-modules` (rules load with `response_module` stripped by default, see [Detection Rules](detection-rules.md)).
2. Confirm the action landed:
   ```bash
   python3 scripts/opencdr.py ir-actions list --page-size 5
   ```
   Expect the new action, `rollback_supported: true` if the module is one of the rollback-eligible ones (see [Incident Response](incident-response.md#rollback)).
3. Roll it back:
   ```bash
   python3 scripts/opencdr.py ir-actions rollback <detection_id>
   ```
   This enqueues the rollback (`202`, `rollback_status` flips to `pending` immediately). Poll `ir-actions get <detection_id>` a few seconds later — expect `rollback_status: succeeded`. If it comes back `failed`, `rollback_error` now carries the real underlying AWS exception text (e.g. an `AssumeRole` `AccessDenied`) — see [IR role setup](ir-role.md) if that's what you hit; a common cause is the target account's IR role trust policy not listing both `responder` and `rollbackHandler`'s execution roles as trusted principals.
4. In the UI's **IR Actions** page, confirm the same action shows the matching status pill (pending → succeeded, or failed with the error visible inline) without a manual refresh — it polls automatically for a bit after you trigger a rollback there.

## 8. The MCP server (if you're using it as the management plane)

Point an MCP-compatible client at `mcp_server/server.py` using its own dedicated API key (see [API Reference](api-reference.md#mcp-server-default-management-plane) for setup). Run its `status` tool first — same check as step 1, proves the MCP server's own key and connection are valid independently of anything else in this doc. Then spot-check one tool per surface it covers (a rules list, a signals query, a settings read) rather than every tool — if `status` and one tool per surface work, the rest follow the same code path.

## Summary checklist

| # | Check | Command | Pass looks like |
|---|---|---|---|
| 1 | API reachable, key valid | `opencdr.py status` | service/time returned, no 403 |
| 2 | Rules loaded | `opencdr.py rules list` | non-empty |
| 3 | Detection fires | `opencdr.py test deployed` | all `PASS` (except 028) |
| 4 | Signals/logs queryable | `opencdr.py signals list` / `logs list` | rows from step 3 visible |
| 5 | Dashboard shows real data | UI Overview/Signals/Logs pages | counts match steps 3/4 |
| 6 | Notifications deliver | trigger a `notify: true` rule | message lands in configured channel |
| 7 | Response fires + rolls back | trigger a `response_module` rule, then `ir-actions rollback` | action recorded, rollback reaches `succeeded` |
| 8 | MCP server connects | MCP client `status` tool | same as step 1 |

If everything above passes, the deployment is confirmed working end to end — not just "the stack deployed," but "a real event, in this account, produces a real signal, a real notification, and (if armed) a real, reversible response."

## Related pages

- [Complete Setup Guide](setup.md) — first-time deployment, before any of the above applies
- [Detection Rules](detection-rules.md) / [dbnz-io/opencdr-detection-rules](https://github.com/dbnz-io/opencdr-detection-rules) — rule schema and catalog
- [Incident Response](incident-response.md) — response modules, rollback, rate limiting
- [API Reference](api-reference.md) — every endpoint this doc's CLI commands wrap

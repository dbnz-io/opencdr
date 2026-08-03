# Security

*The IAM model, how secrets are actually stored, and the known, deliberate limitations — stated plainly rather than glossed over.*

For reporting a vulnerability, see [`SECURITY.md`](../SECURITY.md) — this page is about how the system is built, not how to disclose a bug in it.

## IAM model

Every Lambda has its **own** IAM role (`serverless-iam-roles-per-function`, not the Serverless Framework's default single shared role). This is a meaningful distinction when reasoning about blast radius: `processor` can write signals but not touch SQS; `notifier` can read settings but not DynamoDB streams it doesn't own; only `responder` can call `sts:AssumeRole`, and only on roles matching the exact naming convention `${service}-${stage}-ir-role` in any account — not a blanket `sts:AssumeRole` grant. `responder`'s own execution role has zero IAM/EC2/S3 permissions itself; every actual destructive action runs through the temporary credentials of an assumed role instead. Full detail in [Incident Response](incident-response.md).

The CI deploy role (`ci-bootstrap/oidc-deploy-role.yaml`) is a separate concern from the application's own per-function roles — it's what GitHub Actions assumes via OIDC to run `serverless deploy` in the first place, scoped to the `${ServiceName}-*` resource-naming convention wherever the AWS service in question supports resource-level ARN scoping. See [`ci-bootstrap/README.md`](../ci-bootstrap/README.md).

## Secrets management

Notification channel secrets — Slack/Discord webhook URLs, the Jira API token, and every custom webhook target's header values — are never stored as plaintext DynamoDB attributes. `src/domain/settings_secrets.py` externalizes each one to SSM Parameter Store as a `SecureString` the moment it's written through the API, and DynamoDB holds only an `ssm:`-prefixed reference. `GET /settings` masks every one of these fields to `***REDACTED***` on read regardless — there's no path, intentional or accidental, that returns a real secret value back through the API once it's been set.

The deployed API key itself follows the same principle at the infrastructure level: CI writes it to SSM as a `SecureString` (`/opencdr-<stage>/api-key`) rather than anyone pulling it into a local file by hand.

## API Gateway

API-key auth on every route, backed by a usage plan (10,000 requests/month quota, 100 requests/second rate limit) — a basic backstop against runaway/accidental traffic, not a security control against a determined caller with a valid key.

## Known, deliberate limitations

Stated plainly, because a client evaluating this deployment should know about these rather than discover them:

- **One API key controls everything.** Reading signals, mutating detection rules, reading and writing notification settings, and reassigning which IAM role `responder` assumes per AWS account via `/ir-roles` all sit behind the same single key — there is no route-level scoping. A leaked key is a full compromise of the control surface, not just the read path. Real scoping would need a custom Lambda authorizer, since API Gateway keys aren't route-scoped by default. This is a known, deliberately deferred gap, not an oversight.
- **No per-alert human approval on automated response.** The rate-limit circuit breaker (see [Incident Response](incident-response.md#rate-limiting)) caps runaway automation account-wide, but any individual detection with a `response_module` set fires automatically once it matches — there's no approval step in between.
- **The observability layer is AWS-native, not portable.** See [Observability](observability.md#portability-the-honest-tradeoff) — a deliberate tradeoff, not a limitation to be fixed later by default.
- **A fresh deploy only covers its own region.** `processor`'s EventBridge rule listens on the default bus in the deployment region only — CloudTrail and GuardDuty events from any other region an account operates in never reach it, by default. A mitigation exists (`scripts/setup_region_forwarding.sh`, see [Cross-Region Event Forwarding](region-forwarding.md)) but it's an explicit, opt-in step per additional region, not automatic — a multi-region account that hasn't run it is silently blind outside its deployment region.

## Related pages

- [Incident Response](incident-response.md) — the responder's role-assumption model in full
- [Notifications](notifications.md) — where channel secrets get written
- [API Reference](api-reference.md) — the authentication model from the caller's side
- [`SECURITY.md`](../SECURITY.md) — vulnerability reporting
- [Cross-Region Event Forwarding](region-forwarding.md) — closing the single-region coverage gap

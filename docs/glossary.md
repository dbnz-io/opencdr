# Glossary

*Terms used throughout these docs, defined the way this codebase actually uses them — not always the generic industry definition.*

### Signal vs. alert vs. correlation

- **Signal** — the result of a single **signal rule** matching a single normalized event. Written by `processor`, one row per match, into the signals table.
- **Correlation (rule)** — a rule that groups signals by a field (e.g. `actor.user_name`), counts them in a rolling time window, and fires once a threshold is met.
- **Alert** — the result of a correlation rule's threshold being met. Written by `alerter`. This is the thing that actually gets delivered via [Notifications](notifications.md) and can trigger [Incident Response](incident-response.md) — a bare signal, on its own, does not (unless its own rule sets `notify`/`response_module` directly).

### Detection rule

A JSON document (`rule_kind`, `rule_id`, `rule_body`) stored in the `detection-rules-table`, defining either a signal match or a correlation pattern. See [Detection Rules](detection-rules.md).

### Outbox (pattern)

A reliability pattern: instead of `alerter` calling SQS directly when an alert fires, it writes a row to an outbox table in the same operation as writing the alert. A separate `publisher` Lambda, triggered by that table's own DynamoDB stream, claims and publishes the row to SQS. Guarantees at-least-once delivery without coupling `alerter` directly to SQS availability — see [Architecture](architecture.md).

### IR role

The IAM role `responder` assumes (via `sts:AssumeRole`) to actually execute a response module, resolved per-detection based on which AWS account it came from. See [Incident Response](incident-response.md).

### Circuit breaker (rate limit)

In this codebase specifically: a rolling-window cap on how many destructive IR actions `responder` will execute (`RESPONDER_RATE_LIMIT_MAX_ACTIONS` per `RESPONDER_RATE_LIMIT_WINDOW_MINUTES`). Once tripped, further matching detections are logged and skipped until the window rolls forward. Not a general-purpose resilience pattern here — specifically about capping automated response.

### Dry run

`DREDGE_DRY_RUN=true` — every IR response module still runs its full logic (resolving the target, assuming the IR role) but stops short of the actual mutating AWS API call, logging what it *would* have done instead.

### EMF (Embedded Metric Format)

A CloudWatch-specific JSON log shape that CloudWatch automatically extracts into real metrics without a separate metrics API call — a Lambda just prints a specially-shaped JSON line, and CloudWatch does the rest. Used for all of OpenCDR's [custom metrics](observability.md#custom-metrics) — chosen because it needs no additional IAM or infrastructure beyond the log-write permission every Lambda already has.

### OCSF

The [Open Cybersecurity Schema Framework](https://ocsf.io/) — an industry standard for normalizing security event data. `src/domain/ocsf_min_parser.py` is explicitly a **minimal, OCSF-aligned** parser, not a full implementation: it borrows OCSF's naming and structural concepts (`class_name` values like `api_activity`/`authentication`/`security_finding`, an `actor`/`api`/`network` field grouping) so the shape is familiar to anyone who knows OCSF, but does not implement full OCSF class mapping or `type_uid` assignment. Detection rule conditions in [Detection Rules](detection-rules.md) are written against this minimal normalized shape, not raw CloudTrail/GuardDuty payloads.

### Normalized event

The output of `ocsf_min_parser.py` for a raw CloudTrail or GuardDuty EventBridge event — the common shape (`activity_name`, `actor`, `api`, `network`, ...) that detection rule conditions actually evaluate against, regardless of which raw source produced it.

### Stage

A Serverless Framework deployment target (`dev`, `prod`, etc.) — determines resource naming (`opencdr-<stage>-...`) and which set of SSM parameters/config a deployment reads. OpenCDR today is typically run as a single `dev`-named stage per AWS account, not multiple environments in one account.

## Related pages

- [Architecture](architecture.md) — where these terms fit into the overall system
- [Detection Rules](detection-rules.md) — signal/correlation rule schema in full

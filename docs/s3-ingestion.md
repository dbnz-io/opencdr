# Falco and executable S3 integrations

Status: backend implementation with offline integration coverage. Deployment and
live Falco/Falcosidekick compatibility, throughput, and permission checks remain
release gates. The companion web UI is outside this repository; API, CLI and MCP
management are included here.

## How it works

Upload an object under `ingest/<integration_id>/` in the deployment's ingestion
bucket. S3 sends ObjectCreated events to SQS. OpenCDR retrieves the exact object
version, frames records, invokes the selected parser, validates the normalized
result, evaluates rules and persists evaluated records before dispatching signals.
The shared signal writer completes alert/outbox delivery intent on retries even
when the signal already exists. Existing CloudTrail/GuardDuty paths are unchanged.

Falco uses the bundled immutable `falco.json@1.0.0` parser. Custom integrations
require executable customer-owned Lambda parsers from this first implementation.
The customer owns collection, upload success, custom parser code and its execution
role. OpenCDR owns S3 reads, parsing orchestration, validation, retries, detection,
notification, job diagnostics and raw-object provenance. No custom code is loaded
into the OpenCDR process or given its AWS credentials.

## Deployment and permissions

Deploy the updated stack to staging first. It adds a versioned, encrypted, private
bucket; encrypted queue/DLQ; ingestion state table; worker; alarms; management
routes; and one signals GSI (`gsi_signal_integration`). CloudFormation can add the
single new GSI to an existing signals table. Integrations are inactive until
registered with `enabled: true`.

For executable parsers, publish a **numeric Lambda version** and deploy with:

```sh
npx serverless deploy --stage staging --param='customParserArns=arn:aws:lambda:us-east-1:123456789012:function:customer-parser:7'
```

Replace the illustrative ARN. Multiple exact version ARNs are comma-separated,
without spaces. Empty configuration grants no parser invocation access. Both the
management API (preview/permission check) and ingestion worker can invoke only
these versions. Cross-account functions also need a resource policy granting
those two roles `lambda:InvokeFunction` on the published version. Same-account
invocation does not require an additional resource policy unless otherwise denied.
The customer's parser role should contain only the permissions its code needs.
Set its timeout at or below ten seconds; OpenCDR's invoke client waits twelve
seconds and does not automatically repeat the invocation inside the SDK.

Grant producers **only** `s3:PutObject` on their assigned
`arn:aws:s3:::<bucket>/ingest/<integration_id>/*` prefix. Do not grant delete/version
management permissions. Cross-account producers additionally need a matching
bucket policy statement, limited to the producer role and prefix. TLS and bucket
owner enforced object ownership are required. The worker reads only ingestion
object versions. Source-account and exact-bucket conditions protect the SQS
notification policy.

Bucket/table names and the ingestion role ARN are CloudFormation outputs. The
API catalog (`GET /integrations`) also returns the ingestion bucket, supported
built-in parser and explicitly permitted custom parser versions.

## Stock Falco setup

Configure Falco JSON output and forward through Falcosidekick's AWS S3 output.
Use the ingestion bucket, the integration prefix, and JSON single-record framing.
Falco's structured fields are consumed literally, including dotted keys such as
`output_fields["proc.name"]`. Original rule names, priorities and nanosecond event
times are preserved. Host, process, container and Kubernetes context accompany
signals, alerts, investigation results and archival raw items.

Upstream documentation: [Falco output channels](https://falco.org/docs/concepts/outputs/channels/)
and [Falco forwarding](https://falco.org/docs/concepts/outputs/forwarding/).
Use a pinned Falco/Falcosidekick release pair; verify its S3 key prefix, JSON
payload and ACL behavior against the bucket's owner-enforced settings in staging.
No released upstream pair has yet been certified by this implementation.

Save `falco-integration.json`:

```json
{
  "kind": "falco",
  "format": "json",
  "compression": "none",
  "parser": {"kind": "builtin", "id": "falco.json", "version": "1.0.0"},
  "enabled": true,
  "expected_rev": 0
}
```

```sh
python scripts/opencdr.py integrations put runtime-prod falco-integration.json
python scripts/opencdr.py integrations get runtime-prod
python scripts/opencdr.py integrations jobs runtime-prod
```

Seven non-overlapping stock finding rules cover normalized severity, including
UNKNOWN. Emergency/Alert/Critical map to CRITICAL; Error to HIGH; Warning to MEDIUM;
Notice to LOW; Informational/Debug to INFO. Unrecognized priorities retain their
original value and map to UNKNOWN. CRITICAL/HIGH/MEDIUM notify by default through
existing channel/severity routing. LOW/INFO/UNKNOWN are stored without notification.
These are source finding rules: Falco has already evaluated the runtime detection.
They cover shell, sensitive-file, unexpected-process and escape findings without
parsing display text or requiring a separate rule per vendor rule name.

Stock IDs are `falco/finding-<severity>-v1`, for example
`falco/finding-critical-v1`. A stored rule with the same ID overrides the bundled
rule, including `enabled: false`; deleting the override restores the default.
Additional user rules are additive and can intentionally create multiple detections.
Add the condition `source equals falco` to Falco-specific rules. The bundled rules
are maintained in the application parser module; publishing a companion rule pack
in the external detection-rules repository remains a separate release task.

## Executable parser contract v1

A custom binding replaces the parser and kind above:

```json
{
  "kind": "custom",
  "format": "ndjson",
  "compression": "none",
  "parser": {
    "kind": "lambda",
    "version_arn": "arn:aws:lambda:us-east-1:123456789012:function:customer-parser:7",
    "contract_version": "1"
  },
  "enabled": true,
  "expected_rev": 0
}
```

The Lambda receives:

```json
{
  "contract_version": "1",
  "record": {"timestamp": "2026-09-17T13:00:00Z", "message": "unexpected login"},
  "context": {"integration_id": "custom-prod", "event_id": "<stable-record-id>"}
}
```

Return one of:

- `{"status":"parsed","event":{...}}`: exactly one normalized event.
- `{"status":"dropped","code":"known_noise"}`: deliberate, observable filtering.
- `{"status":"invalid","code":"missing_timestamp"}`: permanent record error.

The event requires timezone-qualified ISO `time`, `category`, `class_name`,
`activity_name` and severity (`CRITICAL/HIGH/MEDIUM/LOW/INFO/UNKNOWN`). Optional
`actor` accepts only `user_name` and `user_id`; `network` accepts `source_ip` and
`user_agent`. Context fields are:

| Object | Supported fields |
| --- | --- |
| host | id, name |
| process | name, pid (nonnegative integer), command_line, parent_name |
| container | id, name, image |
| kubernetes | cluster, namespace, pod, node, workload, service_account |
| finding | rule_name, priority |
| vendor | event_source, tags (up to 32 strings) |

Other context values are optional strings, at most 512 characters; command_line
allows 2048. Actor/network strings allow 1024. The parser cannot return source,
event identity, AWS account/resource/role, routing, response modules or provenance.
OpenCDR assigns those trusted envelope fields. Custom events always have
`source=custom`; runtime users never become inferred IAM users.

See [runnable parser example](../support_files/parsers/example.py).
`python scripts/check_parser.py <trusted-local-module.py> <sample.json>` runs the
same validator locally. This command executes the module you explicitly select;
only run your own trusted parser code. For deployed previews:

```sh
python scripts/opencdr.py integrations preview custom-prod preview.json
```

`preview.json` contains `{"config": <binding>, "record": <sample>}`. Preview invokes
customer code but does not activate the binding or emit detections. Parsers must
be deterministic and side-effect-free: invocation is at least once. Lambda function
errors/timeouts/throttling retry to the DLQ; invalid output is quarantined. Error
payloads and raw records are never logged by the ingestion worker.

## Limits, lifecycle and investigation

Initial limits are 1 MiB compressed **and** expanded object size, 100 records per
object, 16 KiB per record/parser response, and 128 KiB per pinned job or evaluated
record result. These are conservative bounds, not benchmark-derived capacity
claims. Rules/lists exceeding the pinned-job budget fail for operator intervention;
they are not silently truncated. Supported framing: single JSON (`json`), NDJSON
(`ndjson`), or line text (`lines`, custom only), with `none` or `gzip` compression.
No whole-object custom execution, quoted multiline CSV, arrays-as-record-stream,
or multi-event expansion is supported yet. Split larger inputs before upload.
The worker has a 120-second budget and queue concurrency two per deployment.
Per-integration fairness and high-volume capacity remain load-test gates.

Updates require `expected_rev` matching the current revision; stale writes return
409. Rollback means putting a prior configuration with the current expected revision.
Jobs pin their binding, rules and lists on acceptance. A configuration change cannot
change a partly processed object's parser. Disabling stops new job acceptance;
accepted jobs drain with their pinned configuration. Disabled/unregistered uploads
remain retryable and eventually enter the DLQ instead of disappearing.

Object identity includes integration, bucket, key and version. Record identity adds
record index; persisted detection results pin IDs and storage timestamps. Concurrent
or retried workers dispatch the same winning persisted result. Existing table keys
use severity/day and timestamp; managed signal timestamps preserve receipt time
with deterministic extra fractional-second digits to disambiguate storage keys.
Treat timestamps as opaque ISO strings for pagination; rendering can reduce precision.
`event_time` retains source time separately. Dedupe state and raw objects retain
90 days; recovery beyond retention is not guaranteed. Identical producer events
uploaded under different object keys remain distinct in this version.

`GET /integrations/{id}/jobs` returns paginated jobs; `GET .../jobs/{object_id}` adds
record diagnostic codes. `DISPATCHED` means evaluated results reached the durable
signal queue, **not** that downstream notifications finished. `PARTIAL` means some
records were quarantined; `QUARANTINED` indicates an invalid object. Quarantine is
metadata plus an authorized reference to the retained original version, not a copy
into another bucket. Infrastructure failures retry via SQS/DLQ. Use the existing
signal-write DLQ, outbox status and delivery receipts for downstream diagnostics.
`GET /signals?integration_id=<id>` queries the new GSI with normal cursor pagination.
Raw retrieval requires separately authorized S3 access; the API does not issue
public URLs or presigned raw-object downloads.

## Replay, correlation and response safety

`POST /integrations/{id}/jobs/{object_id}/replay` queues a new audited analysis run
against the **current** binding/rules, reading the original object version. It returns
a new object/run ID. Poll its job status normally. Analysis signals are queryable and
archived but cannot notify, respond or enter live correlation. Retrying the original
SQS message repairs the original job with its original snapshots; that is different
from replay. The binding must be enabled for a new replay run.

Runtime correlation requires an explicit `integration_id equals <id>` condition
and `group_by=runtime_entity`. The key combines integration, host and container or
host identity. Queries stay inside one integration and are capped at 3000 recent
records per evaluation, logging a warning if truncated. Existing AWS correlation
rules cannot consume these signals. Verified runtime-to-AWS enrichment and
cross-source correlation are deferred. Correlation currently uses receipt time;
late-data/event-time policies must be validated before broad production rollout.

AWS response modules are rejected on explicitly Falco/custom rules and blocked
again at execution. Generic rules cannot bypass this: S3 detections carry no
response module. Kubernetes response actions are not implemented. Notifications
use the shared six channels; Slack/Discord/email/Jira include bounded runtime
context, webhooks retain the event, and Security Hub uses `Other` resources rather
than inventing IAM identities. Full raw command lines are excluded from formatted
runtime summaries but remain sensitive investigation data.

## Validation and release gates

Run `python scripts/qa.py` for existing AWS journeys and new upload-to-notification,
retry, versioning, custom parser and isolation tests. Run
`python scripts/check_s3_ingestion.py <staging-falco-id>` after deployment to exercise
the real bucket notification, IAM, queue, parser and signal storage. The canary uses
INFO (non-notifying stock rule); customer-added rules may still notify, so use a
dedicated staging deployment. It does not claim to certify external channel delivery.

Before declaring CloudTrail/GuardDuty-level production maturity: certify a pinned
Falco/Falcosidekick pair, run real custom Lambda/cross-account permission tests,
measure load/cost/latency, exercise DLQ recovery, verify all enabled external
notification channels, publish the external rule pack, and complete companion UI
integration. The internal roadmap tracks these remaining gates. Public source/docs
are explicitly allowlisted; internal planning and account configuration stay private.

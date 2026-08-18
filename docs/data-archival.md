# Data Archival & Retention

*Why signals/alerts/logs now expire out of DynamoDB after 90 days, where they actually go first, and how to query the archive.*

## The problem this solves

DynamoDB has no built-in retention — every signal, alert, and log line accumulates forever, and every GSI on the signals/logs tables stores a full copy of each item (`ProjectionType: ALL`), multiplying that storage. None of this data was ever unbounded by design; it just never had an expiration policy at all.

The fix isn't "delete old data" on its own — that would throw away exactly the investigative history a detection-and-response tool exists to preserve. It's **archive first, then expire**: every signal, alert, and log line is streamed to S3 as Parquet before DynamoDB ever deletes it, so the 90-day TTL is a storage-cost decision, not a data-loss one.

## What's archived, and what isn't

| Table | Archived to S3? | TTL | Why |
|---|---|---|---|
| `signals-table` | Yes | 90 days (default) | Individual detections — the core investigative record |
| `alerts-table` | Yes | 90 days (default) | Correlation-rule outputs — same reasoning as signals |
| `logs-table` | Yes | 90 days (default) | OpenCDR's own operational/audit trail |
| `outbox-table` | **No** | 90 days (default) | Delivery-tracking metadata (`PENDING`/`SENT`/`FAILED`), not investigative history — nothing worth keeping once an item's been delivered |

## How it works

```
signals-table ─┐
alerts-table ──┼─ DynamoDB Streams ─► archiver Lambda ─► Kinesis Data Firehose ─► S3 (Parquet)
logs-table ────┘                      (flattens + tags                          account=X/year=Y/
                                        partition fields)                       month=M/day=D/hour=H/
```

`archiver` (`src/handlers/archiver.py`) is triggered by each table's own DynamoDB Stream, same reliability pattern `alerter`/`publisher` already use — `bisectBatchOnFunctionError`, `maximumRetryAttempts`, and a shared `stream-failures` DLQ (see [Architecture](architecture.md#sqs-queues)). It only acts on `INSERT` events; a TTL-driven delete arrives on the same stream as a `REMOVE` event and is deliberately ignored, not re-archived or treated as a signal to do anything.

Since the [partition-key redesign](architecture.md#dynamodb-tables) replaced the original bare-key signals/logs tables with `signals-table-v2`/`logs-table-v2` (a day-bucketed `severity_bucket`/`service_bucket` key instead of a bare low-cardinality one), those two tables route to the exact same Firehose delivery streams as before (`archiver.py`'s `_STREAM_ROUTES` matches by substring, and `"signals-table"`/`"logs-table"` are substrings of `"signals-table-v2"`/`"logs-table-v2"` too), so no new Firehose/Glue infrastructure was needed for the migration. `severity_bucket`/`service_bucket` themselves are never promoted to real Parquet columns — `flatten_signal`/`flatten_log` read `severity`/`service` (the clean, untouched values) as before, and the bucket attribute just rides along unused inside `raw_item`.

For each record, `archiver`:
1. Flattens the DynamoDB item to a handful of stable, useful scalar columns, plus one `raw_item` column holding the complete original item as a JSON string (see [Schema](#schema) below for why).
2. Computes `account`/`year`/`month`/`day`/`hour` from the item's own `timestamp` (and `cloud_account_id`, where present) directly in Python — not in Firehose's JQ processor. This is a deliberate choice: date-math and ISO-timestamp parsing inside Firehose's `MetadataExtraction` processor is real, easy-to-get-subtly-wrong AWS-side configuration with no way to verify it without a real deploy. Firehose's processor here just extracts fields `archiver` already computed.
3. Sends the flattened record to the matching Firehose delivery stream, which converts it to Parquet (via the matching Glue Data Catalog table's schema) and writes it to S3 under a Hive-style partition prefix: `s3://<archive-bucket>/<signals|alerts|logs>/account=<id>/year=<Y>/month=<M>/day=<D>/hour=<H>/`.

## Schema

Each of the three Glue tables (`signals`, `alerts`, `logs` — database `${service}_${stage}_archive`) is **deliberately flat**. `actor`/`network`/`api`/`resources` and similar nested structures are **not** modeled as Parquet structs — every record's full original shape is preserved as one JSON-string `raw_item` column instead. Two reasons:

1. **No schema-sync footgun.** A rigid nested schema would need updating in the Glue table every time a field is added anywhere in a signal/alert's shape, silently dropping anything not accounted for otherwise — the same class of "two places that must stay in sync or something goes silently blind" risk already flagged for the EventBridge pattern (see [`region-forwarding.md`](region-forwarding.md#keeping-this-in-sync)) and deliberately not repeated here.
2. **No untestable AWS-side risk.** Whether `OpenXJsonSerDe`/`ParquetSerDe` handle a deeply nested struct schema correctly isn't something verifiable without a real deploy. A flat schema sidesteps the question entirely.

**`signals`**: `detection_id`, `event_id`, `rule_id`, `severity`, `timestamp`, `category`, `activity_name`, `cloud_account_id`, `cloud_region`, `source`, `actor_user_name`, `raw_item`.

**`alerts`**: `alert_id`, `alert_key`, `rule_id`, `severity`, `timestamp`, `type`, `group_value`, `cloud_account_id`, `match_count`, `raw_item`.

**`logs`**: `log_id`, `event_id`, `event_name`, `event_type`, `service`, `source`, `timestamp`, `level`, `raw_item`.

Querying a field not in this list (or comparing/filtering within `actor`/`details`/etc.) means reading `raw_item` with Athena/Presto's `json_extract` — slower than a real column, but always complete, since `raw_item` is the full original item, not a subset.

## Querying the archive (Athena)

The Glue Data Catalog tables are Athena-ready as soon as they're deployed. All three use [Athena partition projection](https://docs.aws.amazon.com/athena/latest/ug/partition-projection.html) (`projection.enabled` + `storage.location.template` in each table's `Parameters`, matching the exact `account=X/year=Y/month=M/day=D/hour=H/` prefix `archiver`/Firehose writes to) — Athena computes candidate S3 prefixes from the query's own filter values at query time, instead of looking them up in a partition list. **There is no partition-registration step** (no crawler, no `MSCK REPAIR TABLE`, no `ALTER TABLE ... ADD PARTITION`) — new hourly partitions are queryable the moment Firehose lands data in them, and skipping registration entirely also means there's nothing that can drift out of sync with what's actually in S3.

`account` specifically uses projection type `injected`, not a range — account IDs aren't a small enumerable set. **This means every query must filter on `account` with an equality or `IN` predicate**, or Athena has nothing to substitute into the location template and the query returns nothing — this isn't new advice, it's the same "queries, not full scans" discipline this project already asks for (see [Architecture](architecture.md#dynamodb-tables)), just enforced by Athena itself now instead of only by convention.

```sql
-- All CRITICAL signals for one account on one day
SELECT detection_id, rule_id, timestamp, activity_name, actor_user_name
FROM signals
WHERE account = '123456789012' AND year = '2026' AND month = '03' AND day = '15'
  AND severity = 'CRITICAL'
ORDER BY timestamp;

-- Full original item for one detection, including fields not promoted
-- to real columns
SELECT json_extract(raw_item, '$.resources') AS resources
FROM signals
WHERE account = '123456789012' AND detection_id = '...';
```

Partition pruning (the `WHERE account = ... AND year = ... AND ...` filters above) is what keeps this cheap — Athena only scans the S3 prefixes that match, not the whole archive. The projected `year` range is `2025,2030` (`projection.year.range` on each table's `Parameters` in `serverless.yml`) — widen it there if the archive is still in use past 2030.

## Retention configuration

`DYNAMODB_TTL_DAYS` (default `90`, applies to all four tables uniformly) controls how long an item lives in DynamoDB before expiring — not how long it's kept in S3. **Nothing currently deletes archived data from S3** — that's a deliberate scope boundary, not an oversight: cold storage is cheap, and a retention *policy* for the archive itself (S3 Lifecycle rules transitioning to Glacier, or expiring after N years) is a separate decision or a client's own compliance requirement to set, not something this project defaults on your behalf.

`DYNAMODB_TTL_DAYS` is an environment variable, not a `--param`, so it's set the same way as `CORRELATION_QUERY_LIMIT` or any other env-var tunable:

```bash
DYNAMODB_TTL_DAYS=180 serverless deploy --stage dev
```

## Reducing what's queryable live (optional)

Independent of archival, `LOGS_MIN_LEVEL_TO_STORE` (unset by default — stores every level, unchanged from before archival existed) can narrow what actually lands in `logs-table` itself, e.g. `LOGS_MIN_LEVEL_TO_STORE=WARNING` to only persist WARNING/ERROR. This only affects what `GET /logs` can query live — CloudWatch Logs still gets every line via the existing `print()`, and the S3 archive still gets everything regardless of this setting, since `archiver` reads off the DynamoDB stream, which only ever contains what actually got persisted. Set this only if you specifically want a *smaller live-queryable table*, not as a way to reduce archive volume.

## Verified by CI, not just declared

`serverless.yml` declaring `TimeToLiveSpecification` and `archiver`'s streams doesn't by itself prove any of it actually works — that's exactly the class of gap that let a real bug (the correlation-alert extraction bug, see the roadmap) hide behind hundreds of passing unit tests until a real deployment exposed it. `.github/workflows/ci.yml`'s `post-deploy-cloudtrail-check` job (runs after every deploy to `dev`, in parallel with three other post-deploy jobs — see [Deployment](deployment.md#cicd-github-actions-oidc)) includes two checks against the real, just-deployed stack:

1. **TTL configuration** — confirms `aws dynamodb describe-time-to-live` reports `ENABLED`/`expires_at` on all four tables (would catch a `serverless.yml` regression), and that the canary signal this same run just wrote actually has `expires_at` set (would catch an application-code regression — a future write path that forgets to set it, the exact class of bug found by grepping every outbox-write call site this session, where three separate places needed the same fix independently).
2. **Archival pipeline** — confirms `archiver` actually processed the canary signal, by searching its own CloudWatch Logs for the canary's `detection_id` in the `ARCHIVE_BATCH_COMPLETE` summary log's `archived_ids` field (`src/handlers/archiver.py`; that field exists specifically to make this check possible without a new per-record log line — see the field's own comment for why volume matters here). **Deliberately does not wait for the actual Parquet file to land in S3** — Firehose's `BufferingHints` (128MB/300s) means that can take up to 5 minutes, a real and expected latency, not a bug, but too slow to gate every CI run on. Proving the DynamoDB Streams → `archiver` → Firehose `PutRecordBatch` leg worked is the fast, deterministic proxy for "this pipeline works" — that's also where an actual regression (a broken stream trigger, an IAM permission gap, a flattening bug) would surface.

What's still **not** verified by CI, and is realistically a manual check on your first real deploy rather than something worth automating: that the Parquet file actually lands in S3 under the right partition prefix and that Athena can query it. `org-forwarding` (the event-provenance fix) isn't CI-tested at all — it's inherently multi-account, and a single-account CI deploy has nothing to provision it against.

## Related pages

- [Architecture](architecture.md#dynamodb-tables) — where these tables sit in the overall pipeline, and the GSI-not-Scan discipline that applies to all of them
- [Observability](observability.md) — the `stream-failures` DLQ alarm that also covers `archiver`
- [Deployment](deployment.md#cicd-github-actions-oidc) — the full post-deploy pipeline these checks are part of
- [Security](security.md) — least-privilege IAM model this fits into

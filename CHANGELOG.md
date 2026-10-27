# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased]

### Changed
- Removed the public OpenCDR release workflow's PyPI publication job and PyPI-only manual trigger; public releases now create only the version tag, GitHub Release, release notes, and SBOM because `dbnz-io/opencdr` has no PyPI project.
- Defined OpenCDR Core as production-ready within an explicit security shared-responsibility model, separating built-in controls from customer-selected identity, network, recovery, retention, regional, and promotion policies and documenting their cost/operability tradeoffs.
- Advanced the management contract to `2.0.0` and the rule contract to `3.0.0`: reusable lists now have an independent `/lists` lifecycle and top-level configuration-bundle section instead of being writable `rule_kind=list` records.
- Reframed the repository as **OpenCDR Core**, an account-local detection and response data plane with stable deployed resource names for upgrade compatibility.
- Made regional onboarding fail closed by default and verify the live EventBridge target after deployment; partial coverage now requires an explicit `--allow-partial`.
- Made CI install only hash-locked Python dependencies and block on Ruff formatting/linting, full-source mypy, Bandit, dependency audits, rule validation, and secret scanning.
- Switched Lambda packaging to an explicit source allowlist; CI now audits every generated ZIP and deploys that exact package instead of rebuilding it.
- Made ordinary CI deployments safe by default: simulated IR actions, X-Ray off, and Firehose archival data flow off unless explicitly enabled in a manual run.

### Added
- Independently versioned reusable detection lists with exact/CIDR matching, dedicated DynamoDB storage and `/lists` CRUD, CLI/MCP management, fail-closed evaluator caching, and list-version attribution on detections.
- Multi-action incident response through `response_actions`: rules can run up to ten ordered modules, map each module's fixed target keys to triggering-event fields, and retain separate rollback action IDs in the existing IR-actions table.
- Generic REST API access in the Core CLI with safe relative paths, encoded
  query parameters, JSON file/stdin bodies, and nonzero HTTP error handling;
  multi-installation orchestration now lives in the separate `opencdr-deploy`
  project.
- Reversible `standard`/`hardened` resource security profiles. Hardened mode enables DynamoDB deletion protection, CloudFormation retain/update-replace policies, and source-scoped application DLQ use without changing API exposure, enabling backups, or creating customer-account security services.
- Optional `archiveEnabled` deployment flag, disabled by default, with CI-aware verification and an explicit warning that DynamoDB TTL remains active while archival is disabled.
- Optional `xrayEnabled` deployment parameter, disabled by default. Setting it to `true` enables Lambda/API Gateway active tracing and boto3 SDK instrumentation while CloudWatch logs, EMF metrics, alarms, and dashboards remain always on.
- Versioned management contract covering the release manifest, `/status` identity response, declarative configuration bundles, and a fleet-facing alert envelope.
- Regional forwarding DLQs, explicit retry settings, delivery-failure alarms, and source-scoped EventBridge role trust.
- Deployment-contract tests for CloudFormation description limits, event-pattern parity, regional delivery resources, and manifest/version consistency.
- Direct rollbackHandler error, rollback-domain failure, and rollback-DLQ alarms, including a new `ResponderRollbackFailures` metric.

## [0.2.0] — 2026-08-12

### Fixed
- Updated internal and public CI catalog validation to recognize independent `lists/` resources and validate both rules and lists through the same runtime contracts used by the API.
- **Correlation-triggered `disable_user` was a silent no-op for every one of the 4 shipped correlation rules** since correlation rules were introduced — `responder._extract_user_name` never handled a correlation alert's shape (`group_value`/`primary_signal.actor.user_name`), only a signal alert's. Same bug fixed in four sibling extractors (role/bucket/bucket+key/instance-id) via a shared `_request_parameters()` helper. Found by an external audit, independently re-verified, and proven by a new golden-path integration test that fails against the old code and passes against the fix.
- Response-triggering rules didn't distinguish a denied API call from a successful one — added an `api.error_code not_exists` guard to the affected rules plus a structural backstop in `responder.py` independent of rule conditions.
- Rule-operator parity restored between the engine, the API, and the docs: `wildcard`/`in_list`/`not_in_list` are now accepted by the rule-mutation API (previously engine-only, unreachable except via `load_rules.sh`); `not_prefix`/`not_suffix` are now implemented in the engine (previously API-accepted but silently never matched); `rule_kind="list"` is now reachable through the `/rules` API.
- A pre-existing `UnboundLocalError` risk in access-key extraction, and a stale doc comment claiming `GET /rules` was the only wired route.
- The org-wide deployment recipe granted `events:PutEvents` on the central EventBridge bus to any principal in the AWS Organization, not just the intended per-account forwarding mechanism — replaced with a scoped, per-account IAM role (`org-forwarding/`) only `events.amazonaws.com` can assume.
- `ArchiveBucket`'s `BucketName` mixed Serverless Framework's own variable syntax with an unwrapped CloudFormation pseudo-parameter (`${AWS::AccountId}`) in one bare string, resolving to a null bucket name and failing every real deploy — wrapped in `!Sub`. Caught on the first real deploy of this feature, not by any test.
- `post-deploy-check`'s archival-pipeline check used `--query "length(events)"` against a paginating AWS CLI call, which applies `--query` per page and can produce multi-line output — broke the check's numeric comparison and produced a false FAIL even when the archiver had, in fact, processed the canary. Fixed to a pagination-safe non-emptiness check.
- `ci.yml`'s synthetic rule-firing check, `scripts/test_deployed.sh`, and `scripts/opencdr.py`'s `test-deployed` command all hardcoded the legacy `signals-table` name — since the partition-key migration below means nothing writes there anymore, all three would have failed every run. Fixed to query `signals-table-v2`, and gave the two scripts a short retry loop instead of a single fixed sleep, since the write now goes through an SQS hop (`processor` → `signalWriter`) instead of a direct synchronous `PutItem`.

### Changed
- **Automated response is disarmed by default.** `DREDGE_DRY_RUN` now defaults to `true` (was `false`), and `scripts/load_rules.sh` now strips every rule's `response_module` unless `--with-response-modules` is passed. Both layers must be turned on deliberately for a matching detection to execute a real action.
- Signals, alerts, logs, and outbox now TTL out of DynamoDB after 90 days (`DYNAMODB_TTL_DAYS`) — safe because signals/alerts/logs are archived to S3 as Parquet first, via a new `archiver` Lambda + Kinesis Data Firehose + Glue Data Catalog, Hive-partitioned by `account/year/month/day/hour`. Outbox is TTL'd but not archived (delivery-tracking metadata, not investigative history).
- SBOM generation moved from a 90-day `ci.yml` artifact on every push to a permanent asset attached to each tagged release.
- **`signals-table`/`logs-table` replaced by `signals-table-v2`/`logs-table-v2`.** Both previously used a bare, low-cardinality HASH key (`severity`: 6 values, `service`: 8 values) — every write for one value shared a single DynamoDB partition, with a real throughput ceiling independent of pay-per-request billing (a burst of correlated signals during an actual incident, or steady org-wide log volume, could throttle). Replaced with a day-bucketed composite key (`severity_bucket`/`service_bucket`, e.g. `"HIGH#2026-08-12"`, a new attribute — `severity`/`service` themselves stay untouched for the S3/Parquet archive) that self-scales with zero per-deployment tuning. `GET /signals`/`GET /logs`' `severity`/`service` selectors now default to the last 7 days (`date_from`/`date_to`, max 31 days) instead of unbounded history — `event_id`/`category`/`event_name` GSI selectors are unaffected. The original bare-key tables (deployed alongside these during cutover, per CloudFormation's inability to change a table's `KeySchema` in place) have since been fully decommissioned — the `?include_legacy=true` opt-in read and `*_LEGACY`/`*_MIGRATION_CUTOVER_AT` env vars that existed only to bridge that transition window are gone too. See [Architecture](docs/architecture.md#dynamodb-tables).
- `processor`'s signal write is now an SQS enqueue (to a new `signalWriter` Lambda) instead of a direct, synchronous `PutItem` — decouples burst writes from `signals-table-v2`'s partition-key ceiling. `alerter`'s correlation-signal writeback (already fire-and-forget) is routed through the same queue.

### Added
- Cross-region CloudTrail/GuardDuty event forwarding (`region-forwarding/`) — an account operating in more than one region was previously silently blind outside its deployment region.
- Org-wide account forwarding (`org-forwarding/`) for AWS Organizations setups routing every member account's events into a central security account.
- `archiver` Lambda + S3/Parquet archival pipeline, with `post-deploy-check` now verifying both TTL configuration and the archival pipeline against the real deployed stack. The three archive Glue tables use Athena partition projection (`storage.location.template`) so new hourly partitions are queryable immediately — no crawler, no `MSCK REPAIR TABLE` step.
- Green ("remediation succeeded") Slack/Discord/email notifications, distinct from detection alerts.
- Cost tracking: resource tags, `scripts/cost_report.sh`, and an `AWS::Budgets::Budget` alert.
- Full X-Ray tracing of downstream `boto3` calls (previously only the Lambda invocation boundary was traced).
- Optional `LOGS_MIN_LEVEL_TO_STORE` to narrow what's persisted to the logs table, independent of archival.
- A mechanism to promote tagged releases from this repo to the public `dbnz-io/opencdr` repo via a reviewed PR, not a direct push.
- `signalWriter` Lambda + `signals-write-queue`/`signals-write-dlq` — the SQS write-buffer for `signals-table-v2`, absorbing burst writes a hot partition can't sustain synchronously. A `logs-table-v2` throttling alarm as the tripwire for whether logs-table needs the same write-buffer treatment someday (deliberately not given one now — it already degrades gracefully via `logger.py`'s CloudWatch-first write).

### Security
- The IR role (`docs/ir-role-permissions.json` / `OpencdrIrRole`) no longer grants `iam:UpdateAssumeRolePolicy` — it was a full account-wide privilege-escalation primitive (rewrite any role's trust policy, not just the one being contained) that `disable_role`'s detach-all-policies step already makes unnecessary for real containment. S3 bucket/object containment permissions (`PutBucketAcl`, `PutObjectAcl`, etc.) now use scoped `arn:aws:s3:::*` / `arn:aws:s3:::*/*` resources instead of a bare `"*"`.
- Public repo (`dbnz-io/opencdr`): branch protection, secret scanning + push protection, CodeQL, Dependabot security updates, Actions restricted to verified publishers, all actions pinned to commit SHA.
- This repo: Dependabot security updates, Actions restricted to verified publishers, all actions pinned to commit SHA (branch protection and native secret scanning need a paid GitHub plan for private repos, not available on the current plan).

## [0.1.0] — 2026-04-02

### Added
- 6 Lambda functions: processor, alerter, publisher, notifier, responder, api
- 19 signal detection rules covering initial access, persistence, privilege escalation, defense evasion, credential access, and exfiltration
- 4 correlation rules: console login brute force, IAM activity burst, defense evasion burst, credential harvesting
- 7 automated incident response modules: disable_user, delete_user, disable_access_key, disable_role, block_s3_public_access, block_s3_bucket_public_access, isolate_ec2_instances
- Outbox pattern for at-least-once SQS delivery
- Slack and Discord notification support with severity routing
- REST API with API key auth, cursor pagination
- `scripts/load_rules.sh` — seed rules into DynamoDB
- `scripts/test_rules_local.py` — test rules without AWS
- `scripts/test_deployed.sh` — integration test against deployed stack
- Per-function least-privilege IAM roles
- DLQs for both SQS queues and DynamoDB stream failures
- OCSF-aligned event normalization for CloudTrail and GuardDuty

### Infrastructure
- DynamoDB pay-per-request on all 6 tables
- EventBridge rules covering CloudTrail (IAM, S3, EC2, RDS, Secrets Manager, SSM, Lambda, CloudTrail, GuardDuty, Config, Security Hub) and GuardDuty findings
- API Gateway with API key auth, 10k/month quota, 100 RPS throttle

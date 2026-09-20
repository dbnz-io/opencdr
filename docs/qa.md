# Automated QA

Run from a checkout with the detection-rules submodule initialized:

```bash
git submodule update --init --recursive
python -m pip install -r requirements-dev.txt
python scripts/qa.py
```

Use the project's virtual environment (for example, `.venv/bin/python scripts/qa.py`).
Python 3.11 and 3.12 are tested by CI. No AWS credentials, deployment, Docker,
notification accounts, or running server are needed. Every journey gets fresh Moto
resources and the shared test fixture rejects real network connections. Remediation SDK calls
are replaced with deterministic results; the suite never disables a real user.

The default command runs all tests, including existing CLI, MCP, security,
notification-channel, infrastructure-contract, and response-module tests. The new
`tests/qa` suite additionally connects real handlers through DynamoDB, Streams, SQS,
SNS, API Gateway key lookup, and SSM service emulation. Its table keys and indexes
come directly from `serverless.yml`. It consumes actual serialized queue messages
and stream images emitted by the emulator, invoking downstream handlers explicitly.

| Journey | Assertions |
| --- | --- |
| CloudTrail and GuardDuty detection | Create a shipped rule via API, ingest a fresh event, write and query the signal, publish the alert, deliver the email payload to an SNS/SQS test mailbox |
| Duplicate delivery | Replayed signal writes, publisher stream events, and notification messages do not create duplicate stored signals or notifications |
| Rule lifecycle | Create/read/update/delete, duplicate-create rejection, optimistic concurrency, disabled-rule behavior, unknown-key denial |
| Negative ingestion | Unmatched and unsupported events do not generate signals or outbox records |
| Correlation | Multiple recent signals trigger one stored alert and durable outbox; correlation write-back does not recurse |
| Response and rollback | Correct user reaches the remediation SDK boundary, durable claims suppress replay, API queues rollback, action status and requester audit persist, rollback notification is outboxed |
| Notification outage | Missing SNS topic causes a retryable batch failure; restoring it permits successful delivery |
| Partial signal batch | A valid signal is stored while an invalid signal is reported for retry |
| Partial publisher fan-out | A missing response queue preserves the successful notification checkpoint; retry delivers only the remaining destination |
| Archival boundary | Stored signal stream becomes a Firehose record preserving identity and raw payload; partial rejection raises for retry |

## Reports and CI

```bash
python scripts/qa.py --integration-only
python scripts/qa.py --coverage
python scripts/qa.py --output-dir /tmp/opencdr-qa
```

Each run overwrites `report.html`, `summary.json`, `junit.xml`, and `run.log` in
`artifacts/qa` (gitignored by default). HTML lists each test, duration, outcome, and
failure message; the log contains detailed pytest output. The command returns
nonzero for failures, errors, skipped tests, empty collection, or missing/invalid
JUnit output. A skipped test is not treated as proof the app works. `--coverage`
also generates `coverage.xml` at the repository root.

CI's existing Python matrix runs this same full QA command before deployment and
uploads the report directory on success or failure. Download the corresponding
`qa-python-*` artifact and open `report.html` locally.

## Scope

This is a deterministic automated QA suite, not a guarantee that every possible
input works. It tests backend application behavior locally. OpenCDR has no browser
frontend in this repository. AWS services are emulated, Lambda triggers are driven
by the harness, the remediation SDK is substituted, and Firehose delivery is
captured at the transport boundary. Real IAM policies, API Gateway HTTP/API-key
validation, EventBridge routing, deployment configuration, timing/concurrency,
third-party notification reachability, and final Firehose-to-S3 delivery require
separate deployed checks. Handler-level key scope checks are covered here;
API Gateway itself is not exercised over HTTP.

Existing post-deploy CI checks cover portions of that live infrastructure. Do not
interpret the local QA report as a live deployment health check. The older
`scripts/test_deployed.sh` replays shipped events into the configured deployment;
it can trigger the deployment's enabled notification/response rules.

## Extending coverage

Add a named scenario in `tests/qa/test_journeys.py`. Use the `app` fixture to create
rules/settings through the API, send fresh events through `app.ingest`, inspect
stored results through the API or emulator, and consume actual queue/stream
payloads. Assert observable outcomes, including final storage/delivery state;
HTTP 200 alone is insufficient because some handlers log errors and acknowledge
the batch. Keep business logic, repositories, and handlers real. Replace only
external effects that Moto cannot safely model. Existing focused unit tests remain
useful for individual operators, notification providers, and error branches.

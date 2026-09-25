# OpenCDR Core management contract

Contract version `1.0.0` is the narrow boundary between an account-local OpenCDR Core deployment and an optional fleet manager. Contract changes follow semantic versioning: additive optional fields are minor changes; removing or changing required fields is a major change.

## Release manifest

[`management/release-manifest.json`](../management/release-manifest.json) is the source of truth for product version, contract version, deployment model, and schema locations. Release automation must replace development versions with the immutable release version and publish this file alongside deployment artifacts.

## Health and identity

`GET /status` returns HTTP 200 when the API Lambda is live. Its stable fields are:

- `status`, always `ok` for a successful response;
- `product`, always `OpenCDR Core`;
- `core_version` and `management_contract_version`;
- `deployment.stage`, `deployment.account_id`, and `deployment.home_region`;
- `capabilities`, used for feature negotiation;
- `time` and `request_id` for freshness and tracing.

This is a liveness and identity endpoint, not proof that every regional collector is delivering. Fleet must also inspect the regional CloudFormation stacks, EventBridge targets, and DLQs. The regional setup command performs the same live target verification immediately after deployment.

## Configuration bundles

[`configuration-bundle.schema.json`](../management/schemas/configuration-bundle.schema.json) describes desired rules and settings for one Core. Application uses the existing `/rules` and `/settings/{setting_id}` APIs. Fleet must:

1. compare `minimum_core_version` with `/status`;
2. validate the bundle before making writes;
3. use `expected_rev` for optimistic concurrency;
4. apply rule and settings records independently and report partial failure;
5. never place plaintext secrets in a persisted bundle—use the existing settings secret references.

Bundles are declarative but applying a bundle is not a cross-record transaction. Fleet owns reconciliation and retries.

A conforming example is available at [`management/examples/configuration-bundle.example.json`](../management/examples/configuration-bundle.example.json).

## Alert envelope

[`alert.schema.json`](../management/schemas/alert.schema.json) defines the transport-neutral envelope Fleet may ingest. `payload` retains the complete Core signal or correlation alert while the envelope provides stable routing and tenancy fields. The top-level deployment identity is authoritative; consumers must not infer tenancy from arbitrary fields inside `payload`.

The schema defines payload compatibility independently of transport. A future exporter may use SNS, EventBridge, or HTTPS without changing the envelope.

A conforming example is available at [`management/examples/alert.example.json`](../management/examples/alert.example.json).

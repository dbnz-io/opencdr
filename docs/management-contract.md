# OpenCDR Core management contract

Management contract version `2.0.0` is the narrow boundary between an account-local OpenCDR Core deployment and an optional fleet manager. Version 2 moves reusable lists from rule records into the independent `/lists` lifecycle. The detection-rule authoring and release sub-contract is independently versioned as `3.0.0`; it retains multi-action response target mappings and excludes list data from rule releases. Contract changes follow semantic versioning: additive optional fields are minor changes; removing or changing required fields is a major change.

## Detection-content lifecycle

`GET /rules/schema` publishes the supported kinds, operators, bounds, response modules, and evaluation modes. A manager must use `POST /rules/validate` and the side-effect-free `POST /rules/evaluate` before promotion. Candidate evaluation never sends notifications, executes response modules, or persists supplied fixtures.

An immutable rule release manifest contains its release identity, contract version, removal policy, and complete ordered signal/correlation rule desired state. `POST /rule-releases/plan` returns create, update, disable, delete, and unchanged operations. `POST /rule-releases/apply` validates the entire manifest before making revision-guarded writes, stamps source/release provenance, and advances the catalog generation. Reusable lists are promoted separately through `/lists`; rules retain stable `list_id` references.

`GET /rules/runtime-status` distinguishes durable storage from activation. It reports the stored catalog generation and whether both the signal and correlation evaluators have observed it. A fleet manager must show an accepted release as `propagating` until this endpoint reports `verified`.

Rollback uses the same release endpoint with an earlier complete manifest. It is exact convergence, not an upsert: managed content omitted from that earlier version follows the manifest removal policy. Unmanaged content is never removed by a release.

## Release manifest

[`management/release-manifest.json`](../management/release-manifest.json) is the source of truth for product version, contract version, deployment model, and schema locations. Release automation must replace development versions with the immutable release version and publish this file alongside deployment artifacts.

## Health and identity

`GET /status` returns HTTP 200 when the API Lambda is live. Its stable fields are:

- `status`, always `ok` for a successful response;
- `product`, always `OpenCDR Core`;
- `core_version` and `management_contract_version`;
- `security_profile`, either `standard` or `hardened`, describing only the
  protection applied to resources owned by the OpenCDR stack;
- `deployment.stage`, `deployment.account_id`, and `deployment.home_region`;
- `capabilities`, used for feature negotiation;
- `time` and `request_id` for freshness and tracing.

This is a liveness and identity endpoint, not proof that every regional collector is delivering. Fleet must also inspect the regional CloudFormation stacks, EventBridge targets, and DLQs. The regional setup command performs the same live target verification immediately after deployment.

## Configuration bundles

[`configuration-bundle.schema.json`](../management/schemas/configuration-bundle.schema.json) describes desired rules, reusable lists, and settings for one Core. Application uses `/rules`, `/lists`, and `/settings/{setting_id}`. Fleet must:

1. compare `minimum_core_version` with `/status`;
2. validate the bundle before making writes;
3. use `expected_rev` for optimistic concurrency;
4. apply list, rule, and settings records independently and report partial failure;
5. never place plaintext secrets in a persisted bundle—use the existing settings secret references.

Version 1 configuration bundles may contain `rule_kind=list`; migrate those entries to the version 2 top-level `lists` array before applying them to this API. New detection-content automation should combine independently promoted lists with rule releases, which add whole-manifest rule validation, exact removal semantics, provenance, and evaluator verification. Individual DynamoDB writes are not a cross-record transaction; Fleet owns retry/reconciliation after a partial infrastructure failure.

A conforming example is available at [`management/examples/configuration-bundle.example.json`](../management/examples/configuration-bundle.example.json).

## Alert envelope

[`alert.schema.json`](../management/schemas/alert.schema.json) defines the transport-neutral envelope Fleet may ingest. `payload` retains the complete Core signal or correlation alert while the envelope provides stable routing and tenancy fields. The top-level deployment identity is authoritative; consumers must not infer tenancy from arbitrary fields inside `payload`.

The schema defines payload compatibility independently of transport. A future exporter may use SNS, EventBridge, or HTTPS without changing the envelope.

A conforming example is available at [`management/examples/alert.example.json`](../management/examples/alert.example.json).

# Production readiness roadmap

This roadmap separates controls owned by OpenCDR Core from controls owned by the
external production-promotion repository. A production deployment is approved only
when both sides satisfy their gates.

## P0 — repository and build integrity

- [x] Stop tracking generated `.serverless/` and `.requirements.zip` artifacts.
- [x] Exclude local credentials, environment files, repository metadata, caches,
  and generated build output from Lambda packages.
- [x] Replace the package denylist with an explicit `src/**` allowlist, inspect
  every generated Lambda ZIP before deployment, and deploy that exact package.
- [x] Remove the obsolete `serverless-python-requirements` plugin now built into
  Serverless Framework v4.
- [x] Upgrade and lock Serverless; require a clean `npm audit` result.
- [x] Maintain direct Python inputs in `requirements.in` and
  `requirements-dev.in`; deploy and test from generated, version- and hash-locked
  requirements files.
- [x] Pin Dredge to both an immutable source commit and the source archive SHA-256.
- [x] Audit that exact Dredge source: 948 upstream tests pass, Bandit reports no
  medium/high findings, and the only Gitleaks match is the documentation phrase
  "Kubernetes Events API search" rather than a credential.
- [x] Rewrite private repository history to remove `.opencdr.json`, `.serverless/`,
  `.requirements.zip`, and the accidentally tracked `node_modules/` tree after
  creating a verified offline recovery bundle. Clone owners must re-clone or reset
  to the rewritten history after the coordinated force-push.
- [x] Verify the packaged historical API key against the affected API Gateway
  account and region. It matches none of the live keys, so no live key required
  rotation or an SSM update.

## Deployer-owned — management-plane exposure

This is intentionally not a Core release blocker. OpenCDR supplies API keys,
scopes, throttling, and secure secret storage; the deploying organization owns the
identity and network boundary appropriate to its callers and exposure model.

API keys remain useful for metering and coarse client identification, but are not
the identity boundary for production. The recommended target is:

1. Require AWS IAM/SigV4 authorization on every management route. Give each
   control-plane workload or operator role only the `execute-api:Invoke` routes it
   needs.
2. Add an API Gateway resource policy restricting invocation to approved AWS
   accounts, organizations, roles, or VPC endpoints. Use a private REST API when all
   callers can reach it through private AWS networking; otherwise retain the
   regional endpoint with the restrictive resource policy.
3. Keep the existing application scopes as defense in depth during migration, but
   stop issuing the legacy all-scopes bare key and rotate existing broad keys.
4. Update the CLI, MCP server, and external control plane to sign requests with
   short-lived AWS credentials. No long-lived AWS access keys should be introduced.
5. Log caller ARN/account and route authorization decisions, and alarm on denied or
   anomalous management calls.

Tradeoff: IAM/SigV4 is a strong fit for AWS-hosted automation and avoids another
credential store, but local/non-AWS clients need an SSO-backed credential flow and
request signing. A JWT/OIDC Lambda authorizer is the alternative when human and
non-AWS clients dominate, at the cost of operating an identity provider and
authorizer cache/revocation behavior.

## Deployer-owned — recovery objectives and account-level protection

This is intentionally not implemented as unconditional Core infrastructure. The
`hardened` feature flag only strengthens resources already owned by OpenCDR and
stays reversible; it does not add backup services, customer KMS keys, Object Lock,
or account-level security products. The deployer chooses those controls, their
cost, and their operational procedures.

- Add `DeletionPolicy: Retain` and `UpdateReplacePolicy: Retain` to configuration,
  audit, and investigative DynamoDB tables.
- Enable DynamoDB point-in-time recovery for detection rules, settings, IR role
  mappings, IR actions, signals, alerts, and logs. Decide separately whether the
  transient outbox and delivery-state tables need PITR.
- Retain and version the archive bucket, define a customer-approved lifecycle, and
  decide whether AWS-managed encryption is sufficient or a customer-managed KMS key
  is required.
- Define RPO/RTO, backup ownership, restore access, and quarterly restore tests.
- Add infrastructure tests that prevent removal of retention/PITR from protected
  resources.

Tradeoffs: PITR and retained resources add ongoing storage/backup cost; retained
named resources make intentional teardown and clean redeployment more procedural;
customer-managed KMS keys add policy, rotation, and disaster-recovery dependencies.
Those costs are appropriate for configuration and incident-response audit records.

## P1 — drift and production promotion

- [x] Filter only the confirmed API Gateway generated-CORS normalization from the
  development drift check; fail on every other difference.
- [ ] Run the same drift filter in the external production-pipeline repository,
  using a production read-only OIDC role and the production stack name/region.
- [ ] Promote an immutable artifact digest from a successful staging deployment;
  do not rebuild dependencies during production promotion.
- [ ] Require an environment approval, change record, pre-deploy drift check,
  CloudFormation change-set review, post-deploy synthetic checks, and an explicit
  rollback decision window in the production repository.
- [ ] Record source commit, dependency-lock digest, artifact digest, CloudFormation
  template digest, stage, account, region, approver, and deployment result.

The production repository owns deployment credentials and approvals. This Core
repository owns source tests, lockfiles, package-safety checks, drift classification,
and the artifact contract consumed by that pipeline.

## P1 — live validation

- Exercise DLQ redrive and replay paths in a dedicated staging account.
- Verify final Firehose-to-S3 Parquet delivery and Athena queries, not only the
  Lambda-to-Firehose boundary.
- Measure throughput, throttling, concurrency, latency, and cost at expected and
  burst event rates.
- Validate every enabled notification integration and its failure/recovery path.
- Validate every enabled region and cross-account IR trust path.
- Run response modules in dry-run first, then approve live modules individually;
  document the kill switch and rollback drill.

## P2 — quality and observability

- [x] Make Ruff, type checking, Python dependency audit, npm audit, and source/archive
  secret scanning blocking CI gates.
- [x] Reconcile documentation/resource counts and add direct error alarms for any
  function not adequately covered by a DLQ/lag alarm.
- [x] Add a package-content test that opens the produced Lambda ZIP and rejects secret
  filenames and unexpected top-level paths before deployment.

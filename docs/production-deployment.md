# Production deployment responsibilities

OpenCDR supplies deployable infrastructure and secure defaults where they can be
chosen without knowing the customer's operating model. A successful
`serverless deploy` is **not** by itself a production-readiness decision. The AWS
account owner or deployer remains responsible for choosing and validating the
identity boundary, network boundary, retention policy, recovery objectives, and
production promotion process for that environment.

This page is the production gate for an OpenCDR installation. It describes what
the repository currently provides, what the deployer must add, and the evidence
that should exist before production traffic is enabled.

`securityProfile=hardened` can apply reversible deletion resistance and stricter
DLQ use to resources owned by the OpenCDR stack; see
[Resource security profiles](security-profiles.md). It does not change the API or
fulfil any customer-owned account, backup, recovery, or monitoring responsibility
described below.

## Current baseline and deliberate gaps

| Area | Supplied by this repository | Deployer-owned production decision |
|---|---|---|
| Management API | Route-scoped API keys, usage-plan throttling, and keys stored in SSM SecureString by CI | A real identity boundary such as IAM/SigV4 or OIDC/JWT, plus a restrictive API Gateway resource policy and preferably a network boundary |
| Deployment identity | GitHub OIDC bootstrap role; no long-lived AWS keys are required by CI | Separate production account/role, protected environment approval, least-privilege trust conditions, and an immutable-artifact promotion pipeline |
| Stack safety | CI enables termination protection for the development stack; development drift monitoring is included | Production termination protection, pre-deploy and scheduled drift checks, change-set review, and an intentional teardown procedure |
| Ingestion state | The ingestion DynamoDB table has PITR and retain policies; the ingestion S3 bucket has retain policies, versioning, encryption, public-access blocking, and a 90-day lifecycle | Confirm that 90 days meets the customer's retry/evidence requirements and select KMS/Object Lock controls if required |
| Core state | Encryption and application TTL/archive behavior; optional hardened deletion protection and CloudFormation retain policies | Classifying recoverable records, backups/PITR, RPO/RTO, and restoration testing |
| Investigation archive | Optional data flow (`archiveEnabled`, default `false`) into an encrypted, private, TLS-only S3 bucket; hardened mode adds CloudFormation retain policies | Decide whether archival is required before relying on TTL; define backup, versioning, lifecycle/retention, and restore/query policy outside the profile |

Under the default `standard` profile, `IngestionTable` and `IngestionBucket` retain
their existing stronger retain policies; `IngestionTable` has point-in-time
recovery and `IngestionBucket` has versioning. The `hardened` profile extends
deletion protection and CloudFormation retention to the remaining OpenCDR-owned
tables and archive bucket. It does not enable PITR, versioning, or backups for
them—those remain deployer decisions.

## 1. Establish the production identity and network boundary

API keys identify a usage-plan consumer and support OpenCDR's coarse application
scopes. They are not strong production authentication: a copied key can be replayed
until revoked and does not establish a workload or human identity.

Inventory every management caller before changing authorization:

| Caller | Preferred production identity |
|---|---|
| AWS-hosted control plane or automation | A dedicated IAM role using short-lived credentials and SigV4 |
| Operator using `scripts/opencdr.py` | AWS IAM Identity Center/SSO credentials and SigV4, or the organization's OIDC login flow |
| MCP server | A dedicated workload/operator role with short-lived credentials; never a shared long-lived access key |
| External non-AWS service | OIDC/JWT authorizer, or a controlled AWS-hosted broker that signs requests |
| Emergency access | A monitored, time-bound break-glass role with an approval and audit trail |

For an AWS-centric installation, the recommended target is:

1. Set API Gateway management methods to IAM authorization and sign requests with
   SigV4.
2. Grant each role only the required `execute-api:Invoke` routes and methods.
3. Add an API Gateway resource policy restricted to approved accounts,
   organization IDs, roles, or VPC endpoints.
4. Use a private REST API and interface VPC endpoint when every caller has private
   AWS network access. Otherwise retain a regional endpoint with the restrictive
   resource policy and the customer's edge/WAF controls.
5. Log the caller ARN/account and authorization failures, and alarm on unexpected
   principals or repeated denials.

During migration, API Gateway can require both IAM authorization and an API key.
That preserves usage-plan metering and OpenCDR's existing key scopes while IAM
becomes the actual identity boundary. Migrate the CLI, MCP server, control plane,
and operator runbooks before removing compatibility keys. Test every caller in a
non-production stage because enabling IAM is a breaking change for unsigned
requests.

If the deployment primarily serves humans or non-AWS workloads, an OIDC/JWT
authorizer may be a better boundary. In that case the deployer owns the identity
provider, audience/issuer validation, group-to-scope mapping, revocation behavior,
and authorizer-cache policy.

## 2. Classify state before adding blanket retention

Not every table has the same recovery value. Record the classification explicitly:

| State class | Typical resources | Recommended starting position |
|---|---|---|
| Configuration | Detection rules, settings, IR account-role mappings | PITR plus `DeletionPolicy` and `UpdateReplacePolicy` set to `Retain` |
| Security/audit state | IR actions, alerts, signals, logs | PITR when fast live-table recovery is required; retain policies; preserve the S3 archive independently |
| Delivery/transient state | Outbox and delivery-state tables | Decide from recovery semantics; restoring expired or already-delivered work can create duplicates |
| Raw ingestion/retry state | Ingestion table and bucket | Existing protection is enabled; validate lifecycle length and replay procedure |
| Long-term investigation archive | Archive S3 bucket | Retain policies, versioning, customer-approved lifecycle, and optional Object Lock |

PITR and retained resources add cost. Retained named resources also make teardown
and replacement procedural: after a stack deletion, a future deployment cannot
silently create another resource with the same physical name. That friction is
intentional for production data, but it requires a runbook for importing, renaming,
or explicitly deleting retained resources.

CloudFormation retain policies protect against stack deletion and replacement;
they do not stop a principal with direct DynamoDB or S3 deletion permission. Limit
those permissions separately with IAM, permission boundaries, or organization SCPs.

For S3, enable versioning before production data arrives. Add a lifecycle that
matches legal and investigation requirements, including noncurrent versions. If
immutability is required, decide on S3 Object Lock before bucket creation—Object
Lock and its governance/compliance retention model need deliberate account-level
planning and should not be enabled casually.

## 3. Define recovery objectives and prove restoration

The deployer must publish an approved RPO and RTO for each state class. Do not copy
targets from another installation: event volume, compliance obligations, Firehose
buffering, and operator coverage all affect what is achievable.

A recovery plan should name:

- the owner authorized to initiate a restore;
- the maximum acceptable data loss (RPO) and service-recovery time (RTO);
- the DynamoDB PITR window and S3 retention/lifecycle;
- the account and KMS permissions needed during an incident;
- how restored configuration is reconciled with SSM-held secrets;
- how producers are paused or redirected to avoid split-brain writes;
- the validation and cutover criteria, and the rollback from the recovery itself.

Automate a restore exercise in an isolated account or under new physical resource
names. At minimum, the exercise should:

1. restore each protected DynamoDB class to a new table;
2. validate key schemas, indexes, encryption, item counts, and representative
   records without printing secret values;
3. verify archived S3 objects and an Athena query over a known partition;
4. start a disposable OpenCDR stage against restored configuration or validate an
   equivalent import path;
5. record actual RPO/RTO, evidence, failures, and cleanup; and
6. run at least quarterly and after material schema or infrastructure changes.

A backup that has never been restored is not production evidence.

## 4. Promote, do not rebuild, for production

Production deployment credentials and approvals belong in the customer's protected
production pipeline, not in this development repository. The production pipeline
should consume the exact artifact digest tested in staging rather than running a
fresh dependency build.

Require all of the following:

- a protected production environment and explicit approver;
- a source commit, dependency-lock digest, artifact digest, and generated-template
  digest recorded with the deployment;
- a pre-deploy drift check using a read-only production OIDC role;
- CloudFormation change-set review, including replacements and IAM changes;
- termination protection re-enabled after deployment;
- post-deploy authentication, ingestion, notification, archive, and alarm checks;
- a rollback decision window with a named owner; and
- scheduled production drift monitoring using the same exact-difference classifier
  as development.

The production pipeline repository owns these controls because it owns the
production account trust, environment approvals, and release evidence. OpenCDR Core
owns the source tests, dependency locks, package-safety checks, and drift
classification that pipeline consumes.

## Go-live evidence checklist

Do not call an installation production-ready until the deployment owner can attach
evidence for every applicable item:

- [ ] Every management caller has an approved identity and least-privilege route access.
- [ ] API Gateway has an approved resource/network policy; API keys are not the sole identity boundary.
- [ ] Broad compatibility keys have an owner, expiry/rotation plan, and monitored use.
- [ ] Production deploys use a separate short-lived role and protected approval environment.
- [ ] The promoted artifact and template digests match the staging-tested versions.
- [ ] Production termination protection and scheduled/pre-deploy drift checks are enabled.
- [ ] Every state resource has a documented retain/PITR/versioning decision.
- [ ] Archive lifecycle, KMS, immutability, and legal-retention decisions are approved.
- [ ] RPO/RTO targets and backup/restore ownership are documented.
- [ ] A restore exercise has passed and its measured recovery time is within target.
- [ ] Alarm delivery, DLQ replay, notification failure, multi-region coverage, and IR kill switches have been tested.
- [ ] The intentional teardown and retained-resource recovery procedures are documented.

## Related pages

- [Deployment](deployment.md) — development/manual deployment and CI behavior
- [Complete Setup Guide](setup.md) — ordered setup sequence
- [Security](security.md) — current IAM, API-key, and secrets model
- [Stack protection](stack-protection.md) — termination protection and drift detection
- [Data archival](data-archival.md) — live-table TTL and the S3/Parquet archive
- [Production readiness roadmap](production-readiness-roadmap.md) — repository and external-pipeline implementation work

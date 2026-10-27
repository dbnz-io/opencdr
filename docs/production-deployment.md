# Customer production deployment decisions

OpenCDR Core is production-ready within its documented product boundary. It
supplies deployable infrastructure and secure defaults wherever those controls can
be selected without knowing the customer's operating model. See the [security
shared-responsibility model](shared-responsibility.md) for the authoritative
boundary.

This page is implementation guidance for optional or environment-specific controls
owned by the AWS account owner or deployer. Identity, network, retention, recovery,
and promotion choices are not unresolved OpenCDR bugs: their correct configuration
depends on customer identities, topology, legal obligations, recovery targets,
budget, and production account boundary.

`securityProfile=hardened` can apply reversible deletion resistance and stricter
DLQ use to resources owned by the OpenCDR stack; see
[Resource security profiles](security-profiles.md). It does not change the API or
fulfil any customer-owned account, backup, recovery, or monitoring responsibility
described below.

## Supplied baseline and customer decisions

| Area | Supplied by this repository | Customer risk decision or optional additional control |
|---|---|---|
| Management API | Route-scoped API keys, usage-plan throttling, and keys stored in SSM SecureString by CI | Decide whether the supplied bearer-key boundary matches the exposure model or whether IAM/SigV4, OIDC/JWT, a resource policy, WAF, or private networking is warranted |
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
scopes. As with every bearer credential, a copied key can be replayed until revoked
and does not establish a workload or human identity. The customer decides whether
that property is acceptable for its exposure model or whether an identity-aware
boundary is required.

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

Customers requiring recovery of overwritten archive objects should enable S3
versioning before production data arrives and add a lifecycle matching their legal
and investigation requirements, including noncurrent versions. If immutability is
required, decide on S3 Object Lock before bucket creation—Object Lock and its
governance/compliance retention model need deliberate account-level planning and
should not be enabled casually.

## 3. Define recovery objectives and prove restoration

When recoverability is part of the customer's requirements, the deployer should
publish an approved RPO and RTO for each applicable state class. Do not copy targets
from another installation: event volume, compliance obligations, Firehose buffering,
and operator coverage all affect what is achievable. A customer may instead accept
loss of a transient or reproducible state class and document that decision.

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
production pipeline, not in the Core source repository. This separation does not
reduce Core's production readiness; it prevents OpenCDR from owning credentials or
approvals for a customer's AWS account. Customers requiring immutable promotion
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

## Customer installation acceptance checklist

Use this checklist according to the customer's threat model and obligations. An
unchecked optional item is not by itself an OpenCDR defect or proof that Core is
not production-ready; it records a control the deployment owner has accepted,
implemented elsewhere, or determined is not applicable:

- [ ] The accepted identity and route-access model for every management caller is recorded.
- [ ] The customer has accepted the API exposure model or selected additional resource/network controls.
- [ ] Issued API keys have an owner and an appropriate rotation/monitoring decision.
- [ ] The production deployment role, approval, and change-evidence model is recorded.
- [ ] The customer has decided whether exact staged-artifact promotion is required.
- [ ] Termination-protection and drift-monitoring decisions are recorded.
- [ ] Every state resource has an explicit retain/PITR/versioning or accepted-loss decision.
- [ ] Archive lifecycle, encryption, immutability, and legal-retention applicability is recorded.
- [ ] Applicable RPO/RTO targets and backup/restore ownership are documented.
- [ ] Restore testing is performed when the customer relies on restoration as a control.
- [ ] Applicable alarm delivery, DLQ replay, notification, regional coverage, and IR controls have been tested.
- [ ] Teardown and retained-resource procedures exist when retention is enabled.

## Related pages

- [Deployment](deployment.md) — development/manual deployment and CI behavior
- [Complete Setup Guide](setup.md) — ordered setup sequence
- [Security](security.md) — current IAM, API-key, and secrets model
- [Stack protection](stack-protection.md) — termination protection and drift detection
- [Data archival](data-archival.md) — live-table TTL and the S3/Parquet archive
- [Production readiness roadmap](production-readiness-roadmap.md) — repository and external-pipeline implementation work
- [Security shared-responsibility model](shared-responsibility.md) — authoritative ownership and tradeoff boundary

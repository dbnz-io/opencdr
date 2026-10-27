# Security shared-responsibility model

OpenCDR Core is production-ready software within the product boundary described
here. It ships a deployable, tested AWS data plane with secure defaults, an
optional reversible `hardened` profile, package and dependency controls, runtime
observability, and documented operational procedures.

Production readiness of the software does not mean that OpenCDR can choose the
security policy of every AWS account in which it is installed. Identity providers,
network topology, retention obligations, recovery targets, enabled AWS regions,
and release approvals depend on the customer's environment. Those are deployment
decisions under the customer's side of the shared-responsibility model. Their
absence from the OpenCDR stack is intentional and is not an OpenCDR vulnerability
or an incomplete product feature.

## What OpenCDR secures

Every supported deployment includes:

- least-privilege, per-function IAM roles;
- encryption for DynamoDB, S3, and SQS resources;
- S3 public-access blocking, bucket-owner enforcement, and TLS-only access;
- API-key enforcement, route-level application scopes, throttling, and encrypted
  API-key storage;
- bounded retries, dead-letter queues, durable delivery controls, and operational
  alarms;
- explicit package allowlisting and generated-package credential checks;
- locked dependencies, source and dependency security checks, and a comprehensive
  automated test suite;
- safe defaults for automated incident response, including dry-run deployment and
  response-module stripping during ordinary rule loading; and
- an exact, versioned management contract and reproducible deployment artifacts.

OpenCDR also supplies optional controls for resources it owns:

| Control | Default | Opt-in behavior | Main tradeoff |
|---|---|---|---|
| `securityProfile` | `standard` | `hardened` enables DynamoDB deletion protection, CloudFormation retention for OpenCDR tables/buckets, and restricted DLQ redrive | Retained resources keep accruing storage cost and make intentional teardown more procedural |
| `archiveEnabled` | `false` | Streams signals, alerts, and logs to the managed S3/Parquet archive | Firehose/S3/Glue storage and request cost; retention still needs a customer policy |
| `xrayEnabled` | `false` | Enables active Lambda and API Gateway tracing | Additional trace ingestion/storage cost |
| Automated response | dry-run/unarmed | Rules may be loaded with response actions and the responder may be switched to live execution | Live actions can change or disable AWS resources and require customer approval and testing |

These flags can be changed later through a normal stack update. The documented
downgrade acknowledgement prevents an accidental move from `hardened` to
`standard`; none of these flags introduces Object Lock or another irreversible
retention mechanism.

## What the customer or deployment owner secures

The deployment owner chooses and operates controls that require knowledge or
authority OpenCDR cannot safely infer:

| Customer decision | Why OpenCDR does not choose it | Typical options and tradeoffs |
|---|---|---|
| Management API identity and exposure | OpenCDR cannot know whether callers are AWS workloads, workforce users, an external control plane, or private-network clients | Keep the supplied API-key boundary in a controlled environment, or add IAM/SigV4, OIDC/JWT, API Gateway resource policies, WAF, or private endpoints. Stronger identity/network restrictions improve assurance but add client migration, networking, and operating cost. |
| CloudTrail, GuardDuty, and region coverage | These are account-level services and only the customer knows which accounts and regions are in scope | Enable the required sources and install the supplied regional forwarder in every selected region. More regions increase EventBridge, SQS, logging, and operational cost. |
| Backup and recovery policy | RPO/RTO, legal retention, and acceptable replay behavior differ by state class and organization | Select PITR, S3 versioning, external backup, lifecycle rules, and restore exercises as appropriate. They add storage/backup cost and recovery procedures; restoring transient delivery state can also repeat work. |
| Customer-managed KMS, Object Lock, SCPs, GuardDuty, AWS Backup, and similar account controls | These require customer-owned keys, organization policy, compliance choices, or additional AWS services | Enable only where the customer's threat model or regulatory obligations justify their cost and operational constraints. They are intentionally outside `securityProfile=hardened`. |
| Production promotion and approvals | Production credentials, approvers, change records, and environment protections belong to the customer's delivery system | Promote the exact staged artifact through the customer's protected production repository. Stronger approval and evidence requirements add lead time but reduce unauthorized or unreviewed change risk. |
| Notification destinations and egress policy | Only the customer knows the approved Slack, Jira, webhook, and SIEM endpoints | Restrict destinations according to the customer's network and data-handling policy. Allowlisting reduces exfiltration risk but requires maintenance and can block alert delivery when endpoints change. |
| Live incident-response authority | The customer owns the affected AWS resources and change approvals | Keep dry-run, arm selected modules, or enable live response. Faster containment trades against the risk of an incorrect automated action. |

### Customer-selectable application policy

Some runtime policy switches deliberately preserve compatibility unless the
customer selects stricter behavior:

- `STRICT_RULE_VALIDATION=true` changes suspicious or unmatchable rule warnings
  into write-time rejection. This prevents questionable rules from being stored,
  but can reject legacy or customer-authored content that previously loaded with a
  warning.
- Notification URLs always require HTTPS and literal loopback/link-local addresses
  are always blocked. `NOTIFY_RESOLVE_HOSTS=true` adds hostname resolution,
  `NOTIFY_BLOCK_PRIVATE_IPS=true` blocks resolved private addresses,
  `NOTIFY_ALLOWED_HOSTS` supplies the customer allowlist, and
  `NOTIFY_ENFORCE_ALLOWLIST=true` turns allowlist warnings into blocking. DNS
  checks add lookup latency and failure modes; enforced allowlists require upkeep
  and can interrupt notifications after a legitimate endpoint change.

These are application policy inputs, not new services. A customer deployment layer
may pass them into the applicable Lambda environment when its threat model justifies
the tradeoff. OpenCDR cannot safely invent the customer's notification allowlist or
reject existing customer rule content without an explicit migration decision.

## Production use

A supported OpenCDR release may be deployed in production. The deployment owner
should evaluate the customer-owned decisions above and record which controls are
applicable. Choosing not to add an optional control is an accepted risk decision,
not automatically a failed deployment, provided it matches the customer's threat
model and obligations.

Staging and go-live checks validate the installation rather than compensate for an
unfinished product. OpenCDR provides local QA, post-deploy checks, synthetic-event
tools, drift classification, and regional-forwarding verification. The customer
runs the applicable checks in its real AWS accounts because only that environment
can prove IAM enforcement, EventBridge delivery, third-party notification reachability,
selected-region coverage, capacity, and final archive delivery.

When assessing OpenCDR, report a Core defect when a supplied control does not work
as documented, an unsafe default violates this boundary, or the product exposes a
vulnerability. Do not report a customer-owned identity, network, backup, retention,
or promotion choice as an unresolved Core bug merely because OpenCDR does not make
that choice on the customer's behalf.

## Related pages

- [Resource security profiles](security-profiles.md) — exact `standard` and `hardened` behavior
- [Production deployment decisions](production-deployment.md) — implementation guidance for customer-owned controls
- [Security](security.md) — application IAM, secrets, API scopes, and deliberate limitations
- [Deployment](deployment.md) — deployment flags, CI, and post-deploy procedures
- [QA](qa.md) — what automated and live validation prove

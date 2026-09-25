# OpenCDR Core

OpenCDR Core is the account-local detection and response data plane. One Core deployment owns one AWS account: it ingests that account's events, evaluates rules, stores its data, sends notifications, and performs incident response with local IAM authority.

The CloudFormation and Lambda resource names remain `opencdr-*` for upgrade compatibility. “Core” is the product boundary, not a breaking rename of deployed resources.

## Deployment topology

- Deploy the complete Serverless stack once in the account's chosen home region.
- Deploy `region-forwarding/cross-region-forwarder.yaml` in every other enabled region through `scripts/setup_region_forwarding.sh`.
- Regional collectors forward only within the same AWS account. They have an encrypted 14-day DLQ and explicit retry policy.
- A future fleet control plane may install, configure, and monitor Core, but Core's detection path never depends on that control plane being available.

OpenCDR Core deliberately does not discover AWS Organizations accounts or centrally ingest another account's raw events. The legacy `org-forwarding/` path remains for existing installations, but it is not the deployment model for new Core installations.

## Management surface

The stable integration boundary is documented in [Management contract](management-contract.md):

- `management/release-manifest.json` identifies the release and supported contract.
- `GET /status` reports product, version, deployment identity, and capabilities.
- `management/schemas/configuration-bundle.schema.json` describes declarative desired configuration.
- `management/schemas/alert.schema.json` describes normalized alert export.

Core remains independently operable through its REST API and `scripts/opencdr.py`; a fleet manager is an optional client of this surface.

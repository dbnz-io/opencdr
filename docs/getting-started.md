# Getting Started

## Prerequisites

- [Node.js](https://nodejs.org/) >= 18
- [Serverless Framework](https://www.serverless.com/) v3
- Python 3.11
- AWS credentials configured (`aws configure` or environment variables)
- `jq` (for the load/test scripts)

```bash
npm install -g serverless
npm install   # installs serverless-python-requirements and serverless-iam-roles-per-function
```

## Enable CloudTrail

OpenCDR receives events via EventBridge. CloudTrail management events are only delivered to EventBridge when CloudTrail is active in your account and region.

```bash
# Create a trail (one-time setup)
aws cloudtrail create-trail \
  --name opencdr-trail \
  --s3-bucket-name <your-log-bucket> \
  --is-multi-region-trail

# Start logging
aws cloudtrail start-logging --name opencdr-trail
```

Or enable it in the AWS Console under **CloudTrail → Trails → Create trail**. Management events (read + write) must be enabled.

!!! warning
    Without CloudTrail enabled, the processor Lambda will never receive events and no signals will be generated.

## Multi-Account (AWS Organizations)

For multi-account setups, route all CloudTrail and GuardDuty events from every member account into a single central EventBridge bus and deploy OpenCDR once in a dedicated security account.

```
Member Account A  ─┐
Member Account B  ─┼─► EventBridge cross-account rules ─► Central Security Account
Member Account C  ─┘                                         EventBridge default bus
                                                                      │
                                                             OpenCDR processor Lambda
```

**1. Enable an organization trail** in the management account:

```bash
aws cloudtrail create-trail \
  --name org-trail \
  --s3-bucket-name <your-log-bucket> \
  --is-organization-trail \
  --is-multi-region-trail
aws cloudtrail start-logging --name org-trail
```

**2. Allow member accounts to send events to the central bus.** In the central security account:

```bash
aws events put-permission \
  --action events:PutEvents \
  --principal "*" \
  --statement-id AllowOrgAccounts \
  --condition '{"Type":"StringEquals","Key":"aws:PrincipalOrgID","Value":"o-XXXXXXXXXX"}'
```

**3. Create a forwarding rule in each member account** (or deploy via CloudFormation StackSets):

```bash
aws events put-rule \
  --name forward-to-central-opencdr \
  --event-pattern '{"source":["aws.cloudtrail","aws.guardduty"]}' \
  --state ENABLED

aws events put-targets \
  --rule forward-to-central-opencdr \
  --targets '[{
    "Id": "CentralBus",
    "Arn": "arn:aws:events:<region>:<security-account-id>:event-bus/default",
    "RoleArn": "arn:aws:iam::<member-account-id>:role/EventBridgeForwardRole"
  }]'
```

**4. Deploy OpenCDR** in the central security account as normal. Signals will include the originating `aws_account_id` for triage.

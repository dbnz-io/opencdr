# Automated Incident Response

Set `response_module` on any rule to trigger an automated action when it fires.

## Response Modules

| Module | Action |
|---|---|
| `disable_user` | Disable all IAM access keys for the actor |
| `delete_user` | Delete the IAM user |
| `disable_access_key` | Disable a specific access key |
| `disable_role` | Attach a deny-all inline policy to the role |
| `block_s3_public_access` | Enable account-level S3 public access block |
| `block_s3_bucket_public_access` | Block public access on a specific bucket |
| `isolate_ec2_instances` | Replace instance security groups with an isolation group |

## Dry Run

Set `DREDGE_DRY_RUN=true` to simulate all IR actions without making changes:

```bash
serverless deploy --param="dredgeDryRun=true"
```

Or set the environment variable directly on the responder Lambda after deployment.

## Cross-Account Response

Set `OPENCDR_IR_ROLE_ARN` to a role ARN the responder Lambda can assume to perform IR actions in a different AWS account:

```bash
export OPENCDR_IR_ROLE_ARN=arn:aws:iam::<target-account-id>:role/OpenCDRResponderRole
```

The target role must trust the responder Lambda's execution role and have the necessary IAM/EC2/S3 permissions.

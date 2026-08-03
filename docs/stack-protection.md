# Stack protection and drift detection

OpenCDR's CloudFormation stack isn't just infrastructure — it defines the
IAM roles and permissions the `responder` Lambda uses to take destructive
containment actions in a client's AWS account (see
[`ir-role.md`](ir-role.md)). An accidental `serverless remove`, a manual
console edit that drifts a resource out of sync with the template, or a
stack stuck mid-update from a bad deploy are all higher-consequence here
than on a typical stack. Two cheap, standard CloudFormation features close
most of that gap.

## Termination protection

Prevents `DeleteStack` (and therefore `serverless remove`, and the AWS
console's delete button) from working at all until protection is
explicitly turned off first — a deliberate two-step process instead of one
irreversible action.

**If you're using this repo's CI** (`.github/workflows/ci.yml`'s `deploy`
job): already enabled automatically, as the last step of every successful
deploy to `dev`. Nothing to do.

**If you're deploying manually or from your own pipeline**, run this once
after your first deploy (and it's safe to re-run — idempotent):

```bash
aws cloudformation update-termination-protection \
  --enable-termination-protection \
  --stack-name opencdr-<stage>
```

To intentionally tear down a stack, disable it first:

```bash
aws cloudformation update-termination-protection \
  --no-enable-termination-protection \
  --stack-name opencdr-<stage>
serverless remove --stage <stage>
```

## Drift detection

CloudFormation's drift detection compares live resource state against
what the template says it should be — catching a manual console change
(someone loosened an IAM policy statement by hand, say) that would
otherwise go unnoticed until it causes a confusing incident or a failed
future deploy.

**If you're using this repo's CI**: `.github/workflows/drift-check.yml`
runs this weekly (and on manual dispatch) against the `dev` stack, using
the same OIDC deploy role from [`ci-bootstrap/`](../ci-bootstrap/README.md).
It's purely observational — reports drifted resources and fails the
workflow run (visible via GitHub's own failure notifications for scheduled
workflows) but takes no corrective action itself.

**If you're checking manually, or adapting this for your own pipeline**:

```bash
STACK_NAME=opencdr-<stage>

DETECTION_ID=$(aws cloudformation detect-stack-drift \
  --stack-name "$STACK_NAME" \
  --query "StackDriftDetectionId" --output text)

# Poll until DetectionStatus is no longer DETECTION_IN_PROGRESS
aws cloudformation describe-stack-drift-detection-status \
  --stack-drift-detection-id "$DETECTION_ID"

# Once complete, see what (if anything) drifted
aws cloudformation describe-stack-resource-drifts \
  --stack-name "$STACK_NAME" \
  --stack-resource-drift-status-filters MODIFIED DELETED
```

A resource reported as `MODIFIED` or `DELETED` means the template no
longer matches reality — the next `serverless deploy` may either silently
overwrite the manual change or fail unexpectedly, depending on what
drifted. Reconcile by either updating `serverless.yml` to match the
intentional change, or reverting the manual one.

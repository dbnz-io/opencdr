# Delivery reliability and recovery

Correlation alerts and their outbox records are committed in one DynamoDB transaction. A failed transaction leaves neither record committed and the stream retries the operation. The stable outbox ID also deduplicates repeated correlations even when their alert timestamps differ. Correlation signal write-back is an outbox destination, so it can recover independently of notification and response delivery.

The publisher reads the current row returned by its conditional claim, checkpoints each successful destination, and fences subsequent updates with a claim token. A scheduled invocation runs every minute and queries the outbox status/time index for claims or pending work older than 120 seconds. It returns abandoned work to `PENDING` until the existing five-attempt limit is reached. It processes at most 100 rows per status per invocation; later invocations drain any remaining backlog. Exhausted records remain `FAILED` for inspection until their configured TTL expires.

Notifications return SQS partial batch failures. Successful channels and individual webhook targets have durable receipts in `delivery-state-table`; retries skip those destinations. Settings read failures retry the batch instead of temporarily treating notifications as disabled. The notifier has a 30-second timeout, processes one SQS message per invocation, and uses a 180-second queue visibility timeout with five delivery attempts before the notification DLQ. Notification receipts use the configured DynamoDB retention period (90 days by default).

A notification and its external receiver cannot commit atomically with DynamoDB. If a receiver accepts a request but the Lambda crashes before recording success, that notification can be sent again. The same ambiguity exists when an HTTP request times out. Receipts prevent repeating recorded successes, but do not promise exactly-once external delivery.

Automated response uses a stricter rule. Immediately before an action, the responder conditionally creates a permanent claim keyed by the delivery ID and response module. Completed claims suppress duplicates. An interrupted or exceptional action leaves its claim in place, with no automatic expiry or replay. `IR_ACTION_REPLAY_BLOCKED` identifies a blocked replay. Inspect the delivery-state row, the `IR_ACTION_EXCEPTION`/action-result logs, CloudTrail, and the affected resource before deciding whether another execution is appropriate. A returned unsuccessful action result is also retained as a completed attempt; it is not executed again automatically.

## Deploying over an existing stack

The deployment adds a delivery-state table, an outbox status/time GSI, a publisher schedule, and the corresponding IAM permissions. It also enables `ReportBatchItemFailures` for the notifier and grants the publisher access to the signal write queue. Deploy code and infrastructure together; Lambda consumers fail closed if the delivery-state table is not configured. Confirm the new outbox GSI is active before relying on scheduled recovery.

Old `IN_FLIGHT` rows have no claim token or consumer receipts. Their external effects cannot be established from the row alone. Recovery marks those rows `FAILED` with a `RecoveryRequired` error instead of replaying a potentially destructive response. Inspect these separately. Existing `PENDING` rows that predate `updated_at` still use their normal stream path; they are not covered by the recovery index until claimed. Already-lost alerts or deleted SQS messages are not reconstructed by this change.

For manual recovery, inspect `sent_destinations`, `last_error`, the delivery-state receipts, and downstream logs first. Preserve the original outbox ID and receipt state when retrying delivery. An IR claim must only be removed after an operator establishes that repeating the action is appropriate; removing it permits another execution. Permanent IR claims intentionally require explicit housekeeping and are not subject to TTL.

## Settings secrets

New secret values use immutable SSM parameter names beneath the existing settings namespace, ending in `/versions/<unique-id>`, with `Overwrite=False`. The settings document publishes the new reference only when its DynamoDB write succeeds. A rejected revision or create conflict therefore cannot replace an active credential. Existing `ssm:` references and redacted round trips remain supported.

Old versions and parameters from failed writes can remain unreferenced. Do not delete parameters immediately after a timeout: the document write may have committed despite the client error. Parameter cleanup requires checking committed references and allowing concurrent writes to finish. This favors credential safety over automatic garbage collection; account for retained versions in SSM quota management.

AWS references: [DynamoDB transactions](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/transaction-apis.html) and [SQS partial batch failures](https://docs.aws.amazon.com/lambda/latest/dg/example_serverless_SQS_Lambda_batch_item_failures_section.html).

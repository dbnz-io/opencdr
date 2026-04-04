# Built-in Detection Rules

OpenCDR ships 19 signal rules and 4 correlation rules covering the most common AWS attack patterns.

## Load Rules

```bash
# Load all rules into DynamoDB (dev stage)
./scripts/load_rules.sh

# Load into a specific stage / region
./scripts/load_rules.sh --stage prod --region us-west-2

# Preview without writing
./scripts/load_rules.sh --dry-run
```

## Signal Rules

| Rule | Severity | Tactic |
|---|---|---|
| `001` Console login without MFA | HIGH | Initial Access |
| `002` Root account used for any action | CRITICAL | Privilege Escalation |
| `003` Root account console login | CRITICAL | Initial Access |
| `004` Root access key created | CRITICAL | Persistence |
| `005` IAM user created | MEDIUM | Persistence |
| `006` Access key created | MEDIUM | Persistence |
| `007` IAM role created | MEDIUM | Persistence |
| `008` Lambda function created or updated | MEDIUM | Persistence |
| `009` AdministratorAccess policy attached | CRITICAL | Privilege Escalation |
| `010` Wildcard inline policy created | HIGH | Privilege Escalation |
| `011` Security group ingress rule added | MEDIUM | Defense Evasion |
| `012` CloudTrail stopped, deleted, or updated | CRITICAL | Defense Evasion |
| `013` GuardDuty detector deleted or disabled | CRITICAL | Defense Evasion |
| `014` AWS Config recorder stopped or deleted | HIGH | Defense Evasion |
| `015` Security Hub disabled | HIGH | Defense Evasion |
| `016` Secrets Manager secret accessed | HIGH | Credential Access |
| `017` SSM parameter accessed | MEDIUM | Credential Access |
| `018` S3 bucket made public | HIGH | Exfiltration |
| `019` RDS snapshot made public | HIGH | Exfiltration |

## Correlation Rules

| Rule | Severity | Description |
|---|---|---|
| `020` Console login brute force | CRITICAL | 5+ MFA-less logins from same user in 15 min |
| `021` IAM activity burst | CRITICAL | 5+ IAM signals from same actor in 5 min |
| `022` Defense evasion burst | CRITICAL | 2+ logging/detection services disabled in 10 min |
| `023` Credential harvesting | CRITICAL | 3+ secrets/SSM accesses from same actor in 5 min |

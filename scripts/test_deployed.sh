#!/usr/bin/env bash
# test_deployed.sh — Send test events to the deployed OpenCDR processor Lambda
# and verify signals were written to DynamoDB.
#
# Usage:
#   ./scripts/test_deployed.sh                          # dev stage, us-east-1
#   ./scripts/test_deployed.sh --stage prod
#   ./scripts/test_deployed.sh --event 009              # single event by prefix
#   ./scripts/test_deployed.sh --stage prod --region eu-west-1
#
# Requirements: AWS CLI v2, jq

set -euo pipefail

STAGE="dev"
REGION="us-east-1"
EVENT_FILTER=""
EVENTS_DIR="$(cd "$(dirname "$0")/.." && pwd)/support_files/test_events"

# ─── Argument parsing ────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --stage)   STAGE="$2";        shift 2 ;;
    --region)  REGION="$2";       shift 2 ;;
    --event)   EVENT_FILTER="$2"; shift 2 ;;
    *) echo "Unknown argument: $1"; exit 1 ;;
  esac
done

FUNCTION_NAME="opencdr-${STAGE}-processor"
# -v2: signals-table's own low-cardinality `severity` HASH key was
# replaced by a day-bucketed severity_bucket key -- see
# docs/architecture.md#dynamodb-tables. Nothing writes to the legacy
# signals-table anymore.
SIGNALS_TABLE="opencdr-${STAGE}-signals-table-v2"

echo ""
echo "┌─────────────────────────────────────────────────┐"
echo "│  OpenCDR — Integration Test (Deployed)          │"
echo "└─────────────────────────────────────────────────┘"
echo "  Function: ${FUNCTION_NAME}"
echo "  Table   : ${SIGNALS_TABLE}"
echo "  Region  : ${REGION}"
echo ""

# ─── Verify dependencies ─────────────────────────────────────────────────────
for cmd in aws jq; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "ERROR: $cmd not found."
    exit 1
  fi
done

if ! aws sts get-caller-identity --region "$REGION" &>/dev/null; then
  echo "ERROR: AWS credentials not configured or invalid."
  exit 1
fi

# ─── Verify Lambda exists ────────────────────────────────────────────────────
if ! aws lambda get-function --function-name "$FUNCTION_NAME" --region "$REGION" &>/dev/null; then
  echo "ERROR: Lambda '${FUNCTION_NAME}' not found in ${REGION}."
  echo "       Have you deployed? Run: serverless deploy --stage ${STAGE} --region ${REGION}"
  exit 1
fi

# ─── Helper: count signals for a given event_id ──────────────────────────────
count_signals() {
  local event_id="$1"
  aws dynamodb query \
    --table-name "$SIGNALS_TABLE" \
    --index-name gsi_signal_event_id \
    --key-condition-expression "event_id = :eid" \
    --expression-attribute-values "{\":eid\":{\"S\":\"${event_id}\"}}" \
    --select COUNT \
    --region "$REGION" \
    --query "Count" \
    --output text 2>/dev/null || echo "0"
}

# ─── Invoke and check ────────────────────────────────────────────────────────
passed=0
failed=0
skipped=0
tmp_output=$(mktemp)

for event_file in "$EVENTS_DIR"/*.json; do
  filename=$(basename "$event_file")

  if [[ -n "$EVENT_FILTER" && "$filename" != *"$EVENT_FILTER"* ]]; then
    continue
  fi

  # CloudTrail fixtures carry their id at .detail.eventID; GuardDuty
  # Finding fixtures use .detail.id instead (GuardDutyEventBridgeParser's
  # own convention, src/domain/ocsf_min_parser.py -- finding_id becomes
  # the normalized event_id, same field signals-table-v2 is queried by
  # below regardless of source). Without this fallback every GuardDuty
  # fixture in support_files/test_events/ silently hit the "no eventID"
  # skip branch instead of actually being tested.
  event_id=$(jq -r '.detail.eventID // .detail.id // empty' "$event_file")

  if [[ -z "$event_id" ]]; then
    echo "  [SKIP]   $filename — no eventID/id in detail"
    ((skipped++)) || true
    continue
  fi

  # Invoke Lambda synchronously
  http_status=$(aws lambda invoke \
    --function-name "$FUNCTION_NAME" \
    --payload "$(cat "$event_file" | base64)" \
    --cli-binary-format raw-in-base64-out \
    --region "$REGION" \
    --log-type None \
    "$tmp_output" \
    --query 'StatusCode' \
    --output text 2>/dev/null || echo "0")

  if [[ "$http_status" != "200" ]]; then
    echo "  [ERROR]  $filename — Lambda invocation failed (HTTP ${http_status})"
    ((failed++)) || true
    continue
  fi

  response=$(cat "$tmp_output")
  status=$(echo "$response" | jq -r '.status // "unknown"' 2>/dev/null || echo "unknown")

  # processor enqueues to signalWriter (SQS) rather than writing
  # signals-table-v2 directly (see docs/architecture.md#dynamodb-tables)
  # -- retry briefly instead of a single fixed wait, since that hop adds
  # real, if usually small, latency (an SQS-triggered Lambda invoke,
  # possibly a cold one).
  signal_count=0
  for _ in 1 2 3 4 5; do
    sleep 1
    signal_count=$(count_signals "$event_id")
    [[ "$signal_count" -gt 0 ]] && break
  done

  case "$status" in
    processed)
      if [[ "$signal_count" -gt 0 ]]; then
        echo "  [PASS]   $filename  →  status=${status}, signals=${signal_count}"
        ((passed++)) || true
      else
        echo "  [WARN]   $filename  →  status=${status} but 0 signals in DynamoDB"
        ((failed++)) || true
      fi
      ;;
    no_detection)
      echo "  [MISS]   $filename  →  no rules matched (check rules are loaded)"
      ((skipped++)) || true
      ;;
    ignored)
      echo "  [SKIP]   $filename  →  event not supported by parser"
      ((skipped++)) || true
      ;;
    no_rules)
      echo "  [WARN]   $filename  →  no rules in DynamoDB (run load_rules.sh first)"
      ((failed++)) || true
      ;;
    *)
      echo "  [ERROR]  $filename  →  unexpected response: ${response}"
      ((failed++)) || true
      ;;
  esac
done

rm -f "$tmp_output"

echo ""
echo "─────────────────────────────────────────────────"
echo "  Passed : ${passed}"
echo "  Failed : ${failed}"
echo "  Skipped: ${skipped}"
echo ""

if [[ $failed -gt 0 ]]; then
  exit 1
fi

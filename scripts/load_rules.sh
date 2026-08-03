#!/usr/bin/env bash
# load_rules.sh — Load OpenCDR detection rules into DynamoDB.
#
# Usage:
#   ./scripts/load_rules.sh                          # dev stage, us-east-1
#   ./scripts/load_rules.sh --stage prod             # prod stage
#   ./scripts/load_rules.sh --stage prod --region eu-west-1
#   ./scripts/load_rules.sh --dry-run                # print items without writing
#
# Requirements: AWS CLI v2, jq

set -euo pipefail

STAGE="dev"
REGION="us-east-1"
DRY_RUN=false
RULES_DIR="$(cd "$(dirname "$0")/.." && pwd)/support_files/detection_rules"

# ─── Argument parsing ────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --stage)   STAGE="$2";   shift 2 ;;
    --region)  REGION="$2";  shift 2 ;;
    --dry-run) DRY_RUN=true; shift   ;;
    *) echo "Unknown argument: $1"; exit 1 ;;
  esac
done

TABLE="opencdr-${STAGE}-detection-rules-table"

echo ""
echo "┌─────────────────────────────────────────────────┐"
echo "│  OpenCDR — Load Detection Rules                 │"
echo "└─────────────────────────────────────────────────┘"
echo "  Table  : ${TABLE}"
echo "  Region : ${REGION}"
echo "  Dry run: ${DRY_RUN}"
echo ""

# ─── Verify dependencies ─────────────────────────────────────────────────────
if ! command -v aws &>/dev/null; then
  echo "ERROR: AWS CLI not found. Install from https://aws.amazon.com/cli/"
  exit 1
fi

if ! command -v jq &>/dev/null; then
  echo "ERROR: jq not found. Install with: brew install jq / apt install jq"
  exit 1
fi

# ─── Verify AWS credentials ──────────────────────────────────────────────────
if ! aws sts get-caller-identity --region "$REGION" &>/dev/null; then
  echo "ERROR: AWS credentials not configured or invalid."
  exit 1
fi

# ─── Load rules ──────────────────────────────────────────────────────────────
loaded=0
skipped=0
failed=0

for rule_file in "$RULES_DIR"/*.json; do
  filename=$(basename "$rule_file")

  # Skip the legacy test stubs
  if [[ "$filename" == test_atomic_rule.json || \
        "$filename" == test_correlation_rule.json || \
        "$filename" == test_detection_rule.json ]]; then
    echo "  [SKIP]   $filename (test stub)"
    ((skipped++)) || true
    continue
  fi

  rule_id=$(jq -r '.rule_id // empty' "$rule_file")
  rule_kind=$(jq -r '.rule_kind // empty' "$rule_file")

  if [[ -z "$rule_id" || -z "$rule_kind" ]]; then
    echo "  [ERROR]  $filename — missing rule_id or rule_kind"
    ((failed++)) || true
    continue
  fi

  if [[ "$DRY_RUN" == true ]]; then
    echo "  [DRY]    $filename  (${rule_kind} / ${rule_id})"
    ((loaded++)) || true
    continue
  fi

  # Build DynamoDB item from the rule JSON
  # PK: rule_kind  SK: rule_id
  item=$(jq -n \
    --argjson rule "$(cat "$rule_file")" \
    '{
      "rule_kind": { "S": $rule.rule_kind },
      "rule_id":   { "S": $rule.rule_id },
      "rule_body": { "S": ($rule | tostring) }
    }')

  if aws dynamodb put-item \
      --table-name "$TABLE" \
      --item "$item" \
      --region "$REGION" \
      --output text &>/dev/null; then
    echo "  [OK]     $filename  (${rule_kind} / ${rule_id})"
    ((loaded++)) || true
  else
    echo "  [ERROR]  $filename — DynamoDB write failed"
    ((failed++)) || true
  fi
done

echo ""
echo "─────────────────────────────────────────────────"
echo "  Loaded : ${loaded}"
echo "  Skipped: ${skipped}"
echo "  Failed : ${failed}"
echo ""

if [[ $failed -gt 0 ]]; then
  exit 1
fi

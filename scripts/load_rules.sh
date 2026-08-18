#!/usr/bin/env bash
# load_rules.sh — Load OpenCDR detection rules into DynamoDB.
#
# Usage:
#   ./scripts/load_rules.sh                          # dev stage, us-east-1
#   ./scripts/load_rules.sh --stage prod             # prod stage
#   ./scripts/load_rules.sh --stage prod --region eu-west-1
#   ./scripts/load_rules.sh --dry-run                # print items without writing
#   ./scripts/load_rules.sh --with-response-modules  # arm automated response (see below)
#
# Requirements: AWS CLI v2, jq
#
# Rules load UNARMED by default: any response_module set in a rule's own
# JSON is stripped to "" before it's written, regardless of DREDGE_DRY_RUN.
# 20 of the 30 bundled rules ship with a response_module that, once armed,
# lets a matching detection execute a real, destructive AWS action -- see
# docs/incident-response.md#response-modules for the full, current list
# (kept there, not copied here, specifically so this comment can't drift
# out of sync with it the way an earlier "14 of 30" version of this same
# line already did once).
# Pass --with-response-modules once you've reviewed those rules and
# actually want that -- deploying and loading rules with zero flags should
# never be the thing that arms automated response.

set -euo pipefail

STAGE="dev"
REGION="us-east-1"
DRY_RUN=false
WITH_RESPONSE_MODULES=false
RULES_DIR="$(cd "$(dirname "$0")/.." && pwd)/support_files/detection_rules"

# ─── Argument parsing ────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --stage)                  STAGE="$2";   shift 2 ;;
    --region)                 REGION="$2";  shift 2 ;;
    --dry-run)                DRY_RUN=true; shift   ;;
    --with-response-modules)  WITH_RESPONSE_MODULES=true; shift ;;
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
if [[ "$WITH_RESPONSE_MODULES" == true ]]; then
  echo "  Response modules: ARMED -- rules load with their response_module intact"
else
  echo "  Response modules: stripped (pass --with-response-modules to arm)"
fi
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

# Recursive: rule files live in per-source subfolders (cloudtrail/,
# guardduty/, and any future source folder added the same way) rather than
# flat in RULES_DIR itself. find | sort keeps a deterministic order; -print0
# / read -d '' handles filenames safely without word-splitting.
while IFS= read -r -d '' rule_file; do
  filename="${rule_file#"$RULES_DIR"/}"

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

  # Strip response_module unless explicitly armed -- see the header comment.
  # rule_kind "list" rules have no response_module field at all; this is a
  # no-op for them either way.
  if [[ "$WITH_RESPONSE_MODULES" == true ]]; then
    rule_json="$(cat "$rule_file")"
    armed_note=""
  else
    rule_json="$(jq 'if has("response_module") then .response_module = "" else . end' "$rule_file")"
    original_module=$(jq -r '.response_module // empty' "$rule_file")
    if [[ -n "$original_module" ]]; then
      armed_note="  [unarmed, was: ${original_module}]"
    else
      armed_note=""
    fi
  fi

  if [[ "$DRY_RUN" == true ]]; then
    echo "  [DRY]    $filename  (${rule_kind} / ${rule_id})${armed_note}"
    ((loaded++)) || true
    continue
  fi

  # Build DynamoDB item from the rule JSON
  # PK: rule_kind  SK: rule_id
  item=$(jq -n \
    --argjson rule "$rule_json" \
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
    echo "  [OK]     $filename  (${rule_kind} / ${rule_id})${armed_note}"
    ((loaded++)) || true
  else
    echo "  [ERROR]  $filename — DynamoDB write failed"
    ((failed++)) || true
  fi
done < <(find "$RULES_DIR" -type f -name "*.json" -print0 | sort -z)

echo ""
echo "─────────────────────────────────────────────────"
echo "  Loaded : ${loaded}"
echo "  Skipped: ${skipped}"
echo "  Failed : ${failed}"
echo ""

if [[ $failed -gt 0 ]]; then
  exit 1
fi

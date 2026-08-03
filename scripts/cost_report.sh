#!/usr/bin/env bash
# cost_report.sh — Report AWS Cost Explorer spend for one OpenCDR stage.
#
# Filters by the Project=opencdr / Stage=<stage> cost-allocation tags every
# taggable resource in serverless.yml carries. Two one-time prerequisites in
# the AWS account, neither of which this script (or CloudFormation) can do
# for you:
#   1. Cost Explorer must be enabled once (Billing console > Cost Explorer).
#   2. The "Project" and "Stage" tags must be activated as cost allocation
#      tags (Billing console > Cost allocation tags) -- takes up to 24h to
#      start appearing in Cost Explorer after activation, and only covers
#      spend from the point of activation forward, not retroactively.
# Until both are done, this returns an empty/zero result, not an error --
# that's expected, not a bug in this script.
#
# Cost Explorer data itself lags real time by roughly 24h; this is a
# reporting tool for "what did this cost," not a live spend counter.
#
# Usage:
#   ./scripts/cost_report.sh                                   # dev stage, month-to-date, daily
#   ./scripts/cost_report.sh --stage prod
#   ./scripts/cost_report.sh --start 2026-07-01 --end 2026-08-01
#   ./scripts/cost_report.sh --granularity MONTHLY
#   ./scripts/cost_report.sh --granularity HOURLY               # AWS only retains hourly data for the trailing 14 days
#   ./scripts/cost_report.sh --dry-run                          # print the AWS CLI call without running it
#
# Requirements: AWS CLI v2, jq

set -euo pipefail

STAGE="dev"
REGION="us-east-1"
GRANULARITY="DAILY"
START=""
END=""
DRY_RUN=false

# ─── Portable "tomorrow" / "first of this month" (BSD date on macOS vs GNU date on Linux) ──
first_of_month() {
  if date -v+1d >/dev/null 2>&1; then
    date -u +%Y-%m-01
  else
    date -u -d "$(date -u +%Y-%m-01)" +%Y-%m-01
  fi
}

tomorrow() {
  if date -v+1d >/dev/null 2>&1; then
    date -u -v+1d +%Y-%m-%d
  else
    date -u -d tomorrow +%Y-%m-%d
  fi
}

# ─── Argument parsing ────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --stage)       STAGE="$2";       shift 2 ;;
    --region)      REGION="$2";      shift 2 ;;
    --start)       START="$2";       shift 2 ;;
    --end)         END="$2";         shift 2 ;;
    --granularity) GRANULARITY="$2"; shift 2 ;;
    --dry-run)     DRY_RUN=true;     shift   ;;
    *) echo "Unknown argument: $1"; exit 1 ;;
  esac
done

if [[ "$GRANULARITY" != "DAILY" && "$GRANULARITY" != "MONTHLY" && "$GRANULARITY" != "HOURLY" ]]; then
  echo "ERROR: --granularity must be DAILY, MONTHLY, or HOURLY (got: ${GRANULARITY})"
  exit 1
fi

[[ -z "$START" ]] && START="$(first_of_month)"
[[ -z "$END" ]] && END="$(tomorrow)"

echo ""
echo "┌─────────────────────────────────────────────────┐"
echo "│  OpenCDR — Cost Report                          │"
echo "└─────────────────────────────────────────────────┘"
echo "  Stage      : ${STAGE}"
echo "  Region     : ${REGION}"
echo "  Period     : ${START} .. ${END} (end exclusive)"
echo "  Granularity: ${GRANULARITY}"
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

FILTER=$(cat <<EOF
{
  "And": [
    {"Tags": {"Key": "Project", "Values": ["opencdr"]}},
    {"Tags": {"Key": "Stage", "Values": ["${STAGE}"]}}
  ]
}
EOF
)

if [[ "$DRY_RUN" == true ]]; then
  echo "Would run:"
  echo "  aws ce get-cost-and-usage \\"
  echo "    --time-period Start=${START},End=${END} \\"
  echo "    --granularity ${GRANULARITY} \\"
  echo "    --metrics UnblendedCost \\"
  echo "    --group-by Type=DIMENSION,Key=SERVICE \\"
  echo "    --filter '${FILTER}' \\"
  echo "    --region ${REGION}"
  exit 0
fi

# ─── Verify AWS credentials ──────────────────────────────────────────────────
if ! aws sts get-caller-identity --region "$REGION" &>/dev/null; then
  echo "ERROR: AWS credentials not configured or invalid."
  exit 1
fi

# Cost Explorer is a us-east-1-only API regardless of --region (billing data
# is global) -- the --region flag above only controls the STS identity check.
RESULT=$(aws ce get-cost-and-usage \
  --time-period Start="${START}",End="${END}" \
  --granularity "${GRANULARITY}" \
  --metrics "UnblendedCost" \
  --group-by Type=DIMENSION,Key=SERVICE \
  --filter "${FILTER}" \
  --region us-east-1 \
  --output json) || {
    echo ""
    echo "ERROR: Cost Explorer query failed. Common causes:"
    echo "  - Cost Explorer has never been enabled for this account (Billing console > Cost Explorer)."
    echo "  - The Project/Stage tags aren't activated as cost allocation tags yet (Billing console > Cost allocation tags)."
    echo "  - IAM: the caller needs ce:GetCostAndUsage."
    exit 1
  }

TOTAL=$(echo "$RESULT" | jq -r '[.ResultsByTime[].Total.UnblendedCost.Amount // "0"] | map(tonumber) | add')
UNIT=$(echo "$RESULT" | jq -r '.ResultsByTime[0].Total.UnblendedCost.Unit // "USD"')

echo "By service:"
echo "$RESULT" | jq -r '
  [.ResultsByTime[].Groups[]] |
  group_by(.Keys[0]) |
  map({service: .[0].Keys[0], amount: (map(.Metrics.UnblendedCost.Amount | tonumber) | add)}) |
  sort_by(-.amount) |
  .[] |
  "  \(.service): \(.amount | tostring)"
'

echo ""
echo "Total: ${TOTAL} ${UNIT}"

if [[ "$TOTAL" == "0" ]]; then
  echo ""
  echo "NOTE: A zero total usually means the cost allocation tags aren't"
  echo "activated yet (or were only just activated -- allow up to 24h),"
  echo "not that this stack costs nothing. See the header comment in this"
  echo "script for the one-time setup steps."
fi

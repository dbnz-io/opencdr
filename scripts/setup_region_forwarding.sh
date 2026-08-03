#!/usr/bin/env bash
# setup_region_forwarding.sh — Onboard (or remove) additional AWS regions
# so their CloudTrail/GuardDuty events reach OpenCDR, not just the
# deployment region's own events.
#
# Why this exists: CloudTrail delivers an event to the EventBridge default
# bus in whichever region the API call actually happened in -- true even
# for a multi-region trail -- and GuardDuty detectors are per-region.
# OpenCDR's own serverless.yml only listens on its deployment region's
# bus, so an account operating in more than one region is otherwise
# silently blind everywhere else. This deploys
# region-forwarding/cross-region-forwarder.yaml once per additional
# region, each forwarding that region's events to the home region.
#
# Per-region failures are expected, not fatal: an account with AWS
# Control Tower or an SCP restricting the approved region list will
# legitimately deny CloudFormation/EventBridge calls in blocked regions.
# This script acts on each region independently, catches a failure in
# one without aborting the rest, and prints a full per-region summary at
# the end -- never a single all-or-nothing operation. Same guarantee
# applies to --remove.
#
# Usage:
#   ./scripts/setup_region_forwarding.sh --region eu-west-1
#   ./scripts/setup_region_forwarding.sh --regions us-west-2,eu-west-1
#   ./scripts/setup_region_forwarding.sh --stage prod --home-region us-west-2 --regions eu-west-1,ap-southeast-1
#   ./scripts/setup_region_forwarding.sh --regions eu-west-1 --dry-run
#   ./scripts/setup_region_forwarding.sh --region eu-west-1 --remove      # tear down one region
#   ./scripts/setup_region_forwarding.sh --regions eu-west-1,ap-southeast-1 --remove
#
# Requirements: AWS CLI v2

set -uo pipefail
# Deliberately NOT `set -e` -- a failed region must not abort the loop.

STAGE="dev"
HOME_REGION="us-east-1"
REGIONS=""
DRY_RUN=false
REMOVE=false
TEMPLATE="$(cd "$(dirname "$0")/.." && pwd)/region-forwarding/cross-region-forwarder.yaml"

# ─── Argument parsing ────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --stage)       STAGE="$2";       shift 2 ;;
    --home-region) HOME_REGION="$2"; shift 2 ;;
    --regions)     REGIONS="$2";     shift 2 ;;
    --region)      REGIONS="$2";     shift 2 ;;  # singular shorthand -- identical to --regions with one value
    --remove)      REMOVE=true;      shift   ;;
    --dry-run)     DRY_RUN=true;     shift   ;;
    *) echo "Unknown argument: $1"; exit 1 ;;
  esac
done

if [[ -z "$REGIONS" ]]; then
  echo "ERROR: --region (one) or --regions (comma-separated) is required, e.g. --region eu-west-1 or --regions us-west-2,eu-west-1"
  exit 1
fi

MODE_LABEL="Onboard"
[[ "$REMOVE" == true ]] && MODE_LABEL="Remove"

echo ""
echo "┌─────────────────────────────────────────────────┐"
echo "│  OpenCDR — Cross-Region Event Forwarding (${MODE_LABEL})"
echo "└─────────────────────────────────────────────────┘"
echo "  Stage       : ${STAGE}"
echo "  Home region : ${HOME_REGION}"
echo "  Target regions: ${REGIONS}"
echo "  Dry run     : ${DRY_RUN}"
echo ""

# ─── Verify dependencies ─────────────────────────────────────────────────────
if ! command -v aws &>/dev/null; then
  echo "ERROR: AWS CLI not found. Install from https://aws.amazon.com/cli/"
  exit 1
fi

# ─── Verify AWS credentials ──────────────────────────────────────────────────
if ! aws sts get-caller-identity --region "$HOME_REGION" &>/dev/null; then
  echo "ERROR: AWS credentials not configured or invalid."
  exit 1
fi

# ─── Fetch home-region stack outputs (onboarding only -- removal doesn't
#     need parameters, and shouldn't require the home stack to still exist) ──
if [[ "$REMOVE" == false ]]; then
  STACK_NAME="opencdr-${STAGE}"
  echo "Reading outputs from ${STACK_NAME} in ${HOME_REGION}..."

  HOME_BUS_ARN=$(aws cloudformation describe-stacks \
    --stack-name "$STACK_NAME" \
    --region "$HOME_REGION" \
    --query "Stacks[0].Outputs[?OutputKey=='DefaultEventBusArn'].OutputValue" \
    --output text 2>/dev/null)

  FORWARDER_ROLE_ARN=$(aws cloudformation describe-stacks \
    --stack-name "$STACK_NAME" \
    --region "$HOME_REGION" \
    --query "Stacks[0].Outputs[?OutputKey=='RegionForwarderRoleArn'].OutputValue" \
    --output text 2>/dev/null)

  if [[ -z "$HOME_BUS_ARN" || -z "$FORWARDER_ROLE_ARN" || "$HOME_BUS_ARN" == "None" ]]; then
    echo "ERROR: Could not read DefaultEventBusArn/RegionForwarderRoleArn from ${STACK_NAME}."
    echo "       Has this stage been deployed (serverless deploy --stage ${STAGE} --region ${HOME_REGION})?"
    exit 1
  fi

  echo "  Home bus ARN     : ${HOME_BUS_ARN}"
  echo "  Forwarder role ARN: ${FORWARDER_ROLE_ARN}"
  echo ""
fi

# ─── Act on each target region, independently ────────────────────────────────
declare -a SUCCEEDED=()
declare -a FAILED=()
declare -a SKIPPED=()

IFS=',' read -ra REGION_LIST <<< "$REGIONS"
for region in "${REGION_LIST[@]}"; do
  region="$(echo "$region" | xargs)"  # trim whitespace
  [[ -z "$region" ]] && continue

  if [[ "$region" == "$HOME_REGION" ]]; then
    echo "── ${region}: skipped (same as home region) ──"
    SKIPPED+=("$region")
    continue
  fi

  if [[ "$REMOVE" == true ]]; then
    echo "── ${region}: removing forwarder ──"

    if [[ "$DRY_RUN" == true ]]; then
      echo "  Would run: aws cloudformation delete-stack --stack-name opencdr-${STAGE}-region-forwarder --region ${region}"
      SKIPPED+=("$region (dry-run)")
      continue
    fi

    # delete-stack is idempotent -- deleting an already-absent/never-onboarded
    # stack is not an error, so this is always safe to run.
    if aws cloudformation delete-stack \
        --stack-name "opencdr-${STAGE}-region-forwarder" \
        --region "$region" \
        2>"/tmp/opencdr-region-forward-${region}.err" \
      && aws cloudformation wait stack-delete-complete \
        --stack-name "opencdr-${STAGE}-region-forwarder" \
        --region "$region" \
        2>>"/tmp/opencdr-region-forward-${region}.err"; then
      echo "  OK (removed)"
      SUCCEEDED+=("$region")
    else
      reason="$(tail -1 "/tmp/opencdr-region-forward-${region}.err" 2>/dev/null)"
      echo "  FAILED: ${reason}"
      FAILED+=("$region: ${reason}")
    fi
    rm -f "/tmp/opencdr-region-forward-${region}.err"
    echo ""
    continue
  fi

  echo "── ${region}: deploying forwarder ──"

  if [[ "$DRY_RUN" == true ]]; then
    echo "  Would run: aws cloudformation deploy --template-file ${TEMPLATE} --region ${region} ..."
    SKIPPED+=("$region (dry-run)")
    continue
  fi

  # Deliberately not `set -e`-guarded: a failure here (e.g. AccessDenied
  # because this region is blocked by an SCP/Control Tower region
  # restriction) must not stop the loop from trying the remaining regions.
  if aws cloudformation deploy \
      --template-file "$TEMPLATE" \
      --stack-name "opencdr-${STAGE}-region-forwarder" \
      --region "$region" \
      --parameter-overrides \
        ServiceName=opencdr \
        Stage="$STAGE" \
        HomeEventBusArn="$HOME_BUS_ARN" \
        HomeForwarderRoleArn="$FORWARDER_ROLE_ARN" \
      --no-fail-on-empty-changeset \
      2>"/tmp/opencdr-region-forward-${region}.err"; then
    echo "  OK"
    SUCCEEDED+=("$region")
  else
    reason="$(tail -1 "/tmp/opencdr-region-forward-${region}.err" 2>/dev/null)"
    echo "  FAILED: ${reason}"
    echo "  (a Control Tower / SCP region restriction denying this region looks exactly like this — expected, not a bug)"
    FAILED+=("$region: ${reason}")
  fi
  rm -f "/tmp/opencdr-region-forward-${region}.err"
  echo ""
done

# ─── Summary ──────────────────────────────────────────────────────────────
SUCCESS_LABEL="Succeeded"
[[ "$REMOVE" == true ]] && SUCCESS_LABEL="Removed"

echo "┌─────────────────────────────────────────────────┐"
echo "│  Summary                                         │"
echo "└─────────────────────────────────────────────────┘"
echo "  ${SUCCESS_LABEL} (${#SUCCEEDED[@]}): ${SUCCEEDED[*]:-none}"
echo "  Failed    (${#FAILED[@]}):"
for f in "${FAILED[@]:-}"; do
  [[ -n "$f" ]] && echo "    - $f"
done
echo "  Skipped   (${#SKIPPED[@]}): ${SKIPPED[*]:-none}"
echo ""

if [[ ${#SUCCEEDED[@]} -eq 0 && ${#FAILED[@]} -gt 0 ]]; then
  echo "ERROR: every target region failed."
  exit 1
fi

exit 0

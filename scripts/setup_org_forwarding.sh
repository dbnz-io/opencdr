#!/usr/bin/env bash
# setup_org_forwarding.sh — Onboard (or remove) AWS Organizations member
# accounts so their CloudTrail/GuardDuty events reach a central security
# account running OpenCDR, without granting events:PutEvents to every
# principal in the org.
#
# Why this exists: the org-wide deployment recipe used to be
# `aws events put-permission --principal "*" --condition PrincipalOrgID`
# on the central bus -- trusting *any* credential anywhere in the org, not
# just the intended forwarding mechanism. This deploys
# org-forwarding/account-event-forwarder.yaml once per member account,
# each creating a role only events.amazonaws.com can assume and a local
# rule that uses it to forward that account's own real events to the
# central bus -- see docs/org-forwarding.md for the full threat model.
#
# Unlike setup_region_forwarding.sh (same account, different regions, one
# set of credentials via --region), this crosses account boundaries:
# member accounts need their own credentials, via AWS CLI named profiles
# (--profiles). The central/security account's own credentials (default
# profile, or --central-profile) are used only to read its stack outputs.
#
# Per-account failures are expected, not fatal: a missing profile, a
# member account you don't yet have access to, or an SCP blocking
# CloudFormation in that account all look like a normal failure here.
# This script acts on each account independently, catches a failure in
# one without aborting the rest, and prints a full per-account summary at
# the end -- never a single all-or-nothing operation. Same guarantee
# applies to --remove.
#
# Usage:
#   ./scripts/setup_org_forwarding.sh --profile member-a
#   ./scripts/setup_org_forwarding.sh --profiles member-a,member-b,member-c
#   ./scripts/setup_org_forwarding.sh --stage prod --central-profile security-account --profiles member-a,member-b
#   ./scripts/setup_org_forwarding.sh --profiles member-a --member-region eu-west-1
#   ./scripts/setup_org_forwarding.sh --profiles member-a,member-b --dry-run
#   ./scripts/setup_org_forwarding.sh --profile member-a --remove      # tear down one account
#
# Requirements: AWS CLI v2, and named profiles already configured for
# each account this touches (`aws configure --profile <name>` or your
# org's SSO setup -- this script doesn't create profiles, only uses them).

set -uo pipefail
# Deliberately NOT `set -e` -- a failed account must not abort the loop.

STAGE="dev"
CENTRAL_PROFILE=""       # empty = default credentials/profile
CENTRAL_REGION="us-east-1"
MEMBER_REGION=""         # empty = same as CENTRAL_REGION
PROFILES=""
DRY_RUN=false
REMOVE=false
TEMPLATE="$(cd "$(dirname "$0")/.." && pwd)/org-forwarding/account-event-forwarder.yaml"

# ─── Argument parsing ────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --stage)            STAGE="$2";            shift 2 ;;
    --central-profile)  CENTRAL_PROFILE="$2";   shift 2 ;;
    --central-region)   CENTRAL_REGION="$2";    shift 2 ;;
    --member-region)    MEMBER_REGION="$2";     shift 2 ;;
    --profiles)         PROFILES="$2";          shift 2 ;;
    --profile)          PROFILES="$2";          shift 2 ;;  # singular shorthand
    --remove)           REMOVE=true;            shift   ;;
    --dry-run)           DRY_RUN=true;          shift   ;;
    *) echo "Unknown argument: $1"; exit 1 ;;
  esac
done

if [[ -z "$PROFILES" ]]; then
  echo "ERROR: --profile (one) or --profiles (comma-separated) is required, e.g. --profile member-a or --profiles member-a,member-b"
  echo "       Each must be an AWS CLI profile already configured for that member account."
  exit 1
fi

[[ -z "$MEMBER_REGION" ]] && MEMBER_REGION="$CENTRAL_REGION"

CENTRAL_PROFILE_ARGS=()
[[ -n "$CENTRAL_PROFILE" ]] && CENTRAL_PROFILE_ARGS=(--profile "$CENTRAL_PROFILE")

MODE_LABEL="Onboard"
[[ "$REMOVE" == true ]] && MODE_LABEL="Remove"

echo ""
echo "┌─────────────────────────────────────────────────┐"
echo "│  OpenCDR — Org-Wide Account Forwarding (${MODE_LABEL})"
echo "└─────────────────────────────────────────────────┘"
echo "  Stage             : ${STAGE}"
echo "  Central profile   : ${CENTRAL_PROFILE:-<default>}"
echo "  Central region    : ${CENTRAL_REGION}"
echo "  Member region     : ${MEMBER_REGION}"
echo "  Target profiles   : ${PROFILES}"
echo "  Dry run           : ${DRY_RUN}"
echo ""

# ─── Verify dependencies ─────────────────────────────────────────────────────
if ! command -v aws &>/dev/null; then
  echo "ERROR: AWS CLI not found. Install from https://aws.amazon.com/cli/"
  exit 1
fi

# ─── Fetch central-account stack outputs (onboarding only -- removal
#     doesn't need parameters, and shouldn't require the central stack to
#     still exist) ──
if [[ "$REMOVE" == false ]]; then
  if ! aws sts get-caller-identity --region "$CENTRAL_REGION" "${CENTRAL_PROFILE_ARGS[@]}" &>/dev/null; then
    echo "ERROR: could not authenticate to the central account (profile: ${CENTRAL_PROFILE:-default})."
    exit 1
  fi

  STACK_NAME="opencdr-${STAGE}"
  echo "Reading outputs from ${STACK_NAME} in the central account (${CENTRAL_REGION})..."

  CENTRAL_BUS_ARN=$(aws cloudformation describe-stacks \
    --stack-name "$STACK_NAME" \
    --region "$CENTRAL_REGION" \
    "${CENTRAL_PROFILE_ARGS[@]}" \
    --query "Stacks[0].Outputs[?OutputKey=='DefaultEventBusArn'].OutputValue" \
    --output text 2>/dev/null)

  ROLE_NAME=$(aws cloudformation describe-stacks \
    --stack-name "$STACK_NAME" \
    --region "$CENTRAL_REGION" \
    "${CENTRAL_PROFILE_ARGS[@]}" \
    --query "Stacks[0].Outputs[?OutputKey=='OrgAccountForwarderRoleName'].OutputValue" \
    --output text 2>/dev/null)

  if [[ -z "$CENTRAL_BUS_ARN" || "$CENTRAL_BUS_ARN" == "None" ]]; then
    echo "ERROR: Could not read DefaultEventBusArn from ${STACK_NAME} in the central account."
    echo "       Has this stage been deployed there (serverless deploy --stage ${STAGE} --param=\"orgId=o-XXXXXXXXXX\")?"
    exit 1
  fi

  echo "  Central bus ARN         : ${CENTRAL_BUS_ARN}"
  echo "  Expected forwarder role : ${ROLE_NAME}"
  echo ""
  echo "  NOTE: if OrgAccountForwarderRoleName came back empty, the central"
  echo "  stack was deployed without --param=\"orgId=...\" -- OrgForwarderBusPolicy"
  echo "  doesn't exist yet, so member accounts you onboard here won't"
  echo "  actually be trusted to send events until that's fixed centrally."
  echo ""
fi

# ─── Act on each member account, independently ───────────────────────────────
declare -a SUCCEEDED=()
declare -a FAILED=()
declare -a SKIPPED=()

IFS=',' read -ra PROFILE_LIST <<< "$PROFILES"
for profile in "${PROFILE_LIST[@]}"; do
  profile="$(echo "$profile" | xargs)"  # trim whitespace
  [[ -z "$profile" ]] && continue

  if [[ "$REMOVE" == true ]]; then
    echo "── ${profile}: removing forwarder ──"

    if [[ "$DRY_RUN" == true ]]; then
      echo "  Would run: aws cloudformation delete-stack --stack-name opencdr-${STAGE}-account-forwarder --region ${MEMBER_REGION} --profile ${profile}"
      SKIPPED+=("$profile (dry-run)")
      continue
    fi

    if aws cloudformation delete-stack \
        --stack-name "opencdr-${STAGE}-account-forwarder" \
        --region "$MEMBER_REGION" \
        --profile "$profile" \
        2>"/tmp/opencdr-org-forward-${profile}.err" \
      && aws cloudformation wait stack-delete-complete \
        --stack-name "opencdr-${STAGE}-account-forwarder" \
        --region "$MEMBER_REGION" \
        --profile "$profile" \
        2>>"/tmp/opencdr-org-forward-${profile}.err"; then
      echo "  OK (removed)"
      SUCCEEDED+=("$profile")
    else
      reason="$(tail -1 "/tmp/opencdr-org-forward-${profile}.err" 2>/dev/null)"
      echo "  FAILED: ${reason}"
      FAILED+=("$profile: ${reason}")
    fi
    rm -f "/tmp/opencdr-org-forward-${profile}.err"
    echo ""
    continue
  fi

  echo "── ${profile}: deploying forwarder ──"

  if ! aws sts get-caller-identity --region "$MEMBER_REGION" --profile "$profile" &>/dev/null; then
    echo "  FAILED: could not authenticate with profile '${profile}'"
    FAILED+=("$profile: authentication failed")
    echo ""
    continue
  fi

  if [[ "$DRY_RUN" == true ]]; then
    echo "  Would run: aws cloudformation deploy --template-file ${TEMPLATE} --region ${MEMBER_REGION} --profile ${profile} ..."
    SKIPPED+=("$profile (dry-run)")
    continue
  fi

  # Deliberately not `set -e`-guarded: a failure here (e.g. AccessDenied,
  # or an SCP blocking CloudFormation/IAM role creation in this account)
  # must not stop the loop from trying the remaining accounts.
  if aws cloudformation deploy \
      --template-file "$TEMPLATE" \
      --stack-name "opencdr-${STAGE}-account-forwarder" \
      --region "$MEMBER_REGION" \
      --profile "$profile" \
      --capabilities CAPABILITY_NAMED_IAM \
      --parameter-overrides \
        ServiceName=opencdr \
        Stage="$STAGE" \
        CentralEventBusArn="$CENTRAL_BUS_ARN" \
      --no-fail-on-empty-changeset \
      2>"/tmp/opencdr-org-forward-${profile}.err"; then
    echo "  OK"
    SUCCEEDED+=("$profile")
  else
    reason="$(tail -1 "/tmp/opencdr-org-forward-${profile}.err" 2>/dev/null)"
    echo "  FAILED: ${reason}"
    echo "  (an SCP restricting IAM role creation or CloudFormation in this account looks exactly like this -- expected, not a bug)"
    FAILED+=("$profile: ${reason}")
  fi
  rm -f "/tmp/opencdr-org-forward-${profile}.err"
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
  echo "ERROR: every target account failed."
  exit 1
fi

exit 0

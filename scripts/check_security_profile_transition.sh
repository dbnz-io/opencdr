#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 --stage <stage> --target <standard|hardened> [--region <region>] [--allow-downgrade]" >&2
  exit 2
}

stage=""
target=""
region="us-east-1"
allow_downgrade="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --stage) stage="${2:-}"; shift 2 ;;
    --target) target="${2:-}"; shift 2 ;;
    --region) region="${2:-}"; shift 2 ;;
    --allow-downgrade) allow_downgrade="true"; shift ;;
    *) usage ;;
  esac
done

[[ -n "$stage" ]] || usage
[[ "$target" == "standard" || "$target" == "hardened" ]] || usage

stack_name="opencdr-${stage}"
current=$(aws cloudformation describe-stacks \
  --stack-name "$stack_name" \
  --region "$region" \
  --query "Stacks[0].Outputs[?OutputKey=='CoreSecurityProfile'].OutputValue | [0]" \
  --output text 2>/dev/null || true)

# A stack created before security profiles has no output. Treat it as standard;
# this preserves backward compatibility while still protecting every later
# hardened -> standard transition.
if [[ -z "$current" || "$current" == "None" ]]; then
  current="standard"
fi

if [[ "$current" == "hardened" && "$target" == "standard" && "$allow_downgrade" != "true" ]]; then
  echo "ERROR: refusing to reduce ${stack_name} from hardened to standard." >&2
  echo "Re-run with --allow-downgrade only after reviewing the CloudFormation change set." >&2
  exit 1
fi

echo "Security profile transition accepted: ${current} -> ${target} (${stack_name}, ${region})"

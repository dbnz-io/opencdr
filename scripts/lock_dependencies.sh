#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
UV_BIN=${UV_BIN:-uv}
EXPECTED_UV_VERSION="0.13.6"

actual_version=$($UV_BIN --version | awk '{print $2}')
if [[ "$actual_version" != "$EXPECTED_UV_VERSION" ]]; then
  echo "ERROR: dependency locks require uv ${EXPECTED_UV_VERSION}; found ${actual_version}" >&2
  echo "Install it with: python3.12 -m pip install 'uv==${EXPECTED_UV_VERSION}'" >&2
  exit 1
fi

cd "$ROOT_DIR"

common_args=(
  # Resolve from the project's supported floor so the same lock is valid for
  # both CI (3.11/3.12) and the Lambda runtime (3.12).
  --python-version 3.11
  --generate-hashes
  --universal
  --quiet
)

$UV_BIN pip compile "${common_args[@]}" --output-file requirements.txt requirements.in
$UV_BIN pip compile "${common_args[@]}" --output-file requirements-dev.txt requirements-dev.in

echo "Updated requirements.txt and requirements-dev.txt with uv ${EXPECTED_UV_VERSION}."

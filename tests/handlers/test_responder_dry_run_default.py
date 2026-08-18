"""Tests for DREDGE_DRY_RUN's default value and the cold-start
IR_LIVE_MODE_ENABLED warning (INFORME-AUTOR-ES.md §1.2: automated response
was armed by default -- DREDGE_DRY_RUN defaulted to "false"). Both changed
to default-safe ("true" / simulate-only).

Run as a subprocess with a genuinely fresh interpreter, not
importlib.reload(responder) in-process: this module is already imported
(and its module-level table references monkeypatched) by every other test
file in this suite via the shared sys.modules cache, so reloading it here
would mutate that shared object out from under tests in other files
depending on execution order -- a real cross-test isolation risk, not
worth it for testing three lines of cold-start logic.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

_ENV_SETUP = """
import os
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("LOGS_TABLE_NAME", "test-logs-table")
os.environ.setdefault("IR_ACCOUNT_ROLES_TABLE_NAME", "test-ir-account-roles-table")
os.environ.setdefault("OPENCDR_IR_ROLE_ARN", "arn:aws:iam::123456789012:role/test-ir-role")

from unittest.mock import MagicMock
import boto3
boto3.resource = lambda *a, **k: MagicMock()

from src.handlers import responder  # noqa: F401
"""


def _run_fresh_import(dredge_dry_run_env: str | None) -> str:
    env = dict(os.environ)
    if dredge_dry_run_env is None:
        env.pop("DREDGE_DRY_RUN", None)
    else:
        env["DREDGE_DRY_RUN"] = dredge_dry_run_env

    result = subprocess.run(
        [sys.executable, "-c", _ENV_SETUP],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


class TestDryRunDefaultsToSafe:
    def test_unset_env_var_logs_no_live_mode_warning(self):
        stdout = _run_fresh_import(dredge_dry_run_env=None)
        assert "IR_LIVE_MODE_ENABLED" not in stdout

    def test_explicit_true_logs_no_warning(self):
        stdout = _run_fresh_import(dredge_dry_run_env="true")
        assert "IR_LIVE_MODE_ENABLED" not in stdout

    def test_explicit_false_logs_live_mode_warning(self):
        stdout = _run_fresh_import(dredge_dry_run_env="false")
        assert "IR_LIVE_MODE_ENABLED" in stdout
        line = next(line for line in stdout.splitlines() if "IR_LIVE_MODE_ENABLED" in line)
        payload = json.loads(line)
        assert payload["details"]["level"] == "WARNING"

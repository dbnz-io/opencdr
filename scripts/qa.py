#!/usr/bin/env python3
"""Run repeatable local QA and publish a human-readable and machine-readable report."""

from __future__ import annotations

import argparse
import html
import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--integration-only", action="store_true", help="Run only the AWS-emulated journeys"
    )
    parser.add_argument("--coverage", action="store_true", help="Also write coverage.xml for src")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "artifacts/qa")
    args = parser.parse_args()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    junit = output / "junit.xml"
    # Never mistake a previous run's results for a collection/startup failure.
    junit.unlink(missing_ok=True)
    env = {
        k: v
        for k, v in os.environ.items()
        if k not in {"AWS_PROFILE", "AWS_DEFAULT_PROFILE"} and not k.startswith("AWS_ENDPOINT_URL")
    }
    env.update(
        AWS_ACCESS_KEY_ID="testing",
        AWS_SECRET_ACCESS_KEY="testing",
        AWS_SESSION_TOKEN="testing",
        AWS_DEFAULT_REGION="us-east-1",
        AWS_EC2_METADATA_DISABLED="true",
        AWS_XRAY_SDK_ENABLED="false",
    )
    command = [
        sys.executable,
        "-m",
        "pytest",
        "tests/qa" if args.integration_only else "tests",
        "-v",
        "--tb=short",
        f"--junitxml={junit}",
    ]
    if args.coverage:
        command.extend(["--cov=src", "--cov-report=xml"])
    with (output / "run.log").open("w") as log:
        process = subprocess.Popen(
            command, cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )
        for line in process.stdout:
            print(line, end="", flush=True)
            log.write(line)
        code = process.wait()
    cases = []
    report_error = None
    try:
        for case in ET.parse(junit).getroot().iter("testcase"):
            outcome, details = "passed", ""
            for tag in ("error", "failure", "skipped"):
                node = case.find(tag)
                if node is not None:
                    outcome, details = tag, node.get("message", "")
                    break
            cases.append(
                {
                    "name": f"{case.get('classname')}.{case.get('name')}",
                    "outcome": outcome,
                    "seconds": float(case.get("time", 0)),
                    "details": details,
                }
            )
    except (OSError, ET.ParseError, ValueError) as exc:
        report_error = str(exc)
    # Fail closed for missing reports and empty collection, even if pytest exits 0.
    success = (
        code == 0
        and bool(cases)
        and report_error is None
        and all(c["outcome"] == "passed" for c in cases)
    )
    summary = {
        "status": "passed" if success else "failed",
        "pytest_exit_code": code,
        "scope": "integration" if args.integration_only else "full",
        "counts": {
            state: sum(c["outcome"] == state for c in cases)
            for state in ("passed", "failure", "error", "skipped")
        },
        "report_error": report_error,
        "tests": cases,
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    rows = "".join(
        f"<tr><td>{html.escape(c['name'])}</td><td>{c['outcome']}</td>"
        f"<td>{c['seconds']:.3f}s</td><td>{html.escape(c['details'])}</td></tr>"
        for c in cases
    )
    (output / "report.html").write_text(
        '<!doctype html><html lang="en"><meta charset="utf-8"><title>OpenCDR QA report</title>'
        "<style>body{font:15px system-ui;margin:32px}table{border-collapse:collapse;width:100%}"
        "td,th{padding:8px;border:1px solid #ddd;text-align:left}td:first-child{overflow-wrap:anywhere}</style>"
        f"<h1>OpenCDR QA: {summary['status'].upper()}</h1>"
        f"<p>Scope: {summary['scope']}. {html.escape(str(summary['counts']))}</p>"
        f"<p>{html.escape(report_error or '')}</p>"
        "<p>Local handler integration uses emulated AWS. This report does not certify a deployed stack.</p>"
        '<p><a href="run.log">Run log</a> · <a href="junit.xml">JUnit XML</a> · '
        '<a href="summary.json">JSON report</a></p>'
        f"<table><tr><th>Test</th><th>Result</th><th>Duration</th><th>Details</th></tr>{rows}</table></html>"
    )
    print(f"\nQA {summary['status'].upper()}: {output / 'report.html'}")
    return 0 if success else (code or 1)


if __name__ == "__main__":
    raise SystemExit(main())

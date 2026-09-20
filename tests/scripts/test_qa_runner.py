"""The QA command must not report success for incomplete or failed runs."""

import io
import json

import pytest

from scripts import qa


@pytest.mark.parametrize(
    ("xml", "exit_code", "expected"),
    [
        (
            '<testsuites><testsuite><testcase name="works" time="0.1"/></testsuite></testsuites>',
            0,
            0,
        ),
        (
            '<testsuites><testsuite><testcase name="broken"><failure message="bad &lt;tag&gt;"/></testcase></testsuite></testsuites>',
            1,
            1,
        ),
        (
            '<testsuites><testsuite><testcase name="missing"><skipped/></testcase></testsuite></testsuites>',
            0,
            1,
        ),
        ("<testsuites><testsuite/></testsuites>", 0, 1),
        (None, 0, 1),
        ("not xml", 0, 1),
    ],
)
def test_report_outcomes(tmp_path, monkeypatch, xml, exit_code, expected):
    junit = tmp_path / "junit.xml"
    junit.write_text('<testsuites><testsuite><testcase name="stale"/></testsuite></testsuites>')

    class Process:
        stdout = io.StringIO("pytest output\n")

        def __init__(self, command, **kwargs):
            assert not junit.exists(), "Previous run must be removed before starting pytest"
            assert "tests/qa" in command
            assert kwargs["env"]["AWS_ACCESS_KEY_ID"] == "testing"
            assert "AWS_PROFILE" not in kwargs["env"]
            assert "AWS_ENDPOINT_URL" not in kwargs["env"]
            if xml is not None:
                junit.write_text(xml)

        def wait(self):
            return exit_code

    monkeypatch.setenv("AWS_PROFILE", "production")
    monkeypatch.setenv("AWS_ENDPOINT_URL", "https://example.invalid")
    monkeypatch.setattr(qa.subprocess, "Popen", Process)
    monkeypatch.setattr(
        qa.sys, "argv", ["qa.py", "--integration-only", "--output-dir", str(tmp_path)]
    )
    assert qa.main() == expected
    report = json.loads((tmp_path / "summary.json").read_text())
    assert report["status"] == ("passed" if expected == 0 else "failed")
    assert (tmp_path / "run.log").read_text() == "pytest output\n"
    html = (tmp_path / "report.html").read_text()
    assert "bad <tag>" not in html
    if xml and "&lt;tag&gt;" in xml:
        assert "bad &lt;tag&gt;" in html

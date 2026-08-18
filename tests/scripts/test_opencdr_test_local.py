"""Tests for `opencdr.py test local` (cmd_test_local) -- the local rule tester.

No AWS calls at all; runs the real src.domain.detection_engine/ocsf_min_parser
against isolated rule/event fixture directories.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

import opencdr  # noqa: E402  (after sys.path manipulation)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


CLOUDTRAIL_EVENT = {
    "detail-type": "AWS Console Sign In via CloudTrail",
    "source": "aws.signin",
    "account": "123456789012",
    "region": "us-east-1",
    "detail": {
        "eventTime": "2026-08-14T00:00:00Z",
        "eventSource": "signin.amazonaws.com",
        "eventName": "ConsoleLogin",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.1",
        "eventID": "test-evt-1",
        "recipientAccountId": "123456789012",
        "userIdentity": {"type": "IAMUser", "principalId": "AID1", "userName": "attacker"},
        "additionalEventData": {"MFAUsed": "No"},
    },
}


def _console_login_rule(rule_id="001_console_login_no_mfa"):
    return {
        "rule_id": rule_id,
        "rule_kind": "signal",
        "enabled": True,
        "severity": "HIGH",
        "notify": True,
        "response_module": "",
        "conditions": [
            {"field": "activity_name", "op": "equals", "value": "ConsoleLogin"},
            {"field": "raw_event.detail.additionalEventData.MFAUsed", "op": "equals", "value": "No"},
        ],
    }


@pytest.fixture()
def isolated_dirs(tmp_path, monkeypatch):
    rules_dir = tmp_path / "detection_rules"
    events_dir = tmp_path / "test_events"
    rules_dir.mkdir()
    events_dir.mkdir()
    monkeypatch.setattr(opencdr, "RULES_DIR", rules_dir)
    monkeypatch.setattr(opencdr, "EVENTS_DIR", events_dir)
    return rules_dir, events_dir


def _write_json(directory: Path, filename: str, data: dict) -> None:
    (directory / filename).write_text(json.dumps(data))


def _make_args(rule=None, event=None) -> SimpleNamespace:
    return SimpleNamespace(rule=rule, event=event)


# ---------------------------------------------------------------------------
# Empty-match guards
# ---------------------------------------------------------------------------


class TestNoMatches:
    def test_no_rules_at_all_exits_1(self, isolated_dirs, capsys):
        _, events_dir = isolated_dirs
        _write_json(events_dir, "001.json", CLOUDTRAIL_EVENT)
        with pytest.raises(SystemExit) as exc_info:
            opencdr.cmd_test_local(_make_args())
        assert exc_info.value.code == 1
        assert "no rules matched" in capsys.readouterr().out.lower()

    def test_no_events_at_all_exits_1(self, isolated_dirs, capsys):
        rules_dir, _ = isolated_dirs
        _write_json(rules_dir, "001.json", _console_login_rule())
        with pytest.raises(SystemExit) as exc_info:
            opencdr.cmd_test_local(_make_args())
        assert exc_info.value.code == 1
        assert "no events matched" in capsys.readouterr().out.lower()

    def test_rule_filter_matching_nothing_exits_1(self, isolated_dirs):
        rules_dir, events_dir = isolated_dirs
        _write_json(rules_dir, "001.json", _console_login_rule())
        _write_json(events_dir, "001.json", CLOUDTRAIL_EVENT)
        with pytest.raises(SystemExit) as exc_info:
            opencdr.cmd_test_local(_make_args(rule="nonexistent_rule_id"))
        assert exc_info.value.code == 1

    def test_event_filter_matching_nothing_exits_1(self, isolated_dirs):
        rules_dir, events_dir = isolated_dirs
        _write_json(rules_dir, "001.json", _console_login_rule())
        _write_json(events_dir, "001.json", CLOUDTRAIL_EVENT)
        with pytest.raises(SystemExit) as exc_info:
            opencdr.cmd_test_local(_make_args(event="nonexistent_file"))
        assert exc_info.value.code == 1


# ---------------------------------------------------------------------------
# HIT / MISS / SKIP
# ---------------------------------------------------------------------------


class TestMatchOutcomes:
    def test_matching_event_reports_hit_and_fired_rule(self, isolated_dirs, capsys):
        rules_dir, events_dir = isolated_dirs
        _write_json(rules_dir, "001.json", _console_login_rule())
        _write_json(events_dir, "001.json", CLOUDTRAIL_EVENT)

        opencdr.cmd_test_local(_make_args())
        out = capsys.readouterr().out
        assert "[HIT]" in out
        assert "FIRED" in out
        assert "001_console_login_no_mfa" in out
        assert "Matches : 1" in out
        assert "1/1 fired" in out

    def test_non_matching_event_reports_miss(self, isolated_dirs, capsys):
        rules_dir, events_dir = isolated_dirs
        _write_json(rules_dir, "001.json", _console_login_rule())
        non_matching = json.loads(json.dumps(CLOUDTRAIL_EVENT))
        non_matching["detail"]["additionalEventData"]["MFAUsed"] = "Yes"
        _write_json(events_dir, "001.json", non_matching)

        opencdr.cmd_test_local(_make_args())
        out = capsys.readouterr().out
        assert "[MISS]" in out
        assert "0/1 fired" in out

    def test_unparseable_event_reports_skip(self, isolated_dirs, capsys):
        rules_dir, events_dir = isolated_dirs
        _write_json(rules_dir, "001.json", _console_login_rule())
        _write_json(events_dir, "unsupported.json", {"source": "aws.totally-unsupported-service"})

        # cmd_test_local never sys.exit()s after the match loop (only the
        # earlier "no rules/events matched" guards do) -- an unparseable
        # event is reported and the summary still prints normally.
        opencdr.cmd_test_local(_make_args())
        assert "[SKIP]" in capsys.readouterr().out

    def test_unfired_rules_listed_in_summary(self, isolated_dirs, capsys):
        rules_dir, events_dir = isolated_dirs
        _write_json(rules_dir, "001.json", _console_login_rule("001_console_login_no_mfa"))
        _write_json(rules_dir, "999.json", _console_login_rule("999_never_matches") | {
            "conditions": [{"field": "activity_name", "op": "equals", "value": "SomethingElseEntirely"}]
        })
        _write_json(events_dir, "001.json", CLOUDTRAIL_EVENT)

        opencdr.cmd_test_local(_make_args())
        out = capsys.readouterr().out
        assert "no matching test event" in out.lower()
        assert "999_never_matches" in out


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------


class TestFiltering:
    def test_rule_filter_narrows_to_matching_rule_id(self, isolated_dirs, capsys):
        rules_dir, events_dir = isolated_dirs
        _write_json(rules_dir, "001.json", _console_login_rule("001_console_login_no_mfa"))
        _write_json(rules_dir, "002.json", _console_login_rule("002_other_rule"))
        _write_json(events_dir, "001.json", CLOUDTRAIL_EVENT)

        opencdr.cmd_test_local(_make_args(rule="001_console"))
        out = capsys.readouterr().out
        assert "Rules : 1" in out

    def test_event_filter_narrows_by_filename_substring(self, isolated_dirs, capsys):
        rules_dir, events_dir = isolated_dirs
        _write_json(rules_dir, "001.json", _console_login_rule())
        _write_json(events_dir, "001_target.json", CLOUDTRAIL_EVENT)
        _write_json(events_dir, "002_other.json", CLOUDTRAIL_EVENT)

        opencdr.cmd_test_local(_make_args(event="001_target"))
        out = capsys.readouterr().out
        assert "Events: 1" in out


# ---------------------------------------------------------------------------
# rule_kind: list support
# ---------------------------------------------------------------------------


class TestListRuleSupport:
    def test_list_kind_rule_is_loaded_as_a_list_not_a_signal_rule(self, isolated_dirs, capsys):
        rules_dir, events_dir = isolated_dirs
        _write_json(rules_dir, "001.json", _console_login_rule())
        _write_json(rules_dir, "automation.json", {
            "rule_id": "automation-identities",
            "rule_kind": "list",
            "values": ["ci-deploy-role"],
        })
        _write_json(events_dir, "001.json", CLOUDTRAIL_EVENT)

        opencdr.cmd_test_local(_make_args())
        out = capsys.readouterr().out
        # The list rule shows up in the "Lists: N" note, not counted as a
        # signal rule in "Rules : N".
        assert "Rules : 1" in out
        assert "Lists: 1" in out

    def test_malformed_rule_json_is_silently_skipped_not_fatal(self, isolated_dirs, capsys):
        rules_dir, events_dir = isolated_dirs
        _write_json(rules_dir, "001.json", _console_login_rule())
        (rules_dir / "broken.json").write_text("not valid json {{{")
        _write_json(events_dir, "001.json", CLOUDTRAIL_EVENT)

        # Should not raise on the broken file; still finds the one good rule.
        opencdr.cmd_test_local(_make_args())
        assert "Rules : 1" in capsys.readouterr().out

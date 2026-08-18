"""Tests for `opencdr.py test deployed` (cmd_test_deployed).

Primary focus: the eventID/id fallback fix -- CloudTrail fixtures carry
their id at detail.eventID, GuardDuty Finding fixtures use detail.id
instead (GuardDutyEventBridgeParser's own convention). Before the fix,
every GuardDuty fixture in support_files/test_events/ silently hit the
"no eventID" skip branch instead of ever being tested against a real
deployment -- the same class of bug this project has hit before (a
migration's naming convention not propagated to a peripheral script).

Note: cmd_test_deployed only calls sys.exit(1) when failed > 0 -- a run
with only passes/skips falls off the end of the function with no
SystemExit at all. Tests below only wrap in pytest.raises(SystemExit)
when a failure is actually expected.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

import opencdr  # noqa: E402  (after sys.path manipulation)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_args(stage="dev", region="us-east-1", event=None) -> SimpleNamespace:
    return SimpleNamespace(stage=stage, region=region, event=event)


class _FakePayload:
    """Mimics botocore's StreamingBody -- .read() returns bytes."""

    def __init__(self, data: dict):
        self._data = json.dumps(data).encode()

    def read(self):
        return self._data


def _make_lambda_client(
    *,
    status_payload: str = "processed",
    http_status: int = 200,
    invoke_side_effect=None,
    get_function_side_effect=None,
):
    client = MagicMock()
    client.get_function.side_effect = get_function_side_effect
    if invoke_side_effect is not None:
        client.invoke.side_effect = invoke_side_effect
    else:
        client.invoke.return_value = {
            "StatusCode": http_status,
            "Payload": _FakePayload({"status": status_payload}),
        }
    return client


def _make_signals_table(*, counts=None):
    """counts: Count returned per successive .query() call (last value repeats once exhausted)."""
    table = MagicMock()
    counts = list(counts) if counts is not None else [1]
    state = {"n": 0}

    def fake_query(**kwargs):
        idx = min(state["n"], len(counts) - 1)
        state["n"] += 1
        return {"Count": counts[idx]}

    table.query.side_effect = fake_query
    return table


@pytest.fixture()
def events_dir(tmp_path, monkeypatch):
    """Point EVENTS_DIR at an isolated scratch directory for full fixture control."""
    d = tmp_path / "test_events"
    d.mkdir()
    monkeypatch.setattr(opencdr, "EVENTS_DIR", d)
    return d


def _write_event(directory: Path, filename: str, data: dict) -> None:
    (directory / filename).write_text(json.dumps(data))


def _queried_event_id(query_kwargs: dict) -> str:
    """Extract the value compared against in a Key('event_id').eq(...) KeyConditionExpression."""
    return query_kwargs["KeyConditionExpression"].get_expression()["values"][1]


def _run_test_deployed(args, *, lambda_client, signals_table):
    resource = MagicMock()
    resource.Table.return_value = signals_table
    with (
        patch("boto3.client", return_value=lambda_client),
        patch("boto3.resource", return_value=resource),
        patch("time.sleep"),
    ):
        opencdr.cmd_test_deployed(args)


# ---------------------------------------------------------------------------
# eventID / id extraction -- the fix itself
# ---------------------------------------------------------------------------


class TestEventIdExtraction:
    def test_cloudtrail_shaped_fixture_uses_eventid(self, events_dir):
        _write_event(events_dir, "001_cloudtrail.json", {"detail": {"eventID": "ct-event-1"}})
        lambda_client = _make_lambda_client()
        signals_table = _make_signals_table(counts=[1])

        _run_test_deployed(_make_args(), lambda_client=lambda_client, signals_table=signals_table)

        query_kwargs = signals_table.query.call_args.kwargs
        assert _queried_event_id(query_kwargs) == "ct-event-1"

    def test_guardduty_shaped_fixture_falls_back_to_id(self, events_dir):
        # No detail.eventID at all -- exactly the real GuardDuty fixture shape.
        _write_event(events_dir, "024_guardduty.json", {"detail": {"id": "gd-finding-024"}})
        lambda_client = _make_lambda_client()
        signals_table = _make_signals_table(counts=[1])

        _run_test_deployed(_make_args(), lambda_client=lambda_client, signals_table=signals_table)

        query_kwargs = signals_table.query.call_args.kwargs
        assert _queried_event_id(query_kwargs) == "gd-finding-024"

    def test_eventid_preferred_over_id_when_both_present(self, events_dir):
        _write_event(events_dir, "both.json", {"detail": {"eventID": "ct-id", "id": "gd-id"}})
        lambda_client = _make_lambda_client()
        signals_table = _make_signals_table(counts=[1])

        _run_test_deployed(_make_args(), lambda_client=lambda_client, signals_table=signals_table)

        query_kwargs = signals_table.query.call_args.kwargs
        assert _queried_event_id(query_kwargs) == "ct-id"

    def test_neither_eventid_nor_id_is_skipped(self, events_dir, capsys):
        _write_event(events_dir, "neither.json", {"detail": {"type": "SomeFinding"}})
        lambda_client = _make_lambda_client()
        signals_table = _make_signals_table()

        _run_test_deployed(_make_args(), lambda_client=lambda_client, signals_table=signals_table)

        lambda_client.invoke.assert_not_called()
        assert "no eventID/id in detail" in capsys.readouterr().out

    def test_missing_detail_key_entirely_is_skipped(self, events_dir):
        _write_event(events_dir, "no_detail.json", {"source": "aws.guardduty"})
        lambda_client = _make_lambda_client()
        signals_table = _make_signals_table()

        _run_test_deployed(_make_args(), lambda_client=lambda_client, signals_table=signals_table)
        lambda_client.invoke.assert_not_called()

    def test_real_guardduty_fixture_in_repo_resolves_an_id(self):
        """
        Not the isolated events_dir fixture -- deliberately runs against the
        real support_files/test_events/024_guardduty_iam_credential_compromise.json
        (which genuinely has no detail.eventID, only detail.id) to prove the
        fix works against the actual shipped fixture, not just a hand-built one.
        """
        lambda_client = _make_lambda_client()
        signals_table = _make_signals_table(counts=[1])

        _run_test_deployed(
            _make_args(event="024_guardduty_iam_credential_compromise"),
            lambda_client=lambda_client,
            signals_table=signals_table,
        )
        lambda_client.invoke.assert_called_once()
        query_kwargs = signals_table.query.call_args.kwargs
        assert _queried_event_id(query_kwargs) == "gd-finding-id-024"


# ---------------------------------------------------------------------------
# Malformed input
# ---------------------------------------------------------------------------


class TestMalformedFixture:
    def test_invalid_json_is_skipped_not_fatal(self, events_dir, capsys):
        (events_dir / "broken.json").write_text("not valid json {{{")
        lambda_client = _make_lambda_client()
        signals_table = _make_signals_table()

        _run_test_deployed(_make_args(), lambda_client=lambda_client, signals_table=signals_table)
        assert "invalid JSON" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Lambda not found
# ---------------------------------------------------------------------------


class TestLambdaNotFound:
    def test_missing_lambda_exits_before_any_invoke(self, events_dir, capsys):
        _write_event(events_dir, "event.json", {"detail": {"eventID": "e1"}})
        lambda_client = _make_lambda_client(get_function_side_effect=Exception("not found"))
        signals_table = _make_signals_table()

        with pytest.raises(SystemExit) as exc_info:
            _run_test_deployed(_make_args(), lambda_client=lambda_client, signals_table=signals_table)
        assert exc_info.value.code == 1
        lambda_client.invoke.assert_not_called()
        assert "not found" in capsys.readouterr().out.lower()


# ---------------------------------------------------------------------------
# Invocation-level failures
# ---------------------------------------------------------------------------


class TestInvocationFailures:
    def test_invoke_exception_counts_as_failed(self, events_dir):
        _write_event(events_dir, "event.json", {"detail": {"eventID": "e1"}})
        lambda_client = _make_lambda_client(invoke_side_effect=Exception("throttled"))
        signals_table = _make_signals_table()

        with pytest.raises(SystemExit) as exc_info:
            _run_test_deployed(_make_args(), lambda_client=lambda_client, signals_table=signals_table)
        assert exc_info.value.code == 1
        signals_table.query.assert_not_called()

    def test_non_200_http_status_counts_as_failed(self, events_dir):
        _write_event(events_dir, "event.json", {"detail": {"eventID": "e1"}})
        lambda_client = _make_lambda_client(http_status=500)
        signals_table = _make_signals_table()

        with pytest.raises(SystemExit) as exc_info:
            _run_test_deployed(_make_args(), lambda_client=lambda_client, signals_table=signals_table)
        assert exc_info.value.code == 1
        signals_table.query.assert_not_called()


# ---------------------------------------------------------------------------
# processor.py status handling
# ---------------------------------------------------------------------------


class TestProcessorStatusBranches:
    def test_ignored_status_is_skipped_no_signal_query(self, events_dir):
        _write_event(events_dir, "event.json", {"detail": {"eventID": "e1"}})
        lambda_client = _make_lambda_client(status_payload="ignored")
        signals_table = _make_signals_table()

        _run_test_deployed(_make_args(), lambda_client=lambda_client, signals_table=signals_table)
        signals_table.query.assert_not_called()

    def test_no_detection_status_is_skipped(self, events_dir):
        _write_event(events_dir, "event.json", {"detail": {"eventID": "e1"}})
        lambda_client = _make_lambda_client(status_payload="no_detection")
        signals_table = _make_signals_table()

        _run_test_deployed(_make_args(), lambda_client=lambda_client, signals_table=signals_table)
        signals_table.query.assert_not_called()

    def test_no_rules_status_counts_as_failed(self, events_dir):
        _write_event(events_dir, "event.json", {"detail": {"eventID": "e1"}})
        lambda_client = _make_lambda_client(status_payload="no_rules")
        signals_table = _make_signals_table()

        with pytest.raises(SystemExit) as exc_info:
            _run_test_deployed(_make_args(), lambda_client=lambda_client, signals_table=signals_table)
        assert exc_info.value.code == 1

    def test_unexpected_status_counts_as_failed(self, events_dir):
        _write_event(events_dir, "event.json", {"detail": {"eventID": "e1"}})
        lambda_client = _make_lambda_client(status_payload="something_new")
        signals_table = _make_signals_table()

        with pytest.raises(SystemExit) as exc_info:
            _run_test_deployed(_make_args(), lambda_client=lambda_client, signals_table=signals_table)
        assert exc_info.value.code == 1

    def test_processed_with_signals_found_passes(self, events_dir, capsys):
        _write_event(events_dir, "event.json", {"detail": {"eventID": "e1"}})
        lambda_client = _make_lambda_client(status_payload="processed")
        signals_table = _make_signals_table(counts=[2])

        _run_test_deployed(_make_args(), lambda_client=lambda_client, signals_table=signals_table)
        assert "[PASS]" in capsys.readouterr().out

    def test_processed_with_zero_signals_counts_as_failed(self, events_dir):
        _write_event(events_dir, "event.json", {"detail": {"eventID": "e1"}})
        lambda_client = _make_lambda_client(status_payload="processed")
        signals_table = _make_signals_table(counts=[0, 0, 0, 0, 0])

        with pytest.raises(SystemExit) as exc_info:
            _run_test_deployed(_make_args(), lambda_client=lambda_client, signals_table=signals_table)
        assert exc_info.value.code == 1
        assert signals_table.query.call_count == 5

    def test_signal_query_exception_is_skipped_not_fatal(self, events_dir):
        _write_event(events_dir, "event.json", {"detail": {"eventID": "e1"}})
        lambda_client = _make_lambda_client(status_payload="processed")
        signals_table = MagicMock()
        signals_table.query.side_effect = Exception("table not found")

        _run_test_deployed(_make_args(), lambda_client=lambda_client, signals_table=signals_table)

    def test_signal_appears_on_a_later_retry(self, events_dir, capsys):
        _write_event(events_dir, "event.json", {"detail": {"eventID": "e1"}})
        lambda_client = _make_lambda_client(status_payload="processed")
        signals_table = _make_signals_table(counts=[0, 0, 1])

        _run_test_deployed(_make_args(), lambda_client=lambda_client, signals_table=signals_table)
        assert signals_table.query.call_count == 3
        assert "[PASS]" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# --event filter
# ---------------------------------------------------------------------------


class TestEventFilter:
    def test_filter_selects_only_matching_files(self, events_dir):
        _write_event(events_dir, "001_console_login.json", {"detail": {"eventID": "e1"}})
        _write_event(events_dir, "024_guardduty.json", {"detail": {"id": "gd1"}})
        lambda_client = _make_lambda_client()
        signals_table = _make_signals_table(counts=[1])

        _run_test_deployed(_make_args(event="024"), lambda_client=lambda_client, signals_table=signals_table)

        assert lambda_client.invoke.call_count == 1
        payload = json.loads(lambda_client.invoke.call_args.kwargs["Payload"])
        assert payload["detail"]["id"] == "gd1"


# ---------------------------------------------------------------------------
# Overall pass/fail exit code
# ---------------------------------------------------------------------------


class TestExitCode:
    def test_all_passing_does_not_call_sys_exit_with_error(self, events_dir):
        _write_event(events_dir, "event.json", {"detail": {"eventID": "e1"}})
        lambda_client = _make_lambda_client()
        signals_table = _make_signals_table(counts=[1])

        # cmd_test_deployed only calls sys.exit(1) when failed > 0 -- with
        # zero failures it falls off the end of the function, no SystemExit.
        _run_test_deployed(_make_args(), lambda_client=lambda_client, signals_table=signals_table)

    def test_any_failure_exits_1(self, events_dir):
        _write_event(events_dir, "event.json", {"detail": {"eventID": "e1"}})
        lambda_client = _make_lambda_client(http_status=500)
        signals_table = _make_signals_table()

        with pytest.raises(SystemExit) as exc_info:
            _run_test_deployed(_make_args(), lambda_client=lambda_client, signals_table=signals_table)
        assert exc_info.value.code == 1

    def test_summary_counts_printed(self, events_dir, capsys):
        _write_event(events_dir, "pass.json", {"detail": {"eventID": "e1"}})
        _write_event(events_dir, "skip.json", {"detail": {}})
        lambda_client = _make_lambda_client()
        signals_table = _make_signals_table(counts=[1])

        _run_test_deployed(_make_args(), lambda_client=lambda_client, signals_table=signals_table)
        out = capsys.readouterr().out
        assert "Passed  : 1" in out
        assert "Skipped : 1" in out

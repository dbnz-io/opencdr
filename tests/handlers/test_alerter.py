"""Regression-safety tests for the alerter Lambda handler.

These characterize alerter.py's *current* wiring behavior — record filtering,
correlation-rule gating, alert storage idempotency, and outbox writes — as a
safety net ahead of the roadmap fixes already identified for this file
(rule-cache invalidation, the correlation engine's table-scan lookup).

CorrelationEngine itself is unit-tested separately (tests/domain/); here it is
stubbed so these tests stay focused on whether alerter.py wires it, the
rules cache, and AwsHandler correctly.
"""
from __future__ import annotations

import os
from unittest.mock import MagicMock

import pytest
from boto3.dynamodb.types import TypeSerializer

os.environ.setdefault("LOGS_TABLE_NAME", "test-logs-table")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

import src.handlers.alerter as alerter


_ser = TypeSerializer()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_signal(**overrides) -> dict:
    base = {
        "detection_id": "det-1",
        "event_id": "evt-1",
        "rule_id": "001_console_login_no_mfa",
        "timestamp": "2026-01-01T00:00:00+00:00",
        "severity": "HIGH",
    }
    base.update(overrides)
    return base


def make_stream_record(signal: dict, event_name: str = "INSERT") -> dict:
    return {
        "eventName": event_name,
        "dynamodb": {"NewImage": {k: _ser.serialize(v) for k, v in signal.items()}},
    }


def make_event(records: list[dict]) -> dict:
    return {"Records": records}


def make_context():
    ctx = MagicMock()
    ctx.aws_request_id = "test-req-id"
    return ctx


def make_alert(**overrides) -> dict:
    base = {
        "alert_id": "alert-abc",
        "alert_key": "hash-abc",
        "rule_id": "020_correlation_console_login_bruteforce",
        "severity": "CRITICAL",
        "timestamp": "2026-01-01T00:05:00+00:00",
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def reset_rules_cache(monkeypatch):
    monkeypatch.setattr(alerter, "CORR_RULES_CACHE", None)


@pytest.fixture(autouse=True)
def default_tables(monkeypatch):
    monkeypatch.setattr(alerter, "SIGNALS_TABLE_NAME", "test-signals-table")
    monkeypatch.setattr(alerter, "ALERTS_TABLE_NAME", "test-alerts-table")
    monkeypatch.setattr(alerter, "OUTBOX_TABLE_NAME", "test-outbox-table")


@pytest.fixture
def fake_aws(monkeypatch):
    aws = MagicMock()
    aws.put_alert_if_not_exists.return_value = True
    monkeypatch.setattr(alerter, "AwsHandler", MagicMock(return_value=aws))
    return aws


@pytest.fixture
def fake_engine(monkeypatch):
    """Stubs CorrelationEngine so tests control exactly what alerts come back."""
    engine = MagicMock()
    engine.correlate.return_value = []
    monkeypatch.setattr(alerter, "CorrelationEngine", MagicMock(return_value=engine))
    return engine


@pytest.fixture
def with_correlation_rules(monkeypatch):
    monkeypatch.setattr(
        alerter,
        "load_detection_rules",
        MagicMock(return_value=[{"rule_id": "020_correlation_console_login_bruteforce", "enabled": True}]),
    )


# ---------------------------------------------------------------------------
# Record filtering
# ---------------------------------------------------------------------------


class TestRecordFiltering:
    def test_non_insert_modify_event_is_skipped(self, fake_aws, fake_engine, with_correlation_rules):
        record = make_stream_record(make_signal(), event_name="REMOVE")
        result = alerter.lambda_handler(make_event([record]), make_context())

        fake_engine.correlate.assert_not_called()
        assert result == {"status": "ok", "alerts_created": 0, "alerts_stored": 0, "outboxed": 0}

    def test_record_missing_new_image_is_skipped(self, fake_aws, fake_engine, with_correlation_rules):
        record = {"eventName": "INSERT", "dynamodb": {}}
        result = alerter.lambda_handler(make_event([record]), make_context())

        fake_engine.correlate.assert_not_called()
        assert result["alerts_created"] == 0

    def test_correlation_item_type_is_skipped(self, fake_aws, fake_engine, with_correlation_rules):
        """Loop-prevention guard: a signal already tagged item_type=correlation
        (i.e. a correlation write-back) must not be re-fed into correlate()."""
        record = make_stream_record(make_signal(item_type="correlation"))
        result = alerter.lambda_handler(make_event([record]), make_context())

        fake_engine.correlate.assert_not_called()
        assert result["alerts_created"] == 0


# ---------------------------------------------------------------------------
# Rules gating
# ---------------------------------------------------------------------------


class TestRulesGating:
    def test_no_correlation_rules_returns_early(self, fake_aws, fake_engine, monkeypatch):
        monkeypatch.setattr(alerter, "load_detection_rules", MagicMock(return_value=[]))
        record = make_stream_record(make_signal())

        result = alerter.lambda_handler(make_event([record]), make_context())

        assert result == {"status": "no_rules"}
        fake_engine.correlate.assert_not_called()

    def test_rules_are_cached_across_invocations(self, fake_aws, fake_engine, monkeypatch):
        loader = MagicMock(return_value=[{"rule_id": "corr-1", "enabled": True}])
        monkeypatch.setattr(alerter, "load_detection_rules", loader)
        record = make_stream_record(make_signal())

        alerter.lambda_handler(make_event([record]), make_context())
        alerter.lambda_handler(make_event([record]), make_context())

        loader.assert_called_once()

    def test_missing_signals_table_name_raises_before_processing(
        self, fake_aws, fake_engine, with_correlation_rules, monkeypatch
    ):
        monkeypatch.setattr(alerter, "SIGNALS_TABLE_NAME", "")
        record = make_stream_record(make_signal())

        with pytest.raises(RuntimeError, match="Missing SIGNALS_TABLE_NAME"):
            alerter.lambda_handler(make_event([record]), make_context())

        fake_engine.correlate.assert_not_called()


# ---------------------------------------------------------------------------
# Alert storage / outbox
# ---------------------------------------------------------------------------


class TestAlertStorageAndOutbox:
    def test_alert_is_stored_written_back_and_outboxed(
        self, fake_aws, fake_engine, with_correlation_rules
    ):
        fake_engine.correlate.return_value = [make_alert()]
        record = make_stream_record(make_signal())

        result = alerter.lambda_handler(make_event([record]), make_context())

        assert result == {"status": "ok", "alerts_created": 1, "alerts_stored": 1, "outboxed": 1}

        fake_aws.put_alert_if_not_exists.assert_called_once()
        _, kwargs = fake_aws.put_alert_if_not_exists.call_args
        assert kwargs["table_name"] == "test-alerts-table"
        assert kwargs["alert_item"]["alert_key"] == "hash-abc"

        fake_aws.put_signal_if_not_exists.assert_called_once()
        _, kwargs = fake_aws.put_signal_if_not_exists.call_args
        assert kwargs["table_name"] == "test-signals-table"
        assert kwargs["signal_item"]["item_type"] == "correlation"
        assert kwargs["signal_item"]["detection_id"] == "alert-abc"

        fake_aws.ddb_put_item.assert_called_once()
        _, kwargs = fake_aws.ddb_put_item.call_args
        assert kwargs["table_name"] == "test-outbox-table"

    def test_no_alerts_produced_is_a_noop(self, fake_aws, fake_engine, with_correlation_rules):
        fake_engine.correlate.return_value = []
        record = make_stream_record(make_signal())

        result = alerter.lambda_handler(make_event([record]), make_context())

        assert result == {"status": "ok", "alerts_created": 0, "alerts_stored": 0, "outboxed": 0}
        fake_aws.put_alert_if_not_exists.assert_not_called()
        fake_aws.ddb_put_item.assert_not_called()

    def test_alerts_table_unset_skips_storage_and_writeback(
        self, fake_aws, fake_engine, with_correlation_rules, monkeypatch
    ):
        monkeypatch.setattr(alerter, "ALERTS_TABLE_NAME", "")
        fake_engine.correlate.return_value = [make_alert()]
        record = make_stream_record(make_signal())

        result = alerter.lambda_handler(make_event([record]), make_context())

        # Alert is still "created" (computed) but never stored or written back —
        # note storage and outbox are gated independently, so outboxed still fires.
        assert result["alerts_created"] == 1
        assert result["alerts_stored"] == 0
        assert result["outboxed"] == 1
        fake_aws.put_alert_if_not_exists.assert_not_called()
        fake_aws.put_signal_if_not_exists.assert_not_called()

    def test_outbox_table_unset_skips_outbox_only(
        self, fake_aws, fake_engine, with_correlation_rules, monkeypatch
    ):
        monkeypatch.setattr(alerter, "OUTBOX_TABLE_NAME", "")
        fake_engine.correlate.return_value = [make_alert()]
        record = make_stream_record(make_signal())

        result = alerter.lambda_handler(make_event([record]), make_context())

        assert result["alerts_stored"] == 1
        assert result["outboxed"] == 0
        fake_aws.ddb_put_item.assert_not_called()

    def test_duplicate_alert_not_double_counted_and_not_re_outboxed(
        self, fake_aws, fake_engine, with_correlation_rules
    ):
        """Fixed: put_alert_if_not_exists returning False means the alert
        already existed -- stored_alerts must not increment, the
        correlation write-back must not happen, and (fixed) the outbox
        write is now gated on the same "genuinely new" condition, so a
        duplicate is no longer re-outboxed either."""
        fake_aws.put_alert_if_not_exists.return_value = False
        fake_engine.correlate.return_value = [make_alert()]
        record = make_stream_record(make_signal())

        result = alerter.lambda_handler(make_event([record]), make_context())

        assert result["alerts_created"] == 1
        assert result["alerts_stored"] == 0
        assert result["outboxed"] == 0
        fake_aws.put_signal_if_not_exists.assert_not_called()
        fake_aws.ddb_put_item.assert_not_called()

    def test_multiple_alerts_from_one_signal_all_processed(
        self, fake_aws, fake_engine, with_correlation_rules
    ):
        fake_engine.correlate.return_value = [
            make_alert(alert_id="a1", alert_key="k1"),
            make_alert(alert_id="a2", alert_key="k2"),
        ]
        record = make_stream_record(make_signal())

        result = alerter.lambda_handler(make_event([record]), make_context())

        assert result == {"status": "ok", "alerts_created": 2, "alerts_stored": 2, "outboxed": 2}
        assert fake_aws.put_alert_if_not_exists.call_count == 2
        assert fake_aws.ddb_put_item.call_count == 2


# ---------------------------------------------------------------------------
# Batch handling
# ---------------------------------------------------------------------------


class TestBatchHandling:
    def test_mixed_batch_only_valid_records_reach_correlate(
        self, fake_aws, fake_engine, with_correlation_rules
    ):
        skip_event_name = make_stream_record(make_signal(event_id="skip-1"), event_name="REMOVE")
        skip_missing_image = {"eventName": "INSERT", "dynamodb": {}}
        skip_correlation = make_stream_record(make_signal(event_id="skip-2", item_type="correlation"))
        valid_one = make_stream_record(make_signal(event_id="valid-1"))
        valid_two = make_stream_record(make_signal(event_id="valid-2"))

        fake_engine.correlate.side_effect = [
            [make_alert(alert_id="a1", alert_key="k1")],
            [],
        ]

        result = alerter.lambda_handler(
            make_event([skip_event_name, skip_missing_image, skip_correlation, valid_one, valid_two]),
            make_context(),
        )

        assert fake_engine.correlate.call_count == 2
        assert result == {"status": "ok", "alerts_created": 1, "alerts_stored": 1, "outboxed": 1}

    def test_empty_records_list_returns_ok_with_zero_counts(
        self, fake_aws, fake_engine, with_correlation_rules
    ):
        result = alerter.lambda_handler(make_event([]), make_context())
        assert result == {"status": "ok", "alerts_created": 0, "alerts_stored": 0, "outboxed": 0}

    def test_missing_records_key_defaults_to_empty(self, fake_aws, fake_engine, with_correlation_rules):
        result = alerter.lambda_handler({}, make_context())
        assert result == {"status": "ok", "alerts_created": 0, "alerts_stored": 0, "outboxed": 0}


# ---------------------------------------------------------------------------
# _parse_iso
# ---------------------------------------------------------------------------


class TestParseIso:
    def test_parses_zulu_suffix(self):
        dt = alerter._parse_iso("2026-01-01T00:00:00Z")
        assert dt is not None
        assert dt.year == 2026 and dt.tzinfo is not None

    def test_parses_explicit_offset(self):
        dt = alerter._parse_iso("2026-01-01T00:00:00+00:00")
        assert dt is not None

    def test_naive_timestamp_is_assumed_utc(self):
        dt = alerter._parse_iso("2026-01-01T00:00:00")
        assert dt is not None
        assert dt.tzinfo is alerter.UTC

    def test_none_input_returns_none(self):
        assert alerter._parse_iso(None) is None

    def test_non_string_input_returns_none(self):
        assert alerter._parse_iso(12345) is None

    def test_empty_string_returns_none(self):
        assert alerter._parse_iso("") is None

    def test_malformed_string_returns_none(self):
        assert alerter._parse_iso("not-a-date") is None


# ---------------------------------------------------------------------------
# DynamoSignalsRepository — signal lookups backing correlation.
#
# group_by_field="actor.user_name" (the only group_by any real correlation
# rule uses) is indexed (_INDEXED_GROUP_BY_FIELDS) and goes through
# _query_via_gsi -- a Query against gsi_signal_actor_user_name, not a Scan.
# Any other group_by_field falls back to _scan_and_filter, the original
# full-table scan-and-filter -- correct for an arbitrary dot-path, but
# expensive, and now a rare/generic path rather than the only one.
# ---------------------------------------------------------------------------


def make_ddb_item(**overrides) -> dict:
    """A signal already marshalled into DynamoDB AttributeValue shape, as
    the _scan_and_filter fallback's _deser expects from a raw scan
    response. Only used by TestDynamoSignalsRepositoryScanFallback below --
    the GSI/Query path returns plain Python dicts (resource-based)."""
    plain = {
        "detection_id": "det-1",
        "rule_id": "001_console_login_no_mfa",
        "timestamp": "2026-01-01T00:10:00+00:00",
        "actor": {"user_name": "alice"},
    }
    plain.update(overrides)
    return {k: _ser.serialize(v) for k, v in plain.items()}


def _key_condition_parts(expr) -> list[tuple[str, str, str]]:
    """Extract (attribute_name, operator, value) tuples from a
    Key(...).eq(...) & Key(...).gte(...) KeyConditionExpression, so tests
    can assert on the actual attribute/operator/value without depending on
    boto3's internal repr."""
    parts = []
    for leaf in expr.get_expression()["values"]:
        leaf_expr = leaf.get_expression()
        attr = leaf_expr["values"][0].name
        value = leaf_expr["values"][1]
        parts.append((attr, leaf_expr["operator"], value))
    return parts


class TestDynamoSignalsRepository:
    def _repo(self, aws=None, table_name="test-signals-table"):
        aws = aws or MagicMock()
        logger = MagicMock()
        return alerter.DynamoSignalsRepository(aws=aws, logger=logger, table_name=table_name), aws

    def test_empty_table_name_returns_empty_without_querying_anything(self):
        repo, aws = self._repo(table_name="")
        result = repo.query_signals(
            since=alerter.datetime(2020, 1, 1, tzinfo=alerter.UTC),
            group_by_field="actor.user_name",
            group_value="alice",
        )
        assert result == []
        aws._ddb.scan.assert_not_called()
        aws._ddb_resource.Table.assert_not_called()


class TestDynamoSignalsRepositoryGsiPath:
    def _repo(self, aws=None, table_name="test-signals-table"):
        aws = aws or MagicMock()
        logger = MagicMock()
        return alerter.DynamoSignalsRepository(aws=aws, logger=logger, table_name=table_name), aws

    def test_queries_the_actor_user_name_gsi(self):
        aws = MagicMock()
        mock_table = aws._ddb_resource.Table.return_value
        mock_table.query.return_value = {"Items": []}
        repo, _ = self._repo(aws=aws)

        repo.query_signals(
            since=alerter.datetime(2020, 1, 1, tzinfo=alerter.UTC),
            group_by_field="actor.user_name",
            group_value="alice",
        )

        aws._ddb_resource.Table.assert_called_once_with("test-signals-table")
        call_kwargs = mock_table.query.call_args.kwargs
        assert call_kwargs["IndexName"] == "gsi_signal_actor_user_name"
        parts = _key_condition_parts(call_kwargs["KeyConditionExpression"])
        assert ("actor_user_name", "=", "alice") in parts
        assert ("timestamp", ">=", "2020-01-01T00:00:00+00:00") in parts
        aws._ddb.scan.assert_not_called()

    def test_returns_items_from_the_query(self):
        aws = MagicMock()
        mock_table = aws._ddb_resource.Table.return_value
        mock_table.query.return_value = {
            "Items": [{"detection_id": "match", "actor_user_name": "alice"}]
        }
        repo, _ = self._repo(aws=aws)

        result = repo.query_signals(
            since=alerter.datetime(2020, 1, 1, tzinfo=alerter.UTC),
            group_by_field="actor.user_name",
            group_value="alice",
        )

        assert [r["detection_id"] for r in result] == ["match"]

    def test_skips_correlation_item_type(self):
        aws = MagicMock()
        mock_table = aws._ddb_resource.Table.return_value
        mock_table.query.return_value = {
            "Items": [
                {"detection_id": "corr", "item_type": "correlation", "actor_user_name": "alice"},
                {"detection_id": "real", "actor_user_name": "alice"},
            ]
        }
        repo, _ = self._repo(aws=aws)

        result = repo.query_signals(
            since=alerter.datetime(2020, 1, 1, tzinfo=alerter.UTC),
            group_by_field="actor.user_name",
            group_value="alice",
        )

        assert [r["detection_id"] for r in result] == ["real"]

    def test_paginates_via_last_evaluated_key(self):
        aws = MagicMock()
        mock_table = aws._ddb_resource.Table.return_value
        mock_table.query.side_effect = [
            {
                "Items": [{"detection_id": "page1", "actor_user_name": "alice"}],
                "LastEvaluatedKey": {"actor_user_name": "alice", "timestamp": "2026-01-01T00:10:00+00:00"},
            },
            {"Items": [{"detection_id": "page2", "actor_user_name": "alice"}]},
        ]
        repo, _ = self._repo(aws=aws)

        result = repo.query_signals(
            since=alerter.datetime(2020, 1, 1, tzinfo=alerter.UTC),
            group_by_field="actor.user_name",
            group_value="alice",
        )

        assert mock_table.query.call_count == 2
        assert {r["detection_id"] for r in result} == {"page1", "page2"}
        # second call must carry ExclusiveStartKey forward from the first page
        second_call_kwargs = mock_table.query.call_args_list[1].kwargs
        assert second_call_kwargs["ExclusiveStartKey"] == {
            "actor_user_name": "alice",
            "timestamp": "2026-01-01T00:10:00+00:00",
        }

    def test_stops_once_limit_reached_within_a_page(self):
        aws = MagicMock()
        mock_table = aws._ddb_resource.Table.return_value
        mock_table.query.return_value = {
            "Items": [{"detection_id": f"item-{i}", "actor_user_name": "alice"} for i in range(5)]
        }
        repo, _ = self._repo(aws=aws)

        result = repo.query_signals(
            since=alerter.datetime(2020, 1, 1, tzinfo=alerter.UTC),
            group_by_field="actor.user_name",
            group_value="alice",
            limit=2,
        )

        assert len(result) == 2
        # only one query call — the limit is hit within the first page, so no further pagination
        mock_table.query.assert_called_once()

    def test_query_mode_logged_as_gsi(self):
        aws = MagicMock()
        aws._ddb_resource.Table.return_value.query.return_value = {"Items": []}
        logger = MagicMock()
        repo = alerter.DynamoSignalsRepository(aws=aws, logger=logger, table_name="test-signals-table")

        repo.query_signals(
            since=alerter.datetime(2020, 1, 1, tzinfo=alerter.UTC),
            group_by_field="actor.user_name",
            group_value="alice",
        )

        assert logger.info.call_args.kwargs["details"]["query_mode"] == "gsi"


class TestDynamoSignalsRepositoryScanFallback:
    """group_by_field values with no GSI (anything not in
    _INDEXED_GROUP_BY_FIELDS) fall back to the original scan-and-filter
    logic. No real correlation rule hits this path today -- exercised here
    via "network.source_ip" purely to prove the fallback still works."""

    def _repo(self, aws=None, table_name="test-signals-table"):
        aws = aws or MagicMock()
        logger = MagicMock()
        return alerter.DynamoSignalsRepository(aws=aws, logger=logger, table_name=table_name), aws

    def test_filters_by_group_value_dot_path(self):
        aws = MagicMock()
        aws._ddb.scan.return_value = {
            "Items": [
                make_ddb_item(detection_id="match", network={"source_ip": "1.1.1.1"}),
                make_ddb_item(detection_id="no-match", network={"source_ip": "2.2.2.2"}),
            ]
        }
        repo, _ = self._repo(aws=aws)

        result = repo.query_signals(
            since=alerter.datetime(2020, 1, 1, tzinfo=alerter.UTC),
            group_by_field="network.source_ip",
            group_value="1.1.1.1",
        )

        assert [r["detection_id"] for r in result] == ["match"]
        aws._ddb_resource.Table.assert_not_called()

    def test_skips_correlation_item_type(self):
        aws = MagicMock()
        aws._ddb.scan.return_value = {
            "Items": [
                make_ddb_item(detection_id="corr", item_type="correlation", network={"source_ip": "1.1.1.1"}),
                make_ddb_item(detection_id="real", network={"source_ip": "1.1.1.1"}),
            ]
        }
        repo, _ = self._repo(aws=aws)

        result = repo.query_signals(
            since=alerter.datetime(2020, 1, 1, tzinfo=alerter.UTC),
            group_by_field="network.source_ip",
            group_value="1.1.1.1",
        )

        assert [r["detection_id"] for r in result] == ["real"]

    def test_filters_out_signals_older_than_since(self):
        aws = MagicMock()
        aws._ddb.scan.return_value = {
            "Items": [
                make_ddb_item(
                    detection_id="old", timestamp="2020-01-01T00:00:00+00:00", network={"source_ip": "1.1.1.1"}
                ),
                make_ddb_item(
                    detection_id="new", timestamp="2030-01-01T00:00:00+00:00", network={"source_ip": "1.1.1.1"}
                ),
            ]
        }
        repo, _ = self._repo(aws=aws)

        result = repo.query_signals(
            since=alerter.datetime(2025, 1, 1, tzinfo=alerter.UTC),
            group_by_field="network.source_ip",
            group_value="1.1.1.1",
        )

        assert [r["detection_id"] for r in result] == ["new"]

    def test_missing_group_by_field_is_excluded(self):
        aws = MagicMock()
        aws._ddb.scan.return_value = {"Items": [make_ddb_item(detection_id="no-ip", network={})]}
        repo, _ = self._repo(aws=aws)

        result = repo.query_signals(
            since=alerter.datetime(2020, 1, 1, tzinfo=alerter.UTC),
            group_by_field="network.source_ip",
            group_value="1.1.1.1",
        )

        assert result == []

    def test_paginates_via_last_evaluated_key(self):
        aws = MagicMock()
        aws._ddb.scan.side_effect = [
            {
                "Items": [make_ddb_item(detection_id="page1", network={"source_ip": "1.1.1.1"})],
                "LastEvaluatedKey": {"detection_id": {"S": "page1"}},
            },
            {"Items": [make_ddb_item(detection_id="page2", network={"source_ip": "1.1.1.1"})]},
        ]
        repo, _ = self._repo(aws=aws)

        result = repo.query_signals(
            since=alerter.datetime(2020, 1, 1, tzinfo=alerter.UTC),
            group_by_field="network.source_ip",
            group_value="1.1.1.1",
        )

        assert aws._ddb.scan.call_count == 2
        assert {r["detection_id"] for r in result} == {"page1", "page2"}
        # second call must carry ExclusiveStartKey forward from the first page
        _, second_call_kwargs = aws._ddb.scan.call_args_list[1]
        assert second_call_kwargs["ExclusiveStartKey"] == {"detection_id": {"S": "page1"}}

    def test_stops_once_limit_reached_within_a_page(self):
        aws = MagicMock()
        aws._ddb.scan.return_value = {
            "Items": [
                make_ddb_item(detection_id=f"item-{i}", network={"source_ip": "1.1.1.1"}) for i in range(5)
            ]
        }
        repo, _ = self._repo(aws=aws)

        result = repo.query_signals(
            since=alerter.datetime(2020, 1, 1, tzinfo=alerter.UTC),
            group_by_field="network.source_ip",
            group_value="1.1.1.1",
            limit=2,
        )

        assert len(result) == 2
        # only one scan call — the limit is hit within the first page, so no further pagination
        aws._ddb.scan.assert_called_once()

    def test_logs_fallback_warning(self):
        aws = MagicMock()
        aws._ddb.scan.return_value = {"Items": []}
        logger = MagicMock()
        repo = alerter.DynamoSignalsRepository(aws=aws, logger=logger, table_name="test-signals-table")

        repo.query_signals(
            since=alerter.datetime(2020, 1, 1, tzinfo=alerter.UTC),
            group_by_field="network.source_ip",
            group_value="1.1.1.1",
        )

        logger.warning.assert_called_once()
        assert logger.warning.call_args.kwargs["event_name"] == "ALERTER_SIGNALS_SCAN_FALLBACK"

    def test_query_mode_logged_as_scan(self):
        aws = MagicMock()
        aws._ddb.scan.return_value = {"Items": []}
        logger = MagicMock()
        repo = alerter.DynamoSignalsRepository(aws=aws, logger=logger, table_name="test-signals-table")

        repo.query_signals(
            since=alerter.datetime(2020, 1, 1, tzinfo=alerter.UTC),
            group_by_field="network.source_ip",
            group_value="1.1.1.1",
        )

        assert logger.info.call_args.kwargs["details"]["query_mode"] == "scan"

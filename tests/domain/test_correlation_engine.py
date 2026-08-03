from datetime import UTC, datetime, timedelta
from typing import Any

from src.domain.correlation_engine import CorrelationEngine

# ----------------------------
# Fake in-memory SignalsRepository
# ----------------------------


class FakeSignalsRepo:
    """
    Drop-in implementation of the SignalsRepository Protocol.
    Stores signals in memory and filters by group field/value and time window.
    """

    def __init__(self, signals: list[dict[str, Any]] = None):
        self._signals = signals or []

    def query_signals(
        self,
        *,
        since: datetime,
        group_by_field: str,
        group_value: str,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        results = []
        for s in self._signals:
            # Filter by group field value
            val = self._get(s, group_by_field)
            if str(val) != group_value:
                continue
            # Filter by time window
            ts = s.get("timestamp")
            if ts:
                t = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                if t < since:
                    continue
            results.append(s)
        return results[:limit]

    @staticmethod
    def _get(obj, path):
        cur = obj
        for part in path.split("."):
            if isinstance(cur, dict):
                cur = cur.get(part)
            else:
                return None
            if cur is None:
                return None
        return cur


# ----------------------------
# Helpers
# ----------------------------

NOW = datetime(2026, 3, 1, 12, 0, 0, tzinfo=UTC)


def ts(offset_seconds: int = 0) -> str:
    return (NOW + timedelta(seconds=offset_seconds)).isoformat()


def make_signal(
    *,
    user_name: str = "alice",
    rule_id: str = "signal-001",
    activity_name: str = "ConsoleLogin",
    error_code: str = None,
    timestamp: str = None,
) -> dict[str, Any]:
    return {
        "detection_id": f"det-{user_name}-{timestamp or ts()}",
        "event_id": f"evt-{user_name}",
        "rule_id": rule_id,
        "timestamp": timestamp or ts(),
        "severity": "HIGH",
        "activity_name": activity_name,
        "actor": {"user_name": user_name, "account_id": "123456789012"},
        "api": {
            "service": "signin.amazonaws.com",
            "operation": activity_name,
            "error_code": error_code,
        },
        "network": {"source_ip": "1.2.3.4"},
        "category": "authn",
        "class_name": "authentication",
        "source": "cloudtrail",
        "cloud_account_id": "123456789012",
        "cloud_region": "us-east-1",
    }


def make_rule(
    *,
    rule_id: str = "corr-001",
    group_by: str = "actor.user_name",
    threshold: int = 3,
    time_window_seconds: int = 300,
    signal_conditions: list[dict] = None,
    severity: str = "CRITICAL",
    enabled: bool = True,
    notify: bool = True,
    response_module: str = "",
) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "rule_kind": "correlation",
        "enabled": enabled,
        "severity": severity,
        "group_by": group_by,
        "time_window_seconds": time_window_seconds,
        "threshold": threshold,
        "signal_conditions": signal_conditions or [],
        "notify": notify,
        "response_module": response_module,
        "playbook": "Review and disable the actor.",
    }


def engine_with(signals) -> CorrelationEngine:
    return CorrelationEngine(repo=FakeSignalsRepo(signals))


# ----------------------------
# Threshold logic
# ----------------------------


class TestThreshold:
    def test_below_threshold_no_alert(self):
        signals = [make_signal(timestamp=ts(-i * 10)) for i in range(2)]
        rule = make_rule(threshold=3)
        new_signal = make_signal()
        alerts = engine_with(signals).correlate(new_signal=new_signal, rules=[rule], now=NOW)
        assert alerts == []

    def test_at_threshold_fires_alert(self):
        signals = [make_signal(timestamp=ts(-i * 10)) for i in range(3)]
        rule = make_rule(threshold=3)
        new_signal = make_signal()
        alerts = engine_with(signals).correlate(new_signal=new_signal, rules=[rule], now=NOW)
        assert len(alerts) == 1

    def test_above_threshold_fires_single_alert(self):
        signals = [make_signal(timestamp=ts(-i * 10)) for i in range(10)]
        rule = make_rule(threshold=3)
        new_signal = make_signal()
        alerts = engine_with(signals).correlate(new_signal=new_signal, rules=[rule], now=NOW)
        assert len(alerts) == 1

    def test_threshold_one_fires_on_single_signal(self):
        signals = [make_signal()]
        rule = make_rule(threshold=1)
        alerts = engine_with(signals).correlate(new_signal=signals[0], rules=[rule], now=NOW)
        assert len(alerts) == 1


# ----------------------------
# Time window
# ----------------------------


class TestTimeWindow:
    def test_signals_outside_window_excluded(self):
        old = make_signal(timestamp=ts(-600))  # 10 min ago, outside 5 min window
        recent = make_signal(timestamp=ts(-60))  # 1 min ago, inside window
        rule = make_rule(threshold=2, time_window_seconds=300)
        new_signal = make_signal()
        alerts = engine_with([old, recent]).correlate(new_signal=new_signal, rules=[rule], now=NOW)
        # Only 1 recent signal in window, threshold=2, no alert
        assert alerts == []

    def test_signals_inside_window_counted(self):
        signals = [make_signal(timestamp=ts(-60 * i)) for i in range(3)]  # 0, 1, 2 min ago
        rule = make_rule(threshold=3, time_window_seconds=300)
        new_signal = make_signal()
        alerts = engine_with(signals).correlate(new_signal=new_signal, rules=[rule], now=NOW)
        assert len(alerts) == 1

    def test_boundary_signal_exactly_at_window_start_is_included(self):
        boundary = make_signal(timestamp=ts(-300))  # exactly at window edge — inclusive
        rule = make_rule(threshold=1, time_window_seconds=300)
        alerts = engine_with([boundary]).correlate(new_signal=boundary, rules=[rule], now=NOW)
        assert len(alerts) == 1


# ----------------------------
# Grouping
# ----------------------------


class TestGrouping:
    def test_signals_for_different_users_not_counted_together(self):
        alice_signals = [make_signal(user_name="alice", timestamp=ts(-i * 10)) for i in range(3)]
        bob_signal = make_signal(user_name="bob")
        rule = make_rule(threshold=3)
        # Bob triggers correlation — only bob's signals count; bob has 0 in repo
        alerts = engine_with(alice_signals).correlate(new_signal=bob_signal, rules=[rule], now=NOW)
        assert alerts == []

    def test_only_matching_group_value_counted(self):
        alice_signals = [make_signal(user_name="alice", timestamp=ts(-i * 10)) for i in range(3)]
        alice_signal = make_signal(user_name="alice")
        rule = make_rule(threshold=3)
        alerts = engine_with(alice_signals).correlate(
            new_signal=alice_signal, rules=[rule], now=NOW
        )
        assert len(alerts) == 1
        assert alerts[0]["group_value"] == "alice"

    def test_missing_group_by_field_skips_rule(self):
        signal_no_actor = {
            "detection_id": "d1",
            "event_id": "e1",
            "rule_id": "r1",
            "timestamp": ts(),
            "severity": "HIGH",
            "activity_name": "CreateUser",
            "actor": {},  # user_name missing
            "api": {},
            "network": {},
            "category": "iam",
        }
        rule = make_rule(threshold=1, group_by="actor.user_name")
        alerts = engine_with([signal_no_actor]).correlate(
            new_signal=signal_no_actor, rules=[rule], now=NOW
        )
        assert alerts == []


# ----------------------------
# Signal conditions filtering
# ----------------------------


class TestSignalConditions:
    def test_conditions_filter_unmatched_signals(self):
        """Only signals matching the rule's signal_conditions count toward the threshold."""
        matching = [
            make_signal(activity_name="ConsoleLogin", timestamp=ts(-i * 10)) for i in range(3)
        ]
        non_matching = [
            make_signal(activity_name="CreateUser", timestamp=ts(-i * 10 - 5)) for i in range(5)
        ]
        rule = make_rule(
            threshold=3,
            signal_conditions=[{"field": "activity_name", "op": "equals", "value": "ConsoleLogin"}],
        )
        new_signal = make_signal(activity_name="ConsoleLogin")
        alerts = engine_with(matching + non_matching).correlate(
            new_signal=new_signal, rules=[rule], now=NOW
        )
        assert len(alerts) == 1

    def test_no_matching_signals_with_conditions(self):
        signals = [make_signal(activity_name="CreateUser", timestamp=ts(-i * 10)) for i in range(5)]
        rule = make_rule(
            threshold=3,
            signal_conditions=[{"field": "activity_name", "op": "equals", "value": "ConsoleLogin"}],
        )
        new_signal = make_signal(activity_name="ConsoleLogin")
        alerts = engine_with(signals).correlate(new_signal=new_signal, rules=[rule], now=NOW)
        assert alerts == []

    def test_new_signal_itself_must_match_conditions(self):
        """If the incoming signal doesn't match rule conditions, the rule is skipped entirely."""
        signals = [
            make_signal(activity_name="ConsoleLogin", timestamp=ts(-i * 10)) for i in range(5)
        ]
        rule = make_rule(
            threshold=1,
            signal_conditions=[{"field": "activity_name", "op": "equals", "value": "ConsoleLogin"}],
        )
        # Incoming signal has wrong activity — rule should be skipped
        wrong_signal = make_signal(activity_name="CreateUser")
        alerts = engine_with(signals).correlate(new_signal=wrong_signal, rules=[rule], now=NOW)
        assert alerts == []


# ----------------------------
# Alert idempotency
# ----------------------------


class TestAlertKey:
    def test_same_rule_group_window_produces_same_alert_key(self):
        signals = [make_signal(timestamp=ts(-i * 10)) for i in range(3)]
        rule = make_rule(threshold=3)
        new_signal = make_signal()

        eng = engine_with(signals)
        alerts_1 = eng.correlate(new_signal=new_signal, rules=[rule], now=NOW)
        alerts_2 = eng.correlate(new_signal=new_signal, rules=[rule], now=NOW)

        assert alerts_1[0]["alert_key"] == alerts_2[0]["alert_key"]

    def test_different_group_values_produce_different_alert_keys(self):
        alice_signals = [make_signal(user_name="alice", timestamp=ts(-i * 10)) for i in range(3)]
        bob_signals = [make_signal(user_name="bob", timestamp=ts(-i * 10)) for i in range(3)]
        rule = make_rule(threshold=3)

        eng_alice = engine_with(alice_signals)
        eng_bob = engine_with(bob_signals)

        alert_alice = eng_alice.correlate(
            new_signal=make_signal(user_name="alice"), rules=[rule], now=NOW
        )
        alert_bob = eng_bob.correlate(
            new_signal=make_signal(user_name="bob"), rules=[rule], now=NOW
        )

        assert alert_alice[0]["alert_key"] != alert_bob[0]["alert_key"]

    def test_different_rules_produce_different_alert_keys(self):
        signals = [make_signal(timestamp=ts(-i * 10)) for i in range(3)]
        rule_a = make_rule(rule_id="corr-A", threshold=3)
        rule_b = make_rule(rule_id="corr-B", threshold=3)
        new_signal = make_signal()

        eng = engine_with(signals)
        alerts_a = eng.correlate(new_signal=new_signal, rules=[rule_a], now=NOW)
        alerts_b = eng.correlate(new_signal=new_signal, rules=[rule_b], now=NOW)

        assert alerts_a[0]["alert_key"] != alerts_b[0]["alert_key"]


# ----------------------------
# Alert payload
# ----------------------------


class TestAlertPayload:
    def setup_method(self):
        signals = [make_signal(timestamp=ts(-i * 10)) for i in range(3)]
        rule = make_rule(threshold=3, severity="CRITICAL", response_module="disable_user")
        new_signal = make_signal()
        self.alert = engine_with(signals).correlate(new_signal=new_signal, rules=[rule], now=NOW)[0]

    def test_alert_has_required_fields(self):
        for field in (
            "alert_id",
            "alert_key",
            "timestamp",
            "rule_id",
            "severity",
            "group_by",
            "group_value",
            "threshold",
            "match_count",
            "signal_refs",
            "primary_signal",
            "signals_summary",
        ):
            assert field in self.alert, f"missing field: {field}"

    def test_alert_severity(self):
        assert self.alert["severity"] == "CRITICAL"

    def test_alert_response_module(self):
        assert self.alert["response_module"] == "disable_user"

    def test_alert_group_value(self):
        assert self.alert["group_value"] == "alice"

    def test_alert_match_count(self):
        assert self.alert["match_count"] == 3

    def test_signal_refs_bounded(self):
        assert len(self.alert["signal_refs"]) <= 25

    def test_signals_summary_bounded(self):
        assert len(self.alert["signals_summary"]) <= 10

    def test_alert_type_is_correlation(self):
        assert self.alert["type"] == "correlation"


# ----------------------------
# Disabled rules
# ----------------------------


class TestDisabledRules:
    def test_disabled_rule_produces_no_alert(self):
        signals = [make_signal(timestamp=ts(-i * 10)) for i in range(5)]
        rule = make_rule(threshold=1, enabled=False)
        new_signal = make_signal()
        alerts = engine_with(signals).correlate(new_signal=new_signal, rules=[rule], now=NOW)
        assert alerts == []

    def test_only_enabled_rules_fire(self):
        signals = [make_signal(timestamp=ts(-i * 10)) for i in range(3)]
        rules = [
            make_rule(rule_id="enabled-rule", threshold=3, enabled=True),
            make_rule(rule_id="disabled-rule", threshold=1, enabled=False),
        ]
        new_signal = make_signal()
        alerts = engine_with(signals).correlate(new_signal=new_signal, rules=rules, now=NOW)
        assert len(alerts) == 1
        assert alerts[0]["rule_id"] == "enabled-rule"


# ----------------------------
# Multiple rules
# ----------------------------


class TestMultipleRules:
    def test_multiple_rules_can_fire_independently(self):
        signals = [make_signal(timestamp=ts(-i * 10)) for i in range(5)]
        rules = [
            make_rule(rule_id="r1", threshold=3),
            make_rule(rule_id="r2", threshold=5),
        ]
        new_signal = make_signal()
        alerts = engine_with(signals).correlate(new_signal=new_signal, rules=rules, now=NOW)
        assert len(alerts) == 2
        rule_ids = {a["rule_id"] for a in alerts}
        assert rule_ids == {"r1", "r2"}

    def test_empty_rules_list_produces_no_alerts(self):
        signals = [make_signal(timestamp=ts(-i * 10)) for i in range(5)]
        new_signal = make_signal()
        alerts = engine_with(signals).correlate(new_signal=new_signal, rules=[], now=NOW)
        assert alerts == []

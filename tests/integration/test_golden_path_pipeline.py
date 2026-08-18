"""
Golden-path pipeline test: a real CloudTrail fixture -> the real parser ->
the real correlation engine -> the real extractors responder.py uses to
decide what to act on.

Motivated directly by INFORME-AUTOR-ES.md §1.1: `disable_user` on every
correlation-rule alert was a silent no-op, invisible behind 800+ passing
unit tests, because every existing responder test fed it a hand-typed
dict (`{"user_name": "bob"}`) that the real pipeline never produces. This
test instead builds the alert the same way alerter.py's own code does --
via the real ocsf_min_parser + detection_engine + correlation_engine --
and asserts the real `dredge.aws_ir.response.*` call receives the correct
argument. It would have failed before the §1.1 fix and must keep passing
after it, on every future extractor change.

Scope: from a raw EventBridge-shaped fixture through to the dredge call
argument. Does NOT invoke the actual processor/alerter/responder Lambda
handlers (their own AWS read/write behavior -- DynamoDB puts, SQS sends --
is already covered elsewhere); it exercises the domain layer that builds
the alert and the responder extraction layer that consumes it, which is
exactly the boundary where §1.1 broke.
"""

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

from dredge.aws_ir.models import OperationResult

from src.domain.correlation_engine import CorrelationEngine
from src.domain.detection_engine import build_detection_event
from src.domain.ocsf_min_parser import build_default_router
from src.handlers import ir_rollback, responder

FIXTURES_DIR = Path(__file__).resolve().parents[2] / "support_files" / "test_events"
DETECTION_RULES_DIR = Path(__file__).resolve().parents[2] / "support_files" / "detection_rules"
RULES_DIR = DETECTION_RULES_DIR / "cloudtrail"
GUARDDUTY_RULES_DIR = DETECTION_RULES_DIR / "guardduty"
CORRELATION_RULES_DIR = DETECTION_RULES_DIR / "correlation"


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text())


def _make_signal(fixture_name: str, rule_name: str, *, rules_dir: Path = RULES_DIR) -> dict:
    """Real parse + real detection-build, same functions processor.py calls."""
    raw_event = _load_json(FIXTURES_DIR / fixture_name)
    rule = _load_json(rules_dir / rule_name)

    router = build_default_router()
    normalized = router.parse(raw_event)
    assert normalized is not None, f"{fixture_name} didn't parse -- fixture or parser broken"

    return build_detection_event(normalized, rule)


class _FakeSignalsRepository:
    """Returns a fixed set of prior signals, enough to clear any threshold
    used in this file. Real query_signals() interface, no DynamoDB."""

    def __init__(self, signals: list[dict]) -> None:
        self._signals = signals

    def query_signals(self, *, since, group_by_field, group_value, limit=200):
        return self._signals


def _sqs_record(body_obj: dict) -> dict:
    return {"body": json.dumps(body_obj), "receiptHandle": "rh-golden-path"}


def test_correlation_alert_disable_user_receives_real_actor_user_name(monkeypatch):
    """This is the exact §1.1 scenario: a rule_021-shaped correlation alert
    (group_by=actor.user_name, response_module=disable_user), built by the
    real correlation engine from a real IAM-event fixture, must resolve to
    the fixture's actor.user_name ("attacker") when responder executes it --
    not None."""
    signal = _make_signal("009_admin_policy_attached.json", "009_admin_policy_attached.json")
    assert signal["category"] == "iam"
    assert signal["actor"]["user_name"] == "attacker"
    assert signal["api"].get("error_code") is None

    correlation_rule = _load_json(RULES_DIR / "021_correlation_iam_activity_burst.json")
    assert correlation_rule["response_module"] == "disable_user"
    threshold = correlation_rule["threshold"]

    repo = _FakeSignalsRepository([signal] * threshold)
    engine = CorrelationEngine(repo=repo)
    alerts = engine.correlate(
        new_signal=signal,
        rules=[correlation_rule],
        now=datetime.now(UTC),
    )

    assert len(alerts) == 1, "correlation engine didn't fire -- fixture/rule threshold mismatch"
    alert = alerts[0]
    assert alert["group_value"] == "attacker"
    assert alert["primary_signal"]["actor"]["user_name"] == "attacker"

    # This is the real SQS message body responder.py receives -- see
    # publisher.py's _load_payload/aws.sqs_send: the alert dict itself,
    # not wrapped in a "detection_event" key.
    dredge = MagicMock()
    monkeypatch.setattr(responder, "_get_dredge", lambda role_arn=None: dredge)
    logger = MagicMock()

    responder._process_record(_sqs_record(alert), "req-1", "rh-golden-path", logger)

    dredge.aws_ir.response.disable_user.assert_called_once_with(user_name="attacker")
    logger.error.assert_not_called()


def test_signal_level_disable_user_still_works(monkeypatch):
    """Same pipeline, signal-level (not correlation) path -- this one
    already worked before §1.1 (raw_event carries userIdentity directly);
    kept here as the control case so a future change that breaks the
    signal-level path shows up here too, not just in the correlation case."""
    raw_event = _load_json(FIXTURES_DIR / "009_admin_policy_attached.json")
    rule = _load_json(RULES_DIR / "009_admin_policy_attached.json")
    assert rule["response_module"] == "disable_user"

    router = build_default_router()
    normalized = router.parse(raw_event)
    detection = build_detection_event(normalized, rule)

    # processor.py's alert_item forwards raw_event verbatim; mirror that here.
    alert_item = {
        **detection,
        "detection_id": detection["detection_id"],
    }
    alert_item["raw_event"] = normalized.raw_event

    dredge = MagicMock()
    monkeypatch.setattr(responder, "_get_dredge", lambda role_arn=None: dredge)
    logger = MagicMock()

    responder._process_record(_sqs_record(alert_item), "req-2", "rh-golden-path-2", logger)

    dredge.aws_ir.response.disable_user.assert_called_once_with(user_name="attacker")
    logger.error.assert_not_called()


def test_cross_source_correlation_actor_based_disable_user(monkeypatch):
    """Rule 029: a GuardDuty credential-compromise finding + a CloudTrail
    admin-policy-attach from the same actor.user_name, correlated via the
    existing gsi_signal_actor_user_name GSI path (same field the 4
    pre-existing pure-CloudTrail correlation rules already use). Built from
    real parsed fixtures, same rigor as the rule-021 test above -- proves
    cross-source correlation actually fires and responder resolves the
    real target, not just that the JSON schema is well-formed."""
    guardduty_signal = _make_signal(
        "029_correlation_guardduty_credential_compromise_matching_actor.json",
        "024_guardduty_iam_credential_compromise.json",
        rules_dir=GUARDDUTY_RULES_DIR,
    )
    cloudtrail_signal = _make_signal("009_admin_policy_attached.json", "009_admin_policy_attached.json")

    assert guardduty_signal["actor"]["user_name"] == "attacker"
    assert cloudtrail_signal["actor"]["user_name"] == "attacker"

    correlation_rule = _load_json(CORRELATION_RULES_DIR / "029_correlation_guardduty_credential_compromise_then_privesc.json")
    assert correlation_rule["response_module"] == "disable_user"
    assert correlation_rule["threshold"] == 2

    repo = _FakeSignalsRepository([guardduty_signal, cloudtrail_signal])
    engine = CorrelationEngine(repo=repo)
    alerts = engine.correlate(
        new_signal=cloudtrail_signal,
        rules=[correlation_rule],
        now=datetime.now(UTC),
    )

    assert len(alerts) == 1, "cross-source correlation didn't fire"
    alert = alerts[0]
    assert alert["group_value"] == "attacker"
    assert {s["rule_id"] for s in alert["signal_refs"]} == {
        "024_guardduty_iam_credential_compromise",
        "009_admin_policy_attached",
    }

    dredge = MagicMock()
    monkeypatch.setattr(responder, "_get_dredge", lambda role_arn=None: dredge)
    logger = MagicMock()

    responder._process_record(_sqs_record(alert), "req-3", "rh-golden-path-3", logger)

    dredge.aws_ir.response.disable_user.assert_called_once_with(user_name="attacker")
    logger.error.assert_not_called()


def test_cross_source_correlation_source_ip_based_visibility_only(monkeypatch):
    """Rule 030: a GuardDuty EC2 backdoor/C2 finding + a CloudTrail
    GetSecretValue call from the same network.source_ip -- the first
    shipped rule to use the generic scan-and-filter fallback path (no GSI
    for network.source_ip). Deliberately response_module="" -- 025's
    finding family has no accessKeyDetails/IAM-user resource, so
    responder._extract_user_name has nothing to resolve regardless of
    which signal ends up primary. This test proves the alert fires
    correctly; it does NOT assert a responder dispatch, since none is
    wired."""
    guardduty_signal = _make_signal(
        "030_correlation_guardduty_backdoor_matching_source_ip.json",
        "025_guardduty_ec2_backdoor_malware.json",
        rules_dir=GUARDDUTY_RULES_DIR,
    )
    cloudtrail_signal = _make_signal("016_secretsmanager_accessed.json", "016_secretsmanager_accessed.json")

    assert guardduty_signal["network"]["source_ip"] == "203.0.113.2"
    assert cloudtrail_signal["network"]["source_ip"] == "203.0.113.2"

    correlation_rule = _load_json(CORRELATION_RULES_DIR / "030_correlation_guardduty_backdoor_then_secrets_access.json")
    assert correlation_rule["response_module"] == ""
    assert correlation_rule["threshold"] == 2

    repo = _FakeSignalsRepository([guardduty_signal, cloudtrail_signal])
    engine = CorrelationEngine(repo=repo)
    alerts = engine.correlate(
        new_signal=cloudtrail_signal,
        rules=[correlation_rule],
        now=datetime.now(UTC),
    )

    assert len(alerts) == 1, "source-IP cross-source correlation didn't fire"
    alert = alerts[0]
    assert alert["group_value"] == "203.0.113.2"
    assert {s["rule_id"] for s in alert["signal_refs"]} == {
        "025_guardduty_ec2_backdoor_malware",
        "016_secretsmanager_accessed",
    }


def test_security_group_rule_revoked_with_translated_shape(monkeypatch):
    """Rule 011: real CloudTrail AuthorizeSecurityGroupIngress fixture ->
    real parser -> real detection build -> responder's
    _extract_security_group_rule_change -> a real (mocked)
    dredge.aws_ir.response.deauthorize_security_group_rules call. Proves
    the CloudTrail-shape-to-boto3-shape translation end to end, not just
    the extractor helper in isolation."""
    raw_event = _load_json(FIXTURES_DIR / "011_security_group_opened.json")
    rule = _load_json(RULES_DIR / "011_security_group_opened.json")
    assert rule["response_module"] == "deauthorize_security_group_rules"

    router = build_default_router()
    normalized = router.parse(raw_event)
    detection = build_detection_event(normalized, rule)

    # processor.py's alert_item forwards raw_event and activity_name verbatim.
    alert_item = {**detection, "raw_event": normalized.raw_event}

    dredge = MagicMock()
    monkeypatch.setattr(responder, "_get_dredge", lambda role_arn=None: dredge)
    logger = MagicMock()

    responder._process_record(_sqs_record(alert_item), "req-4", "rh-golden-path-4", logger)

    dredge.aws_ir.response.deauthorize_security_group_rules.assert_called_once_with(
        group_id="sg-0abc123",
        ingress_rules=[{"IpProtocol": "tcp", "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "FromPort": 22, "ToPort": 22}],
        egress_rules=None,
    )
    logger.error.assert_not_called()


def test_security_group_rollback_round_trips_end_to_end(monkeypatch):
    """Rule 011 again, this time carried all the way through the rollback
    pipeline: real fixture -> real parse/detection -> responder._process_record
    (writes an irActionsTable row via _write_ir_action_record/_build_rollback_kwargs)
    -> that same row fed into ir_rollback._process_record (reads it back,
    dispatches through ROLLBACK_MODULE_HANDLERS) -> dredge.aws_ir.response.
    authorize_security_group_rules called with the exact rules that were
    revoked. Proves the round trip works from a real captured action, not
    just that each half works against a hand-typed fixture."""
    raw_event = _load_json(FIXTURES_DIR / "011_security_group_opened.json")
    rule = _load_json(RULES_DIR / "011_security_group_opened.json")
    assert rule["response_module"] == "deauthorize_security_group_rules"

    router = build_default_router()
    normalized = router.parse(raw_event)
    detection = build_detection_event(normalized, rule)
    alert_item = {**detection, "raw_event": normalized.raw_event}

    dredge = MagicMock()
    dredge.aws_ir.response.deauthorize_security_group_rules.return_value = OperationResult(
        operation="deauthorize_security_group_rules",
        target="sg=sg-0abc123",
        success=True,
        details={"ingress_rules_revoked": 1},
    )
    monkeypatch.setattr(responder, "_get_dredge", lambda role_arn=None: dredge)

    written_items: list[dict] = []
    actions_table = MagicMock()
    actions_table.put_item.side_effect = lambda Item: written_items.append(Item)
    monkeypatch.setattr(responder, "_ir_actions_table", actions_table)

    role_arn = "arn:aws:iam::123456789012:role/opencdr-dev-ir-role"
    monkeypatch.setattr(responder, "_resolve_role_arn", lambda account_id: role_arn)

    responder._process_record(_sqs_record(alert_item), "req-5", "rh-golden-path-5", MagicMock())

    assert len(written_items) == 1
    action_row = written_items[0]
    assert action_row["response_module"] == "deauthorize_security_group_rules"
    assert action_row["undo_module"] == "authorize_security_group_rules"
    assert action_row["rollback_supported"] is True
    assert action_row["role_arn"] == role_arn

    # Feed the exact row responder wrote into the rollback pipeline.
    rollback_dredge = MagicMock()
    rollback_dredge.aws_ir.response.authorize_security_group_rules.return_value = OperationResult(
        operation="authorize_security_group_rules",
        target="sg=sg-0abc123",
        success=True,
        details={"ingress_rules_authorized": 1},
    )
    monkeypatch.setattr(ir_rollback, "_get_dredge", lambda role_arn=None: rollback_dredge)
    monkeypatch.setattr(ir_rollback, "_recent_action_count", lambda: 0)

    rollback_table = MagicMock()
    rollback_table.get_item.return_value = {"Item": action_row}
    monkeypatch.setattr(ir_rollback, "_ir_actions_table", rollback_table)

    rollback_outbox = MagicMock()
    monkeypatch.setattr(ir_rollback, "_outbox_table", rollback_outbox)

    rollback_logger = MagicMock()
    ir_rollback._process_record(
        _sqs_record({"detection_id": action_row["detection_id"]}), "req-6", "rh-golden-path-6", rollback_logger
    )

    rollback_dredge.aws_ir.response.authorize_security_group_rules.assert_called_once_with(
        group_id="sg-0abc123",
        ingress_rules=[{"IpProtocol": "tcp", "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "FromPort": 22, "ToPort": 22}],
        egress_rules=None,
    )
    rollback_logger.error.assert_not_called()
    rollback_table.update_item.assert_called_once()
    assert rollback_table.update_item.call_args.kwargs["Key"] == {"detection_id": action_row["detection_id"]}

    rollback_outbox.put_item.assert_called_once()
    notify_payload = json.loads(rollback_outbox.put_item.call_args.kwargs["Item"]["payload"])
    assert notify_payload["type"] == "rollback_success"
    assert notify_payload["response_module"] == "deauthorize_security_group_rules"
    assert notify_payload["undo_module"] == "authorize_security_group_rules"


def test_disable_user_rollback_round_trips_end_to_end(monkeypatch):
    """Rule 009 again (see test_signal_level_disable_user_still_works),
    this time through the rollback pipeline -- the Bucket-3 case, where
    disable_user's own inline-policy capture (added alongside its already-
    existing access_keys_disabled/groups_removed/managed_policies_detached
    detail keys) is what makes rollback_supported=True possible at all."""
    raw_event = _load_json(FIXTURES_DIR / "009_admin_policy_attached.json")
    rule = _load_json(RULES_DIR / "009_admin_policy_attached.json")
    assert rule["response_module"] == "disable_user"

    router = build_default_router()
    normalized = router.parse(raw_event)
    detection = build_detection_event(normalized, rule)
    alert_item = {**detection, "raw_event": normalized.raw_event}

    dredge = MagicMock()
    dredge.aws_ir.response.disable_user.return_value = OperationResult(
        operation="disable_user",
        target="user=attacker",
        success=True,
        details={
            "access_keys_disabled": ["AKIAEXAMPLE"],
            "groups_removed": ["admins"],
            "managed_policies_detached": ["arn:aws:iam::aws:policy/AdministratorAccess"],
            "inline_policies": {"backdoor-policy": {"Version": "2012-10-17", "Statement": []}},
        },
    )
    monkeypatch.setattr(responder, "_get_dredge", lambda role_arn=None: dredge)

    written_items: list[dict] = []
    actions_table = MagicMock()
    actions_table.put_item.side_effect = lambda Item: written_items.append(Item)
    monkeypatch.setattr(responder, "_ir_actions_table", actions_table)

    role_arn = "arn:aws:iam::123456789012:role/opencdr-dev-ir-role"
    monkeypatch.setattr(responder, "_resolve_role_arn", lambda account_id: role_arn)

    responder._process_record(_sqs_record(alert_item), "req-7", "rh-golden-path-7", MagicMock())

    assert len(written_items) == 1
    action_row = written_items[0]
    assert action_row["response_module"] == "disable_user"
    assert action_row["undo_module"] == "restore_user"
    assert action_row["rollback_supported"] is True

    rollback_dredge = MagicMock()
    rollback_dredge.aws_ir.response.restore_user.return_value = OperationResult(
        operation="restore_user", target="user=attacker", success=True, details={}
    )
    monkeypatch.setattr(ir_rollback, "_get_dredge", lambda role_arn=None: rollback_dredge)
    monkeypatch.setattr(ir_rollback, "_recent_action_count", lambda: 0)

    rollback_table = MagicMock()
    rollback_table.get_item.return_value = {"Item": action_row}
    monkeypatch.setattr(ir_rollback, "_ir_actions_table", rollback_table)

    rollback_outbox = MagicMock()
    monkeypatch.setattr(ir_rollback, "_outbox_table", rollback_outbox)

    rollback_logger = MagicMock()
    ir_rollback._process_record(
        _sqs_record({"detection_id": action_row["detection_id"]}), "req-8", "rh-golden-path-8", rollback_logger
    )

    rollback_dredge.aws_ir.response.restore_user.assert_called_once_with(
        user_name="attacker",
        access_keys_disabled=["AKIAEXAMPLE"],
        groups_removed=["admins"],
        managed_policies_detached=["arn:aws:iam::aws:policy/AdministratorAccess"],
        inline_policies={"backdoor-policy": {"Version": "2012-10-17", "Statement": []}},
    )
    rollback_logger.error.assert_not_called()
    rollback_table.update_item.assert_called_once()

    rollback_outbox.put_item.assert_called_once()
    notify_payload = json.loads(rollback_outbox.put_item.call_args.kwargs["Item"]["payload"])
    assert notify_payload["type"] == "rollback_success"
    assert notify_payload["response_module"] == "disable_user"
    assert notify_payload["undo_module"] == "restore_user"

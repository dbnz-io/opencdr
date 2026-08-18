"""Coverage for the curated GuardDuty detection rules (024-027) and their
catch-all (028): every curated rule must match its own finding type and
reject the other three; the catch-all must reject all four curated finding
types (its whole reason for existing -- see 028's not_matches/not_prefix
conditions) while still catching an uncovered GuardDuty finding; and no rule
in this family should ever match a CloudTrail-sourced event.

Rules are loaded from the actual JSON files in support_files/detection_rules/
rather than hand-copied here, so a future edit to a rule's conditions is
exercised by this test the moment it's saved.
"""
from __future__ import annotations

import json
from pathlib import Path

from src.domain.detection_engine import rule_matches, run_detection
from src.domain.ocsf_min_parser import Actor, ApiCall, Network, NormalizedEvent

RULES_DIR = Path(__file__).parent.parent.parent / "support_files" / "detection_rules" / "guardduty"


def load_rule(rule_id: str) -> dict:
    return json.loads((RULES_DIR / f"{rule_id}.json").read_text())


IAM_RULE = load_rule("024_guardduty_iam_credential_compromise")
EC2_RULE = load_rule("025_guardduty_ec2_backdoor_malware")
S3_RULE = load_rule("026_guardduty_s3_exposure_exfiltration")
ATTACK_SEQUENCE_RULE = load_rule("027_guardduty_attack_sequence")
CATCHALL_RULE = load_rule("028_guardduty_catchall")

ALL_GUARDDUTY_RULES = [IAM_RULE, EC2_RULE, S3_RULE, ATTACK_SEQUENCE_RULE, CATCHALL_RULE]


def make_gd_event(
    activity_name: str, *, severity: str = "HIGH", gd_resource_type: str | None = None
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id="test-gd-event",
        source="guardduty",
        time="2026-01-01T00:00:00Z",
        category="threat",
        class_name="security_finding",
        activity_name=activity_name,
        severity=severity,
        actor=Actor(user_name="suspicious-user"),
        api=ApiCall(service="guardduty", operation=activity_name),
        network=Network(),
        gd_resource_type=gd_resource_type,
    )


def make_cloudtrail_event(activity_name: str = "CreateUser", *, severity: str = "HIGH") -> NormalizedEvent:
    return NormalizedEvent(
        event_id="test-ct-event",
        source="cloudtrail",
        time="2026-01-01T00:00:00Z",
        category="iam",
        class_name="api_activity",
        activity_name=activity_name,
        severity=severity,
        actor=Actor(user_name="alice"),
        api=ApiCall(service="iam.amazonaws.com", operation=activity_name),
        network=Network(),
    )


# ----------------------------
# 024 — IAM credential compromise
# ----------------------------


class TestIamCredentialCompromiseRule:
    def test_matches_tor_ip_caller(self):
        event = make_gd_event(
            "UnauthorizedAccess:IAMUser/TorIPCaller", severity="HIGH", gd_resource_type="IAMUser"
        )
        assert rule_matches(event, IAM_RULE)

    def test_matches_compromised_credentials(self):
        event = make_gd_event(
            "CredentialAccess:IAMUser/CompromisedCredentials", severity="HIGH", gd_resource_type="IAMUser"
        )
        assert rule_matches(event, IAM_RULE)

    def test_rejects_ec2_finding(self):
        event = make_gd_event("Backdoor:EC2/C&CActivity.B", severity="HIGH", gd_resource_type="EC2")
        assert not rule_matches(event, IAM_RULE)

    def test_rejects_s3_finding(self):
        event = make_gd_event(
            "Policy:S3/BucketPublicAccessGranted", severity="HIGH", gd_resource_type="S3"
        )
        assert not rule_matches(event, IAM_RULE)

    def test_rejects_attack_sequence_finding(self):
        event = make_gd_event("AttackSequence:IAM/CompromisedCredentials", severity="CRITICAL")
        assert not rule_matches(event, IAM_RULE)

    def test_rejects_unlisted_iam_finding_type(self):
        # Recon:IAMUser/MaliciousIPCaller is a real GuardDuty finding type,
        # deliberately left uncovered by the curated rule -- catch-all territory.
        event = make_gd_event(
            "Recon:IAMUser/MaliciousIPCaller", severity="MEDIUM", gd_resource_type="IAMUser"
        )
        assert not rule_matches(event, IAM_RULE)


# ----------------------------
# 025 — EC2 backdoor/malware
# ----------------------------


class TestEc2BackdoorMalwareRule:
    def test_matches_backdoor(self):
        event = make_gd_event("Backdoor:EC2/C&CActivity.B", severity="HIGH", gd_resource_type="EC2")
        assert rule_matches(event, EC2_RULE)

    def test_matches_cryptocurrency(self):
        event = make_gd_event(
            "CryptoCurrency:EC2/BitcoinTool.B", severity="HIGH", gd_resource_type="EC2"
        )
        assert rule_matches(event, EC2_RULE)

    def test_rejects_unauthorized_access_brute_force(self):
        # Deliberately excluded: brute-force/recon, not confirmed compromise.
        event = make_gd_event(
            "UnauthorizedAccess:EC2/SSHBruteForce", severity="MEDIUM", gd_resource_type="EC2"
        )
        assert not rule_matches(event, EC2_RULE)

    def test_rejects_iam_finding(self):
        event = make_gd_event(
            "UnauthorizedAccess:IAMUser/TorIPCaller", severity="HIGH", gd_resource_type="IAMUser"
        )
        assert not rule_matches(event, EC2_RULE)

    def test_rejects_s3_finding(self):
        event = make_gd_event(
            "Policy:S3/BucketPublicAccessGranted", severity="HIGH", gd_resource_type="S3"
        )
        assert not rule_matches(event, EC2_RULE)


# ----------------------------
# 026 — S3 exposure/exfiltration
# ----------------------------


class TestS3ExposureExfiltrationRule:
    def test_matches_bucket_public_access_granted(self):
        event = make_gd_event(
            "Policy:S3/BucketPublicAccessGranted", severity="HIGH", gd_resource_type="S3"
        )
        assert rule_matches(event, S3_RULE)

    def test_matches_exfiltration_anomalous_behavior(self):
        event = make_gd_event(
            "Exfiltration:S3/AnomalousBehavior", severity="HIGH", gd_resource_type="S3"
        )
        assert rule_matches(event, S3_RULE)

    def test_rejects_low_severity_config_drift_finding(self):
        # Deliberately excluded: config drift, not exposure/exfiltration.
        event = make_gd_event(
            "Policy:S3/BucketBlockPublicAccessDisabled", severity="LOW", gd_resource_type="S3"
        )
        assert not rule_matches(event, S3_RULE)

    def test_rejects_discovery_finding(self):
        event = make_gd_event("Discovery:S3/AnomalousBehavior", severity="MEDIUM", gd_resource_type="S3")
        assert not rule_matches(event, S3_RULE)

    def test_rejects_ec2_finding(self):
        event = make_gd_event("Backdoor:EC2/C&CActivity.B", severity="HIGH", gd_resource_type="EC2")
        assert not rule_matches(event, S3_RULE)


# ----------------------------
# 027 — Attack Sequence
# ----------------------------


class TestAttackSequenceRule:
    def test_matches_iam_attack_sequence(self):
        event = make_gd_event("AttackSequence:IAM/CompromisedCredentials", severity="CRITICAL")
        assert rule_matches(event, ATTACK_SEQUENCE_RULE)

    def test_matches_ec2_attack_sequence(self):
        event = make_gd_event("AttackSequence:EC2/CompromisedInstanceGroup", severity="CRITICAL")
        assert rule_matches(event, ATTACK_SEQUENCE_RULE)

    def test_rejects_non_attack_sequence_finding(self):
        event = make_gd_event(
            "UnauthorizedAccess:IAMUser/TorIPCaller", severity="HIGH", gd_resource_type="IAMUser"
        )
        assert not rule_matches(event, ATTACK_SEQUENCE_RULE)


# ----------------------------
# 028 — Catch-all
# ----------------------------


class TestCatchallRule:
    def test_rejects_all_curated_iam_finding(self):
        event = make_gd_event(
            "UnauthorizedAccess:IAMUser/TorIPCaller", severity="HIGH", gd_resource_type="IAMUser"
        )
        assert not rule_matches(event, CATCHALL_RULE)

    def test_rejects_curated_ec2_finding(self):
        event = make_gd_event("Backdoor:EC2/C&CActivity.B", severity="HIGH", gd_resource_type="EC2")
        assert not rule_matches(event, CATCHALL_RULE)

    def test_rejects_curated_s3_finding(self):
        event = make_gd_event(
            "Policy:S3/BucketPublicAccessGranted", severity="HIGH", gd_resource_type="S3"
        )
        assert not rule_matches(event, CATCHALL_RULE)

    def test_rejects_curated_attack_sequence_finding(self):
        event = make_gd_event("AttackSequence:IAM/CompromisedCredentials", severity="CRITICAL")
        assert not rule_matches(event, CATCHALL_RULE)

    def test_catches_uncovered_medium_finding(self):
        event = make_gd_event(
            "Recon:IAMUser/MaliciousIPCaller", severity="MEDIUM", gd_resource_type="IAMUser"
        )
        assert rule_matches(event, CATCHALL_RULE)

    def test_catches_uncovered_high_finding(self):
        event = make_gd_event(
            "UnauthorizedAccess:EC2/SSHBruteForce", severity="MEDIUM", gd_resource_type="EC2"
        )
        assert rule_matches(event, CATCHALL_RULE)

    def test_rejects_low_severity_uncovered_finding(self):
        # Below the catch-all's own severity floor -- not a curated exclusion,
        # just out of scope for a MEDIUM/HIGH/CRITICAL-only catch-all.
        event = make_gd_event(
            "Policy:S3/BucketBlockPublicAccessDisabled", severity="LOW", gd_resource_type="S3"
        )
        assert not rule_matches(event, CATCHALL_RULE)


# ----------------------------
# Cross-cutting: no double-firing, no CloudTrail leakage
# ----------------------------


class TestNoDoubleFiringAcrossCuratedAndCatchall:
    def test_each_curated_finding_fires_exactly_one_rule(self):
        cases = [
            make_gd_event(
                "UnauthorizedAccess:IAMUser/TorIPCaller", severity="HIGH", gd_resource_type="IAMUser"
            ),
            make_gd_event("Backdoor:EC2/C&CActivity.B", severity="HIGH", gd_resource_type="EC2"),
            make_gd_event(
                "Policy:S3/BucketPublicAccessGranted", severity="HIGH", gd_resource_type="S3"
            ),
            make_gd_event("AttackSequence:IAM/CompromisedCredentials", severity="CRITICAL"),
        ]
        for event in cases:
            detections = run_detection(event, ALL_GUARDDUTY_RULES)
            assert len(detections) == 1, (event.activity_name, [d["rule_id"] for d in detections])

    def test_uncovered_finding_fires_only_catchall(self):
        event = make_gd_event(
            "Recon:IAMUser/MaliciousIPCaller", severity="MEDIUM", gd_resource_type="IAMUser"
        )
        detections = run_detection(event, ALL_GUARDDUTY_RULES)
        assert [d["rule_id"] for d in detections] == ["028_guardduty_catchall"]


class TestNoCloudTrailLeakage:
    def test_cloudtrail_event_matches_no_guardduty_rule(self):
        event = make_cloudtrail_event()
        assert run_detection(event, ALL_GUARDDUTY_RULES) == []

    def test_cloudtrail_event_with_high_severity_still_rejected(self):
        # source == guardduty is a hard gate on every rule in this family --
        # confirm severity alone can't slip a CloudTrail event past the catch-all.
        event = make_cloudtrail_event(severity="CRITICAL")
        assert not rule_matches(event, CATCHALL_RULE)

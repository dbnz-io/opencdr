import os
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


class _Loader(yaml.SafeLoader):
    pass


def _intrinsic(loader, tag, node):
    if isinstance(node, yaml.ScalarNode):
        return {tag: loader.construct_scalar(node)}
    if isinstance(node, yaml.SequenceNode):
        return {tag: loader.construct_sequence(node)}
    return {tag: loader.construct_mapping(node)}


_Loader.add_multi_constructor("!", _intrinsic)


def _yaml(path: str) -> dict:
    return yaml.load((ROOT / path).read_text(), Loader=_Loader)


def test_profiles_are_explicit_reversible_resource_protection_modes():
    profiles = _yaml("deployment/security-profiles.yml")

    assert profiles == {
        "standard": {
            "dynamodbDeletionProtection": False,
            "deletionPolicy": "Delete",
            "updateReplacePolicy": "Delete",
        },
        "hardened": {
            "dynamodbDeletionProtection": True,
            "deletionPolicy": "Retain",
            "updateReplacePolicy": "Retain",
        },
    }


def test_all_dynamodb_tables_follow_the_selected_profile():
    cfg = _yaml("serverless.yml")
    resources = cfg["resources"]["Resources"]
    tables = {
        name: value for name, value in resources.items() if value["Type"] == "AWS::DynamoDB::Table"
    }

    assert len(tables) == 11
    for name, table in tables.items():
        assert table["Properties"]["DeletionProtectionEnabled"] == (
            "${self:custom.securityProfile.dynamodbDeletionProtection}"
        )
        if name == "IngestionTable":
            # Existing stronger baseline retained for compatibility.
            assert table["DeletionPolicy"] == "Retain"
            assert table["UpdateReplacePolicy"] == "Retain"
        else:
            assert table["DeletionPolicy"] == "${self:custom.securityProfile.deletionPolicy}"
            assert (
                table["UpdateReplacePolicy"] == "${self:custom.securityProfile.updateReplacePolicy}"
            )


def test_state_buckets_have_secure_defaults_and_hardened_retention_hook():
    resources = _yaml("serverless.yml")["resources"]["Resources"]
    archive = resources["ArchiveBucket"]
    archive_policy = resources["ArchiveBucketPolicy"]["Properties"]["PolicyDocument"]["Statement"][
        0
    ]

    assert archive["DeletionPolicy"] == "${self:custom.securityProfile.deletionPolicy}"
    assert archive["UpdateReplacePolicy"] == "${self:custom.securityProfile.updateReplacePolicy}"
    assert archive["Properties"]["OwnershipControls"]["Rules"] == [
        {"ObjectOwnership": "BucketOwnerEnforced"}
    ]
    assert all(archive["Properties"]["PublicAccessBlockConfiguration"].values())
    assert archive_policy["Effect"] == "Deny"
    assert archive_policy["Condition"]["Bool"]["aws:SecureTransport"] is False


def test_all_sqs_queues_use_managed_encryption_and_dlqs_are_scoped_when_hardened():
    resources = _yaml("serverless.yml")["resources"]["Resources"]
    queues = {
        name: value for name, value in resources.items() if value["Type"] == "AWS::SQS::Queue"
    }

    assert len(queues) == 11
    assert all(queue["Properties"]["SqsManagedSseEnabled"] is True for queue in queues.values())

    for logical_id in (
        "NotificationsQueueDLQ",
        "ResponsesQueueDLQ",
        "IrRollbackQueueDLQ",
        "SignalsWriteQueueDLQ",
    ):
        conditional = queues[logical_id]["Properties"]["RedriveAllowPolicy"]["If"]
        assert conditional[0] == "HardenedProfile"
        assert conditional[1]["redrivePermission"] == "byQueue"
        assert len(conditional[1]["sourceQueueArns"]) == 1

    # The ingestion source queue predates this profile and has a generated
    # physical name. Referencing it from its DLQ would create a CFN cycle;
    # assigning a name now would replace the live queue. Keep upgrade safety.
    assert "RedriveAllowPolicy" not in queues["IngestionDLQ"]["Properties"]


def test_security_profile_is_exposed_without_sensitive_configuration():
    cfg = _yaml("serverless.yml")

    assert cfg["params"]["default"]["securityProfile"] == "standard"
    assert (
        cfg["functions"]["api"]["environment"]["OPENCDR_SECURITY_PROFILE"]
        == "${param:securityProfile}"
    )
    assert cfg["resources"]["Outputs"]["CoreSecurityProfile"]["Value"] == "${param:securityProfile}"
    assert cfg["resources"]["Outputs"]["ArchiveEnabled"]["Value"] == "${param:archiveEnabled}"
    assert cfg["resources"]["Outputs"]["XRayEnabled"]["Value"] == "${param:xrayEnabled}"


def test_transition_guard_requires_explicit_hardened_downgrade(tmp_path):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_aws = fake_bin / "aws"
    fake_aws.write_text("#!/usr/bin/env bash\nprintf 'hardened\\n'\n")
    fake_aws.chmod(0o755)
    env = {**os.environ, "PATH": f"{fake_bin}:{os.environ['PATH']}"}
    command = [
        str(ROOT / "scripts" / "check_security_profile_transition.sh"),
        "--stage",
        "prod",
        "--target",
        "standard",
    ]

    rejected = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True)
    accepted = subprocess.run(
        command + ["--allow-downgrade"], cwd=ROOT, env=env, capture_output=True, text=True
    )

    assert rejected.returncode == 1
    assert "refusing to reduce" in rejected.stderr
    assert accepted.returncode == 0
    assert "hardened -> standard" in accepted.stdout

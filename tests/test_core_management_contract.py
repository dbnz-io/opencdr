"""Deployment and management-contract guards for OpenCDR Core."""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]


class _Loader(yaml.SafeLoader):
    pass


def _intrinsic(loader, tag_suffix, node):
    if isinstance(node, yaml.ScalarNode):
        return {tag_suffix: loader.construct_scalar(node)}
    if isinstance(node, yaml.SequenceNode):
        return {tag_suffix: loader.construct_sequence(node)}
    return {tag_suffix: loader.construct_mapping(node)}


_Loader.add_multi_constructor("!", _intrinsic)


def _yaml(path: str) -> dict:
    return yaml.load((ROOT / path).read_text(), Loader=_Loader)


def test_release_manifest_matches_deployment_contract_versions():
    manifest = json.loads((ROOT / "management/release-manifest.json").read_text())
    serverless = _yaml("serverless.yml")
    defaults = serverless["params"]["default"]

    assert manifest["product"] == "OpenCDR Core"
    assert manifest["release_version"] == defaults["coreVersion"]
    assert manifest["management_contract_version"] == defaults["managementContractVersion"]
    assert re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?", manifest["release_version"])

    for contract_path in manifest["contracts"].values():
        if contract_path.startswith("management/"):
            assert (ROOT / contract_path).is_file(), contract_path

    outputs = serverless["resources"]["Outputs"]
    assert outputs["CoreProduct"]["Value"] == "OpenCDR Core"
    assert "CoreVersion" in outputs
    assert "ManagementContractVersion" in outputs
    assert "CoreAccountId" in outputs
    assert "CoreHomeRegion" in outputs


def test_contract_schemas_are_versioned_json_schema_documents():
    for path in sorted((ROOT / "management/schemas").glob("*.schema.json")):
        schema = json.loads(path.read_text())
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert schema["$id"].endswith("/1.0.0")
        assert schema["type"] == "object"
        Draft202012Validator.check_schema(schema)


def test_management_contract_examples_validate():
    pairs = (
        ("configuration-bundle.schema.json", "configuration-bundle.example.json"),
        ("alert.schema.json", "alert.example.json"),
    )
    for schema_name, example_name in pairs:
        schema = json.loads((ROOT / "management/schemas" / schema_name).read_text())
        example = json.loads((ROOT / "management/examples" / example_name).read_text())
        Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER).validate(example)


def test_standalone_cloudformation_descriptions_fit_aws_limit():
    for path in (
        "region-forwarding/cross-region-forwarder.yaml",
        "org-forwarding/account-event-forwarder.yaml",
    ):
        description = _yaml(path)["Description"]
        assert len(description) <= 1024, f"{path} Description is {len(description)} characters"


def test_regional_collector_has_retry_dlq_and_scoped_queue_policy():
    resources = _yaml("region-forwarding/cross-region-forwarder.yaml")["Resources"]
    queue = resources["ForwardingDeadLetterQueue"]["Properties"]
    target = resources["ForwardingRule"]["Properties"]["Targets"][0]
    policy = resources["ForwardingDeadLetterQueuePolicy"]["Properties"]["PolicyDocument"]["Statement"][0]

    assert queue["MessageRetentionPeriod"] == 1209600
    assert queue["SqsManagedSseEnabled"] is True
    assert target["RetryPolicy"] == {
        "MaximumEventAgeInSeconds": 86400,
        "MaximumRetryAttempts": 185,
    }
    assert "DeadLetterConfig" in target
    assert policy["Principal"] == {"Service": "events.amazonaws.com"}
    assert "aws:SourceArn" in policy["Condition"]["ArnEquals"]
    assert resources["ForwardingFailedInvocationsAlarm"]["Properties"]["MetricName"] == "FailedInvocations"
    assert resources["ForwardingDeadLetterQueueAlarm"]["Properties"]["MetricName"] == "ApproximateNumberOfMessagesVisible"


def test_regional_forwarder_role_trust_is_source_scoped():
    resources = _yaml("serverless.yml")["resources"]["Resources"]
    trust = resources["RegionForwarderRole"]["Properties"]["AssumeRolePolicyDocument"]["Statement"][0]
    condition = trust["Condition"]
    assert "aws:SourceAccount" in condition["StringEquals"]
    assert "aws:SourceArn" in condition["ArnLike"]


def test_forwarder_patterns_cover_the_home_processor_patterns():
    serverless = _yaml("serverless.yml")
    processor_patterns = [
        event["eventBridge"]["pattern"]
        for event in serverless["functions"]["processor"]["events"]
        if "eventBridge" in event
    ]
    expected_sources = {source for pattern in processor_patterns for source in pattern["source"]}
    expected_types = {
        detail_type
        for pattern in processor_patterns
        for detail_type in pattern["detail-type"]
    }

    for path in (
        "region-forwarding/cross-region-forwarder.yaml",
        "org-forwarding/account-event-forwarder.yaml",
    ):
        pattern = _yaml(path)["Resources"]["ForwardingRule"]["Properties"]["EventPattern"]
        assert set(pattern["source"]) == expected_sources
        assert set(pattern["detail-type"]) == expected_types

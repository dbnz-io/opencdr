from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def _config():
    class Loader(yaml.SafeLoader):
        pass

    def intrinsic(loader, tag, node):
        if isinstance(node, yaml.ScalarNode):
            return {tag: loader.construct_scalar(node)}
        return {tag: loader.construct_sequence(node)}

    Loader.add_multi_constructor("!", intrinsic)
    return yaml.load((ROOT / "serverless.yml").read_text(), Loader=Loader)


def test_archive_is_optional_and_disabled_by_default():
    cfg = _config()

    assert cfg["params"]["default"]["archiveEnabled"] == "false"
    stream_events = cfg["functions"]["archiver"]["events"]
    assert len(stream_events) == 3
    assert all(
        event["stream"]["enabled"] == "${strToBool(${param:archiveEnabled})}"
        for event in stream_events
    )


def test_archive_pipeline_resources_remain_managed_for_reversible_toggling():
    resources = _config()["resources"]["Resources"]
    managed = {
        "ArchiveBucket",
        "ArchiveGlueDatabase",
        "ArchiveSignalsGlueTable",
        "ArchiveAlertsGlueTable",
        "ArchiveLogsGlueTable",
        "ArchiveFirehoseRole",
        "ArchiveSignalsFirehose",
        "ArchiveAlertsFirehose",
        "ArchiveLogsFirehose",
        "AlarmArchiverErrors",
        "AlarmArchiverIteratorAge",
    }

    assert managed <= resources.keys()
    assert all("Condition" not in resources[logical_id] for logical_id in managed)

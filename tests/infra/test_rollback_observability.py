from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def _resources():
    class Loader(yaml.SafeLoader):
        pass

    def intrinsic(loader, tag, node):
        if isinstance(node, yaml.ScalarNode):
            return {tag: loader.construct_scalar(node)}
        return {tag: loader.construct_sequence(node)}

    Loader.add_multi_constructor("!", intrinsic)
    config = yaml.load((ROOT / "serverless.yml").read_text(), Loader=Loader)
    return config["resources"]["Resources"]


def test_rollback_failures_have_function_domain_and_dlq_alarms():
    resources = _resources()

    assert resources["AlarmRollbackHandlerErrors"]["Properties"]["MetricName"] == "Errors"
    assert (
        resources["AlarmResponderRollbackFailures"]["Properties"]["MetricName"]
        == "ResponderRollbackFailures"
    )
    assert resources["AlarmIrRollbackDLQDepth"]["Properties"]["Dimensions"][0]["Value"] == {
        "GetAtt": "IrRollbackQueueDLQ.QueueName"
    }

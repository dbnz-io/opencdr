from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def config():
    class Loader(yaml.SafeLoader):
        pass

    def intrinsic(loader, tag, node):
        if isinstance(node, yaml.ScalarNode):
            return {tag: loader.construct_scalar(node)}
        return {tag: loader.construct_sequence(node)}

    Loader.add_multi_constructor("!", intrinsic)
    return yaml.load((ROOT / "serverless.yml").read_text(), Loader=Loader)


def test_xray_is_optional_and_disabled_by_default():
    cfg = config()

    assert cfg["params"]["default"]["xrayEnabled"] == "false"
    assert cfg["provider"]["tracing"] == {
        "lambda": "${strToBool(${param:xrayEnabled})}",
        "apiGateway": "${strToBool(${param:xrayEnabled})}",
    }
    assert cfg["provider"]["environment"]["AWS_XRAY_SDK_ENABLED"] == "${param:xrayEnabled}"

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


def test_lambda_packages_use_a_fail_closed_source_allowlist():
    patterns = _config()["package"]["patterns"]

    assert patterns == ["!**", "src/**"]


def test_legacy_python_requirements_plugin_is_not_loaded_twice():
    cfg = _config()

    assert "plugins" not in cfg
    assert "pythonRequirements" in cfg["custom"]

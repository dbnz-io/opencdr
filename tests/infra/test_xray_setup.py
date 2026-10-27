from unittest.mock import Mock

from src.infra import xray_setup


def test_patch_boto3_is_enabled_by_default(monkeypatch):
    monkeypatch.delenv("AWS_XRAY_SDK_ENABLED", raising=False)
    patch = Mock()
    configure = Mock()
    monkeypatch.setattr(xray_setup, "patch", patch)
    monkeypatch.setattr(xray_setup.xray_recorder, "configure", configure)

    xray_setup.patch_boto3()

    configure.assert_called_once_with(context_missing="LOG_ERROR")
    patch.assert_called_once_with(["boto3"])


def test_patch_boto3_does_nothing_when_xray_is_disabled(monkeypatch):
    monkeypatch.setenv("AWS_XRAY_SDK_ENABLED", "false")
    patch = Mock()
    configure = Mock()
    monkeypatch.setattr(xray_setup, "patch", patch)
    monkeypatch.setattr(xray_setup.xray_recorder, "configure", configure)

    xray_setup.patch_boto3()

    configure.assert_not_called()
    patch.assert_not_called()

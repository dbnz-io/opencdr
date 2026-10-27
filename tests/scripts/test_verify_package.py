import zipfile

import pytest

from scripts.verify_package import verify


def _zip(path, names, content="content"):
    with zipfile.ZipFile(path, "w") as bundle:
        for name in names:
            bundle.writestr(name, content)


def test_accepts_runtime_source_and_dependencies(tmp_path):
    _zip(tmp_path / "service.zip", ["src/handlers/api.py", "boto3/__init__.py"])

    manifest = verify(tmp_path)

    assert manifest["archives"][0]["path"] == "service.zip"
    assert len(manifest["archives"][0]["sha256"]) == 64


@pytest.mark.parametrize(
    "name",
    [
        ".opencdr.json",
        ".env.production",
        ".aws/credentials",
        "docs/runbook.md",
        "private.key",
        "../escape",
    ],
)
def test_rejects_local_or_secret_material(tmp_path, name):
    _zip(tmp_path / "service.zip", ["src/handlers/api.py", name])

    with pytest.raises(ValueError, match="unsafe deployment archive"):
        verify(tmp_path)


def test_rejects_missing_archives(tmp_path):
    with pytest.raises(ValueError, match="no deployment ZIP files"):
        verify(tmp_path)


def test_allows_ca_certificates_but_rejects_private_key_pem(tmp_path):
    _zip(tmp_path / "ca.zip", ["certifi/cacert.pem"], "-----BEGIN CERTIFICATE-----")
    verify(tmp_path)

    _zip(tmp_path / "key.zip", ["local/private.pem"], "-----BEGIN PRIVATE KEY-----")
    with pytest.raises(ValueError, match="private-key PEM file"):
        verify(tmp_path)

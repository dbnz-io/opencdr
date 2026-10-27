#!/usr/bin/env python3
"""Fail closed when a Serverless deployment package contains local material."""

from __future__ import annotations

import argparse
import hashlib
import json
import stat
import sys
import zipfile
from pathlib import Path, PurePosixPath

FORBIDDEN_ANYWHERE = {
    ".aws",
    ".git",
    ".github",
    ".serverless",
    ".venv",
    "__pycache__",
    "node_modules",
    "venv",
}
FORBIDDEN_TOP_LEVEL = {
    "artifacts",
    "ci-bootstrap",
    "deployment",
    "docs",
    "management",
    "org-forwarding",
    "region-forwarding",
    "scripts",
    "tests",
}
FORBIDDEN_NAMES = {
    ".opencdr.json",
    ".pypirc",
    ".npmrc",
    ".requirements.zip",
    "credentials",
    "id_rsa",
    "id_ed25519",
    "serverless.yml",
}
SECRET_SUFFIXES = {".key", ".p12", ".pfx", ".jks"}


def _unsafe_reason(info: zipfile.ZipInfo) -> str | None:
    raw = info.filename
    path = PurePosixPath(raw)
    parts = tuple(part for part in path.parts if part not in ("", "."))
    lower_parts = tuple(part.lower() for part in parts)

    if path.is_absolute() or ".." in parts:
        return "path traversal or absolute path"
    if stat.S_ISLNK(info.external_attr >> 16):
        return "symbolic link"
    if any(part.startswith(".env") for part in lower_parts):
        return "environment file"
    if any(part in FORBIDDEN_ANYWHERE for part in lower_parts):
        return "repository or build-only path"
    if lower_parts and lower_parts[0] in FORBIDDEN_TOP_LEVEL:
        return "repository or build-only path"
    if lower_parts and lower_parts[-1] in FORBIDDEN_NAMES:
        return "credential or repository file"
    if lower_parts and PurePosixPath(lower_parts[-1]).suffix in SECRET_SUFFIXES:
        return "private-key or keystore file"
    return None


def verify(package_dir: Path) -> dict[str, object]:
    archives = sorted(package_dir.glob("*.zip"))
    if not archives:
        raise ValueError(f"no deployment ZIP files found in {package_dir}")

    manifest: dict[str, object] = {"schema_version": 1, "archives": []}
    for archive in archives:
        violations: list[str] = []
        with zipfile.ZipFile(archive) as bundle:
            members = bundle.infolist()
            if not members:
                violations.append("archive is empty")
            for info in members:
                reason = _unsafe_reason(info)
                if (
                    reason is None
                    and PurePosixPath(info.filename.lower()).suffix == ".pem"
                    and b"PRIVATE KEY" in bundle.read(info)
                ):
                    reason = "private-key PEM file"
                if reason:
                    violations.append(f"{info.filename}: {reason}")
        if violations:
            joined = "\n  - ".join(violations)
            raise ValueError(f"unsafe deployment archive {archive}:\n  - {joined}")

        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        manifest["archives"].append(
            {"path": archive.name, "sha256": digest, "bytes": archive.stat().st_size}
        )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package_dir", type=Path)
    args = parser.parse_args()
    try:
        manifest = verify(args.package_dir)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        print(f"package verification failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

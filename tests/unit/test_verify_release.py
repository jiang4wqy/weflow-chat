from __future__ import annotations

import hashlib
import json
from pathlib import Path
import zipfile

import pytest

from tools.verify_release import (
    ReleaseVerificationError,
    verify_release,
)


def _release(tmp_path: Path, *, unsafe: bool = False):
    version = "0.1.0"
    root = f"weflow-chat-{version}"
    files = {
        "README.md": b"manual offline refresh",
        "LICENSE": b"source available",
        "PRIVACY.md": b"offline",
        "SECURITY.md": b"fail closed",
        "THIRD_PARTY_NOTICES.md": b"notices",
        "install.ps1": b"param()",
        "runtime/python/python.exe": b"python",
        "runtime/node/node.exe": b"node",
        "scripts/Install-WeFlowChat.ps1": b"param()",
        "scripts/Run-WeFlowChatInstalled.cmd": b"@echo off",
        "src/weflow_chat/__init__.py": (
            b'path = r"C:' + b'\\Users\\private-name"'
            if unsafe
            else b'__version__ = "0.1.0"'
        ),
    }
    manifest = {
        "schemaVersion": 1,
        "version": version,
        "files": [
            {
                "path": name,
                "sha256": hashlib.sha256(payload).hexdigest().upper(),
                "size": len(payload),
            }
            for name, payload in sorted(files.items())
        ],
    }
    archive = tmp_path / f"weflow-chat-{version}-win-x64.zip"
    with zipfile.ZipFile(archive, "w") as package:
        for name, payload in files.items():
            package.writestr(f"{root}/{name}", payload)
        package.writestr(
            f"{root}/release-manifest.json",
            json.dumps(manifest).encode(),
        )
    digest = hashlib.sha256(archive.read_bytes()).hexdigest().upper()
    digest_path = tmp_path / f"{archive.name}.sha256"
    digest_path.write_bytes(
        f"{digest}  {archive.name}\r\n".encode("ascii")
    )
    return archive, digest_path, digest


def test_release_verifier_accepts_exact_manifest(tmp_path):
    archive, digest_path, digest = _release(tmp_path)

    assert verify_release(
        archive_path=archive,
        sha256_path=digest_path,
        version="0.1.0",
    ) == digest


def test_release_verifier_rejects_privacy_finding(tmp_path):
    archive, digest_path, _digest = _release(tmp_path, unsafe=True)

    with pytest.raises(
        ReleaseVerificationError, match="release_privacy_finding"
    ):
        verify_release(
            archive_path=archive,
            sha256_path=digest_path,
            version="0.1.0",
        )


def test_release_verifier_rejects_digest_drift(tmp_path):
    archive, digest_path, _digest = _release(tmp_path)
    digest_path.write_bytes(
        f"{'0' * 64}  {archive.name}\r\n".encode("ascii")
    )

    with pytest.raises(
        ReleaseVerificationError, match="archive_hash_mismatch"
    ):
        verify_release(
            archive_path=archive,
            sha256_path=digest_path,
            version="0.1.0",
        )

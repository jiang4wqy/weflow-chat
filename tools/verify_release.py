from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import zipfile

from tools.privacy_scan import scan_payload


_VERSION = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
_HEX64 = re.compile(r"^[0-9A-F]{64}$")
_MAX_ENTRY_BYTES = 192 * 1024 * 1024
_MAX_ARCHIVE_BYTES = 768 * 1024 * 1024
_TEXT_PATHS = {
    "README.md",
    "LICENSE",
    "PRIVACY.md",
    "SECURITY.md",
    "THIRD_PARTY_NOTICES.md",
    "install.ps1",
}
_TEXT_PREFIXES = (
    "scripts/",
    "src/",
    "validator-node/src/",
    "vss-helper/",
)
_REQUIRED = {
    "README.md",
    "LICENSE",
    "PRIVACY.md",
    "SECURITY.md",
    "THIRD_PARTY_NOTICES.md",
    "install.ps1",
    "release-manifest.json",
    "runtime/python/python.exe",
    "runtime/node/node.exe",
    "scripts/Install-WeFlowChat.ps1",
    "scripts/Run-WeFlowChatInstalled.cmd",
    "src/weflow_chat/__init__.py",
}


class ReleaseVerificationError(RuntimeError):
    pass


def _strict_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ReleaseVerificationError("duplicate_json_key")
        value[key] = item
    return value


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest().upper()


def _relative_entry(name: str, expected_root: str) -> str | None:
    normalized = name.replace("\\", "/")
    if (
        not normalized
        or normalized.startswith("/")
        or re.match(r"^[A-Za-z]:", normalized)
    ):
        raise ReleaseVerificationError("archive_path_invalid")
    parts = normalized.rstrip("/").split("/")
    if (
        not parts
        or parts[0] != expected_root
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise ReleaseVerificationError("archive_path_invalid")
    if len(parts) == 1:
        return None
    return "/".join(parts[1:])


def verify_release(
    *, archive_path: Path, sha256_path: Path, version: str
) -> str:
    if _VERSION.fullmatch(version) is None:
        raise ReleaseVerificationError("version_invalid")
    archive = archive_path.resolve(strict=True)
    digest_file = sha256_path.resolve(strict=True)
    expected_name = f"weflow-chat-{version}-win-x64.zip"
    if archive.name != expected_name:
        raise ReleaseVerificationError("archive_name_invalid")
    actual_archive_hash = _sha256(archive.read_bytes())
    try:
        digest_line = digest_file.read_text(encoding="ascii")
    except (OSError, UnicodeError) as error:
        raise ReleaseVerificationError("digest_file_invalid") from error
    if digest_line != f"{actual_archive_hash}  {expected_name}\n" and (
        digest_line != f"{actual_archive_hash}  {expected_name}\r\n"
    ):
        raise ReleaseVerificationError("archive_hash_mismatch")

    expected_root = f"weflow-chat-{version}"
    payloads: dict[str, bytes] = {}
    names_casefold: set[str] = set()
    total = 0
    try:
        with zipfile.ZipFile(archive) as package:
            for item in package.infolist():
                relative = _relative_entry(item.filename, expected_root)
                unix_mode = (item.external_attr >> 16) & 0xFFFF
                if unix_mode and stat.S_ISLNK(unix_mode):
                    raise ReleaseVerificationError("archive_link_rejected")
                if item.is_dir() or relative is None:
                    continue
                folded = relative.casefold()
                if folded in names_casefold:
                    raise ReleaseVerificationError("archive_name_collision")
                names_casefold.add(folded)
                if item.file_size > _MAX_ENTRY_BYTES:
                    raise ReleaseVerificationError("archive_entry_too_large")
                total += item.file_size
                if total > _MAX_ARCHIVE_BYTES:
                    raise ReleaseVerificationError("archive_too_large")
                payloads[relative] = package.read(item)
    except (OSError, zipfile.BadZipFile) as error:
        raise ReleaseVerificationError("archive_invalid") from error

    if not _REQUIRED <= set(payloads):
        raise ReleaseVerificationError("required_file_missing")
    if any(
        PurePosixPath(name).parts[0] in {"tests", ".git", "docs"}
        for name in payloads
    ):
        raise ReleaseVerificationError("release_scope_invalid")

    try:
        manifest = json.loads(
            payloads["release-manifest.json"].decode("utf-8-sig"),
            object_pairs_hook=_strict_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ReleaseVerificationError("manifest_nonfinite")
            ),
        )
    except ReleaseVerificationError:
        raise
    except (UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise ReleaseVerificationError("manifest_invalid") from error
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {"schemaVersion", "version", "files"}
        or manifest["schemaVersion"] != 1
        or manifest["version"] != version
        or not isinstance(manifest["files"], list)
        or not manifest["files"]
    ):
        raise ReleaseVerificationError("manifest_invalid")
    listed: dict[str, tuple[int, str]] = {}
    for entry in manifest["files"]:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"path", "sha256", "size"}
            or not isinstance(entry["path"], str)
            or not isinstance(entry["sha256"], str)
            or _HEX64.fullmatch(entry["sha256"]) is None
            or type(entry["size"]) is not int
            or entry["size"] < 0
            or entry["path"] == "release-manifest.json"
            or entry["path"] in listed
            or _relative_entry(
                f"{expected_root}/{entry['path']}", expected_root
            )
            != entry["path"]
        ):
            raise ReleaseVerificationError("manifest_invalid")
        listed[entry["path"]] = (entry["size"], entry["sha256"])
    actual_names = set(payloads) - {"release-manifest.json"}
    if set(listed) != actual_names:
        raise ReleaseVerificationError("manifest_file_set_mismatch")
    for name, (size, digest) in listed.items():
        payload = payloads[name]
        if len(payload) != size or _sha256(payload) != digest:
            raise ReleaseVerificationError("manifest_hash_mismatch")
        if name in _TEXT_PATHS or name.startswith(_TEXT_PREFIXES):
            if scan_payload(
                scope="release", path=name, payload=payload
            ):
                raise ReleaseVerificationError("release_privacy_finding")
    return actual_archive_hash


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="verify-release")
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--sha256", type=Path, required=True)
    parser.add_argument("--version", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        digest = verify_release(
            archive_path=arguments.archive,
            sha256_path=arguments.sha256,
            version=arguments.version,
        )
    except (OSError, ReleaseVerificationError):
        print("release_verification_failed", file=sys.stderr)
        return 1
    print(f"release_verification_ok:{digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

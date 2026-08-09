from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import uuid

from weflow_chat.atomic_io import (
    atomic_write_bytes,
    replace_write_through,
)
from weflow_chat.manifest import (
    CopyVerificationError,
    build_manifest,
    content_signature,
    validate_account_role_tree,
    validate_scandir_entry,
)
from weflow_chat.media import (
    MediaStoreManifest,
    MediaStoreReceipt,
)
from weflow_chat.models import CopyRole
from weflow_chat.paths import (
    assert_descendant,
    canonical_existing,
    canonical_future,
)


_ACCOUNT_RE = re.compile(r"wxid_[A-Za-z0-9_]{1,128}")
_SHA256_RE = re.compile(r"[0-9A-F]{64}")
_MEDIA_ROOTS = {
    ("msg", "attach"),
    ("msg", "video"),
}
_LEGACY_WINDOWS_FILE_PATH_MAX = 259
_LEGACY_WINDOWS_DIRECTORY_PATH_MAX = 247


class PresentationError(RuntimeError):
    pass


def _require_presentation_path_budget(
        *,
        partial_root: Path,
        final_root: Path,
        manifest_path: Path,
        relative_files: tuple[PurePosixPath, ...],
        required_directories: tuple[PurePosixPath, ...],
) -> None:
    if os.name != "nt":
        return
    for root in (partial_root, final_root):
        if (
            len(str(root))
            > _LEGACY_WINDOWS_DIRECTORY_PATH_MAX
            or any(
                len(str(root.joinpath(*relative.parts)))
                > _LEGACY_WINDOWS_DIRECTORY_PATH_MAX
                for relative in required_directories
            )
        ):
            raise PresentationError(
                "presentation_path_budget_exceeded"
            )
        for relative in relative_files:
            path = root.joinpath(*relative.parts)
            if (
                len(str(path)) > _LEGACY_WINDOWS_FILE_PATH_MAX
                or len(str(path.parent))
                > _LEGACY_WINDOWS_DIRECTORY_PATH_MAX
            ):
                raise PresentationError(
                    "presentation_path_budget_exceeded"
                )
    if (
        len(str(manifest_path)) > _LEGACY_WINDOWS_FILE_PATH_MAX
        or len(str(manifest_path.parent))
        > _LEGACY_WINDOWS_DIRECTORY_PATH_MAX
    ):
        raise PresentationError("presentation_path_budget_exceeded")


@dataclass(frozen=True, slots=True)
class PresentationFile:
    relative_path: str
    kind: str
    size: int
    sha256: str
    device_id: int
    file_id: int


@dataclass(frozen=True, slots=True)
class PresentationManifest:
    schema_version: int
    source_account_name: str
    media_store_manifest_sha256: str
    files: tuple[PresentationFile, ...]
    file_count: int
    byte_count: int


@dataclass(frozen=True, slots=True)
class PresentationReceipt:
    schema_version: int
    presentation_root: Path
    manifest_path: Path
    manifest_sha256: str
    manifest: PresentationManifest
    file_count: int
    byte_count: int


def _manifest_value(manifest: PresentationManifest) -> dict[str, object]:
    return {
        "schemaVersion": manifest.schema_version,
        "sourceAccountName": manifest.source_account_name,
        "mediaStoreManifestSha256": (
            manifest.media_store_manifest_sha256
        ),
        "fileCount": manifest.file_count,
        "byteCount": manifest.byte_count,
        "files": [
            {
                "relativePath": item.relative_path,
                "kind": item.kind,
                "size": item.size,
                "sha256": item.sha256,
                "deviceId": item.device_id,
                "fileId": item.file_id,
            }
            for item in manifest.files
        ],
    }


def _canonical_manifest(manifest: PresentationManifest) -> bytes:
    return json.dumps(
        _manifest_value(manifest),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _canonical_receipt(
        manifest: PresentationManifest,
        manifest_sha256: str,
) -> bytes:
    return json.dumps(
        {
            "schemaVersion": 1,
            "manifestSha256": manifest_sha256,
            "manifest": _manifest_value(manifest),
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _reject_duplicate_keys(
        pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"invalid_json_constant:{value}")


def _read_stable_plain_file(
        path: Path,
        *,
        maximum_size: int,
) -> tuple[bytes, Path]:
    canonical = canonical_existing(path)
    before = canonical.stat(follow_symlinks=False)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_size <= 0
        or before.st_size > maximum_size
    ):
        raise ValueError("plain_file_required")
    flags = os.O_RDONLY
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(canonical, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            (opened.st_dev, opened.st_ino, opened.st_size)
            != (before.st_dev, before.st_ino, before.st_size)
        ):
            raise ValueError("file_identity_changed")
        chunks = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise ValueError("file_short_read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ValueError("file_grew_during_read")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    named = canonical.stat(follow_symlinks=False)
    if (
        (after.st_dev, after.st_ino, after.st_size)
        != (before.st_dev, before.st_ino, before.st_size)
        or (named.st_dev, named.st_ino, named.st_size)
        != (before.st_dev, before.st_ino, before.st_size)
    ):
        raise ValueError("file_identity_changed")
    return b"".join(chunks), canonical


def _canonical_media_manifest(manifest: MediaStoreManifest) -> bytes:
    return json.dumps(
        {
            "schemaVersion": manifest.schema_version,
            "sourceAccountName": manifest.source_account_name,
            "fileCount": manifest.file_count,
            "byteCount": manifest.byte_count,
            "files": [
                {
                    "relativePath": item.relative_path,
                    "size": item.size,
                    "sha256": item.sha256,
                    "volumeSerial": item.volume_serial,
                    "fileId": item.file_id,
                }
                for item in manifest.files
            ],
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def _validate_media_receipt(
        receipt: MediaStoreReceipt,
        *,
        account_name: str,
) -> tuple[bytes, Path]:
    if (
        type(receipt) is not MediaStoreReceipt
        or type(receipt.manifest) is not MediaStoreManifest
        or receipt.schema_version != 1
        or receipt.manifest.schema_version != 1
        or receipt.manifest.source_account_name != account_name
        or receipt.file_count != receipt.manifest.file_count
        or receipt.byte_count != receipt.manifest.byte_count
        or type(receipt.manifest_sha256) is not str
        or _SHA256_RE.fullmatch(receipt.manifest_sha256) is None
    ):
        raise PresentationError("media_store_receipt_invalid")
    try:
        manifest_path = canonical_existing(Path(receipt.manifest_path))
    except (OSError, ValueError) as error:
        raise PresentationError(
            "media_store_manifest_invalid"
        ) from error
    if not manifest_path.is_file() or manifest_path.name != "media-manifest.json":
        raise PresentationError("media_store_manifest_invalid")
    manifest_bytes = manifest_path.read_bytes()
    expected_bytes = _canonical_media_manifest(receipt.manifest)
    if (
        manifest_bytes != expected_bytes
        or sha256(manifest_bytes).hexdigest().upper()
        != receipt.manifest_sha256
    ):
        raise PresentationError("media_store_manifest_mismatch")
    paths = []
    folded = set()
    for item in receipt.manifest.files:
        relative = PurePosixPath(item.relative_path)
        key = relative.as_posix().casefold()
        if (
            relative.is_absolute()
            or "\\" in item.relative_path
            or ":" in item.relative_path
            or len(relative.parts) < 3
            or tuple(relative.parts[:2]) not in _MEDIA_ROOTS
            or any(part in ("", ".", "..") for part in relative.parts)
            or key in folded
            or type(item.size) is not int
            or item.size < 0
            or type(item.sha256) is not str
            or _SHA256_RE.fullmatch(item.sha256) is None
            or type(item.volume_serial) is not int
            or item.volume_serial < 0
            or type(item.file_id) is not int
            or item.file_id < 0
        ):
            raise PresentationError("media_store_receipt_invalid")
        folded.add(key)
        paths.append(item.relative_path)
    if (
        paths != sorted(paths)
        or len(paths) != receipt.manifest.file_count
        or sum(item.size for item in receipt.manifest.files)
        != receipt.manifest.byte_count
    ):
        raise PresentationError("media_store_receipt_invalid")
    return manifest_bytes, manifest_path.parent


def _copy_database_file(
        source: Path,
        destination: Path,
        *,
        expected_size: int,
        expected_sha256: str,
) -> PresentationFile:
    before = source.stat()
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    with destination.open("r+b") as stream:
        stream.flush()
        os.fsync(stream.fileno())
    after = source.stat()
    published = destination.stat()
    if (
        (before.st_dev, before.st_ino, before.st_size)
        != (after.st_dev, after.st_ino, after.st_size)
        or published.st_size != expected_size
        or _sha256_file(source) != expected_sha256
        or _sha256_file(destination) != expected_sha256
        or (published.st_dev, published.st_ino)
        == (after.st_dev, after.st_ino)
    ):
        raise PresentationError("presentation_database_copy_mismatch")
    return PresentationFile(
        relative_path="",
        kind="database",
        size=published.st_size,
        sha256=expected_sha256,
        device_id=published.st_dev,
        file_id=published.st_ino,
    )


def _copy_media_file(
        source: Path,
        destination: Path,
        *,
        expected_size: int,
        expected_sha256: str,
        expected_volume_serial: int,
        expected_file_id: int,
) -> PresentationFile:
    source = canonical_existing(source)
    before = source.stat()
    before_sha256 = _sha256_file(source)
    confirmed_before = source.stat()
    if (
        not source.is_file()
        or before.st_size != expected_size
        or before_sha256 != expected_sha256
        or (
            confirmed_before.st_dev,
            confirmed_before.st_ino,
            confirmed_before.st_size,
        ) != (before.st_dev, before.st_ino, before.st_size)
        or (before.st_dev, before.st_ino)
        != (expected_volume_serial, expected_file_id)
    ):
        raise PresentationError("media_store_file_mismatch")
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        shutil.copyfile(source, destination)
        with destination.open("r+b") as stream:
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as error:
        raise PresentationError(
            "presentation_media_copy_failed"
        ) from error
    after = source.stat()
    after_sha256 = _sha256_file(source)
    confirmed_after = source.stat()
    published = destination.stat()
    published_sha256 = _sha256_file(destination)
    confirmed_published = destination.stat()
    if (
        (before.st_dev, before.st_ino, before.st_size)
        != (after.st_dev, after.st_ino, after.st_size)
        or (
            confirmed_after.st_dev,
            confirmed_after.st_ino,
            confirmed_after.st_size,
        ) != (after.st_dev, after.st_ino, after.st_size)
        or after_sha256 != expected_sha256
        or published.st_size != expected_size
        or published_sha256 != expected_sha256
        or (
            confirmed_published.st_dev,
            confirmed_published.st_ino,
            confirmed_published.st_size,
        ) != (
            published.st_dev,
            published.st_ino,
            published.st_size,
        )
        or (published.st_dev, published.st_ino)
        == (after.st_dev, after.st_ino)
    ):
        raise PresentationError("presentation_media_copy_mismatch")
    return PresentationFile(
        relative_path="",
        kind="media",
        size=published.st_size,
        sha256=expected_sha256,
        device_id=published.st_dev,
        file_id=published.st_ino,
    )


def _plain_tree_paths(root: Path) -> tuple[set[str], set[str]]:
    root = canonical_existing(root)
    directories = set()
    files = set()
    pending = [root]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as opened:
            entries = list(opened)
        if len({item.name.casefold() for item in entries}) != len(entries):
            raise PresentationError("presentation_name_collision")
        for entry in entries:
            kind = validate_scandir_entry(entry)
            path = Path(entry.path)
            assert_descendant(path, root)
            relative = path.relative_to(root).as_posix()
            if kind == "directory":
                directories.add(relative)
                pending.append(path)
            else:
                files.add(relative)
    return directories, files


def _verify_published_files(
        root: Path,
        files: tuple[PresentationFile, ...],
) -> None:
    try:
        for item in files:
            path = canonical_existing(
                root.joinpath(
                    *PurePosixPath(item.relative_path).parts
                )
            )
            information = path.stat()
            if (
                not path.is_file()
                or information.st_size != item.size
                or information.st_dev != item.device_id
                or information.st_ino != item.file_id
                or _sha256_file(path) != item.sha256
            ):
                raise PresentationError(
                    "presentation_publication_mismatch"
                )
    except PresentationError:
        raise
    except (OSError, ValueError) as error:
        raise PresentationError(
            "presentation_publication_mismatch"
        ) from error


def _expected_tree_shape(
        account_name: str,
        files: tuple[PresentationFile, ...],
) -> tuple[set[str], set[str]]:
    expected_files = {item.relative_path for item in files}
    expected_directories = {
        account_name,
        f"{account_name}/db_storage",
        f"{account_name}/msg",
        f"{account_name}/msg/attach",
        f"{account_name}/msg/video",
    }
    for relative in expected_files:
        parent = PurePosixPath(relative).parent
        while parent != PurePosixPath("."):
            expected_directories.add(parent.as_posix())
            parent = parent.parent
    return expected_directories, expected_files


def _parse_presentation_manifest(
        value: object,
        *,
        account_name: str,
) -> PresentationManifest:
    manifest_keys = {
        "schemaVersion",
        "sourceAccountName",
        "mediaStoreManifestSha256",
        "files",
        "fileCount",
        "byteCount",
    }
    if type(value) is not dict or set(value) != manifest_keys:
        raise ValueError("manifest_shape_invalid")
    schema_version = value["schemaVersion"]
    source_account_name = value["sourceAccountName"]
    media_manifest_sha256 = value["mediaStoreManifestSha256"]
    file_count = value["fileCount"]
    byte_count = value["byteCount"]
    raw_files = value["files"]
    if (
        type(schema_version) is not int
        or schema_version != 1
        or type(source_account_name) is not str
        or source_account_name != account_name
        or type(media_manifest_sha256) is not str
        or _SHA256_RE.fullmatch(media_manifest_sha256) is None
        or type(file_count) is not int
        or file_count < 0
        or type(byte_count) is not int
        or byte_count < 0
        or type(raw_files) is not list
    ):
        raise ValueError("manifest_field_invalid")

    file_keys = {
        "relativePath",
        "kind",
        "size",
        "sha256",
        "deviceId",
        "fileId",
    }
    files = []
    folded = set()
    for raw in raw_files:
        if type(raw) is not dict or set(raw) != file_keys:
            raise ValueError("manifest_file_shape_invalid")
        relative_text = raw["relativePath"]
        kind = raw["kind"]
        size = raw["size"]
        content_sha256 = raw["sha256"]
        device_id = raw["deviceId"]
        file_id = raw["fileId"]
        if (
            type(relative_text) is not str
            or type(kind) is not str
            or kind not in {"database", "media"}
            or type(size) is not int
            or size < 0
            or type(content_sha256) is not str
            or _SHA256_RE.fullmatch(content_sha256) is None
            or type(device_id) is not int
            or device_id < 0
            or type(file_id) is not int
            or file_id < 0
        ):
            raise ValueError("manifest_file_field_invalid")
        relative = PurePosixPath(relative_text)
        parts = relative.parts
        folded_path = relative_text.casefold()
        common_invalid = (
            relative.is_absolute()
            or relative.as_posix() != relative_text
            or "\\" in relative_text
            or ":" in relative_text
            or any(part in ("", ".", "..") for part in parts)
            or folded_path in folded
        )
        database_invalid = (
            kind == "database"
            and (
                len(parts) < 3
                or tuple(parts[:2])
                != (account_name, "db_storage")
            )
        )
        media_invalid = (
            kind == "media"
            and (
                len(parts) < 4
                or parts[0] != account_name
                or tuple(parts[1:3]) not in _MEDIA_ROOTS
            )
        )
        if common_invalid or database_invalid or media_invalid:
            raise ValueError("manifest_relative_path_invalid")
        folded.add(folded_path)
        files.append(PresentationFile(
            relative_path=relative_text,
            kind=kind,
            size=size,
            sha256=content_sha256,
            device_id=device_id,
            file_id=file_id,
        ))
    if (
        [item.relative_path for item in files]
        != sorted(item.relative_path for item in files)
        or file_count != len(files)
        or byte_count != sum(item.size for item in files)
    ):
        raise ValueError("manifest_aggregate_invalid")
    return PresentationManifest(
        schema_version=schema_version,
        source_account_name=source_account_name,
        media_store_manifest_sha256=media_manifest_sha256,
        files=tuple(files),
        file_count=file_count,
        byte_count=byte_count,
    )


def read_presentation_receipt(
        path: Path,
        *,
        expected_presentation_root: Path,
        account_name: str,
) -> PresentationReceipt:
    if (
        type(account_name) is not str
        or _ACCOUNT_RE.fullmatch(account_name) is None
    ):
        raise PresentationError("presentation_receipt_invalid")
    try:
        presentation_root = canonical_existing(
            Path(expected_presentation_root)
        )
        if (
            presentation_root.name != "presentation"
            or not presentation_root.is_dir()
        ):
            raise ValueError("presentation_root_invalid")
        expected_manifest_path = canonical_existing(
            presentation_root.parent / "presentation-manifest.json"
        )
        receipt_bytes, manifest_path = _read_stable_plain_file(
            Path(path),
            maximum_size=64 * 1024 * 1024,
        )
        if manifest_path != expected_manifest_path:
            raise ValueError("manifest_path_invalid")
        value = json.loads(
            receipt_bytes.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
        if (
            type(value) is not dict
            or set(value)
            != {"schemaVersion", "manifestSha256", "manifest"}
            or type(value["schemaVersion"]) is not int
            or value["schemaVersion"] != 1
            or type(value["manifestSha256"]) is not str
            or _SHA256_RE.fullmatch(value["manifestSha256"]) is None
        ):
            raise ValueError("receipt_shape_invalid")
        manifest = _parse_presentation_manifest(
            value["manifest"],
            account_name=account_name,
        )
        canonical_manifest = _canonical_manifest(manifest)
        manifest_sha256 = sha256(
            canonical_manifest
        ).hexdigest().upper()
        if (
            manifest_sha256 != value["manifestSha256"]
            or receipt_bytes
            != _canonical_receipt(manifest, manifest_sha256)
        ):
            raise ValueError("receipt_canonical_hash_mismatch")
    except PresentationError:
        raise
    except (
        json.JSONDecodeError,
        OSError,
        TypeError,
        UnicodeError,
        ValueError,
    ) as error:
        raise PresentationError(
            "presentation_receipt_invalid"
        ) from error

    expected_directories, expected_files = _expected_tree_shape(
        account_name,
        manifest.files,
    )
    directories, files = _plain_tree_paths(presentation_root)
    if (
        directories != expected_directories
        or files != expected_files
    ):
        raise PresentationError("presentation_publication_mismatch")
    _verify_published_files(presentation_root, manifest.files)
    return PresentationReceipt(
        schema_version=1,
        presentation_root=presentation_root,
        manifest_path=manifest_path,
        manifest_sha256=manifest_sha256,
        manifest=manifest,
        file_count=manifest.file_count,
        byte_count=manifest.byte_count,
    )


def build_presentation(
        *,
        active_root: Path,
        media_receipt: MediaStoreReceipt,
        destination_root: Path,
        account_name: str,
) -> PresentationReceipt:
    if (
        type(account_name) is not str
        or _ACCOUNT_RE.fullmatch(account_name) is None
    ):
        raise PresentationError("presentation_account_invalid")
    try:
        active_root = canonical_existing(Path(active_root))
        validate_account_role_tree(
            active_root,
            source_account_name=account_name,
        )
        active_before = build_manifest(
            active_root,
            role=CopyRole.ACTIVE,
        )
    except (CopyVerificationError, OSError, ValueError) as error:
        raise PresentationError(
            "presentation_active_invalid"
        ) from error
    manifest_bytes, media_store_root = _validate_media_receipt(
        media_receipt,
        account_name=account_name,
    )
    destination_root = canonical_future(Path(destination_root))
    if (
        destination_root.name != "presentation"
        or os.path.lexists(destination_root)
    ):
        raise PresentationError("presentation_destination_invalid")
    destination_parent = canonical_existing(destination_root.parent)
    presentation_manifest_path = (
        destination_parent / "presentation-manifest.json"
    )
    if os.path.lexists(presentation_manifest_path):
        raise PresentationError("presentation_destination_invalid")
    media_store_root = canonical_existing(media_store_root)

    partial = destination_parent / (
        f".p.{uuid.uuid4().hex[:16]}"
    )
    relative_files = tuple(
        PurePosixPath(item.relative_path)
        for item in active_before.files
    ) + tuple(
        PurePosixPath(
            account_name,
            *PurePosixPath(item.relative_path).parts,
        )
        for item in media_receipt.manifest.files
    )
    _require_presentation_path_budget(
        partial_root=partial,
        final_root=destination_root,
        manifest_path=presentation_manifest_path,
        relative_files=relative_files,
        required_directories=(
            PurePosixPath(account_name),
            PurePosixPath(account_name, "msg"),
            PurePosixPath(account_name, "msg", "attach"),
            PurePosixPath(account_name, "msg", "video"),
        ),
    )
    partial.mkdir()
    account_root = partial / account_name
    (account_root / "msg" / "attach").mkdir(parents=True)
    (account_root / "msg" / "video").mkdir(parents=True)

    entries = []
    for item in active_before.files:
        source = active_root / Path(item.relative_path)
        destination = partial / Path(item.relative_path)
        copied = _copy_database_file(
            source,
            destination,
            expected_size=item.size,
            expected_sha256=item.sha256,
        )
        entries.append(PresentationFile(
            relative_path=item.relative_path,
            kind=copied.kind,
            size=copied.size,
            sha256=copied.sha256,
            device_id=copied.device_id,
            file_id=copied.file_id,
        ))
    store_account = media_store_root / account_name
    for item in media_receipt.manifest.files:
        relative = PurePosixPath(item.relative_path)
        source = store_account.joinpath(*relative.parts)
        presentation_relative = PurePosixPath(
            account_name,
            *relative.parts,
        ).as_posix()
        copied = _copy_media_file(
            source,
            partial.joinpath(*PurePosixPath(
                presentation_relative
            ).parts),
            expected_size=item.size,
            expected_sha256=item.sha256,
            expected_volume_serial=item.volume_serial,
            expected_file_id=item.file_id,
        )
        entries.append(PresentationFile(
            relative_path=presentation_relative,
            kind=copied.kind,
            size=copied.size,
            sha256=copied.sha256,
            device_id=copied.device_id,
            file_id=copied.file_id,
        ))

    active_after = build_manifest(
        active_root,
        role=CopyRole.ACTIVE,
    )
    if content_signature(active_after) != content_signature(active_before):
        raise PresentationError("active_changed_during_presentation")
    if (
        media_receipt.manifest_path.read_bytes() != manifest_bytes
        or sha256(manifest_bytes).hexdigest().upper()
        != media_receipt.manifest_sha256
    ):
        raise PresentationError("media_store_manifest_changed")

    entries.sort(key=lambda item: item.relative_path)
    expected_directories, expected_files = _expected_tree_shape(
        account_name,
        tuple(entries),
    )
    directories, files = _plain_tree_paths(partial)
    if (
        directories != expected_directories
        or files != expected_files
    ):
        raise PresentationError("presentation_tree_mismatch")

    manifest = PresentationManifest(
        schema_version=1,
        source_account_name=account_name,
        media_store_manifest_sha256=media_receipt.manifest_sha256,
        files=tuple(entries),
        file_count=len(entries),
        byte_count=sum(item.size for item in entries),
    )
    canonical_bytes = _canonical_manifest(manifest)
    replace_write_through(partial, destination_root)
    published = canonical_existing(destination_root)
    if published != destination_root:
        raise PresentationError("presentation_publication_mismatch")
    directories, files = _plain_tree_paths(published)
    if (
        directories != expected_directories
        or files != expected_files
    ):
        raise PresentationError("presentation_publication_mismatch")
    _verify_published_files(published, manifest.files)
    manifest_sha256 = sha256(canonical_bytes).hexdigest().upper()
    receipt_bytes = _canonical_receipt(manifest, manifest_sha256)
    try:
        atomic_write_bytes(
            presentation_manifest_path,
            receipt_bytes,
        )
    except OSError as error:
        raise PresentationError(
            "presentation_receipt_write_failed"
        ) from error
    receipt = read_presentation_receipt(
        presentation_manifest_path,
        expected_presentation_root=published,
        account_name=account_name,
    )
    if (
        receipt.manifest != manifest
        or receipt.manifest_sha256 != manifest_sha256
    ):
        raise PresentationError("presentation_receipt_invalid")
    return receipt

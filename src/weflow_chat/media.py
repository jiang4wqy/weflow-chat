from dataclasses import dataclass
from hashlib import sha256
import json
import os
import re
import stat
from pathlib import Path, PurePosixPath

from weflow_chat.atomic_io import atomic_write_json, replace_write_through


_SHA256_RE = re.compile(r"[0-9A-F]{64}")
_ACCOUNT_RE = re.compile(r"[A-Za-z0-9_]{1,128}")
_ALLOWED_ROOTS = {
    ("msg", "attach"),
    ("msg", "video"),
}
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_MAX_MANIFEST_BYTES = 64 * 1024 * 1024


class MediaImportError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class MediaStoreFile:
    relative_path: str
    size: int
    sha256: str
    volume_serial: int
    file_id: int


@dataclass(frozen=True, slots=True)
class _StagedMediaFile:
    relative_path: str
    size: int
    sha256: str


@dataclass(frozen=True, slots=True)
class MediaStoreManifest:
    schema_version: int
    source_account_name: str
    files: tuple[MediaStoreFile, ...]
    file_count: int
    byte_count: int


@dataclass(frozen=True, slots=True)
class MediaStoreReceipt:
    schema_version: int
    manifest_path: Path
    manifest_sha256: str
    manifest: MediaStoreManifest
    file_count: int
    byte_count: int
    published_count: int
    skipped_count: int


def _validated_relative_path(value: object) -> PurePosixPath:
    if type(value) is not str or "\\" in value or ":" in value:
        raise MediaImportError("media_relative_path_invalid")
    relative = PurePosixPath(value)
    if (
            relative.is_absolute() or
            relative.as_posix() != value or
            len(relative.parts) < 3 or
            tuple(relative.parts[:2]) not in _ALLOWED_ROOTS or
            any(part in ("", ".", "..") for part in relative.parts)):
        raise MediaImportError("media_relative_path_invalid")
    return relative


def _validated_staging_files(receipt) -> tuple[_StagedMediaFile, ...]:
    if (
            type(receipt.source_account_name) is not str or
            _ACCOUNT_RE.fullmatch(receipt.source_account_name) is None or
            type(receipt.file_count) is not int or
            type(receipt.byte_count) is not int or
            receipt.file_count < 0 or receipt.byte_count < 0 or
            type(receipt.manifest_sha256) is not str or
            _SHA256_RE.fullmatch(receipt.manifest_sha256) is None):
        raise MediaImportError("media_staging_receipt_invalid")
    files = []
    folded_paths = set()
    for item in receipt.files:
        relative = _validated_relative_path(item.relative_path)
        folded = relative.as_posix().casefold()
        if folded in folded_paths:
            raise MediaImportError("media_relative_path_collision")
        folded_paths.add(folded)
        if (
                type(item.size) is not int or item.size < 0 or
                type(item.sha256) is not str or
                _SHA256_RE.fullmatch(item.sha256) is None):
            raise MediaImportError("media_staging_receipt_invalid")
        files.append(_StagedMediaFile(
            relative.as_posix(), item.size, item.sha256))
    files.sort(key=lambda item: item.relative_path)
    if (
            len(files) != receipt.file_count or
            sum(item.size for item in files) != receipt.byte_count or
            _staging_manifest_sha256(tuple(files)) !=
            receipt.manifest_sha256):
        raise MediaImportError("media_staging_receipt_invalid")
    return tuple(files)


def _staging_manifest_sha256(
        files: tuple[_StagedMediaFile, ...]) -> str:
    payload = json.dumps(
        [
            {
                "relativePath": item.relative_path,
                "size": item.size,
                "sha256": item.sha256,
            }
            for item in files
        ],
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return sha256(payload).hexdigest().upper()


def _ordinary_path_kind(path: Path) -> str:
    try:
        info = path.lstat()
    except OSError as error:
        raise MediaImportError("media_staging_tree_invalid") from error
    if path.is_symlink() or (
            getattr(info, "st_file_attributes", 0) & _REPARSE_POINT):
        raise MediaImportError("media_staging_tree_invalid")
    if stat.S_ISDIR(info.st_mode):
        return "directory"
    if stat.S_ISREG(info.st_mode):
        return "file"
    raise MediaImportError("media_staging_tree_invalid")


def _validate_staging_tree(
        staging_root: Path, *, account_name: str,
        expected_files: tuple[_StagedMediaFile, ...]) -> Path:
    if _ordinary_path_kind(staging_root) != "directory":
        raise MediaImportError("media_staging_tree_invalid")
    try:
        top_entries = list(os.scandir(staging_root))
    except OSError as error:
        raise MediaImportError("media_staging_tree_invalid") from error
    if (
            len(top_entries) != 1 or
            top_entries[0].name != account_name or
            _ordinary_path_kind(Path(top_entries[0].path)) != "directory"):
        raise MediaImportError("media_staging_tree_invalid")
    account_root = Path(top_entries[0].path)
    pending = [account_root]
    actual_files = []
    while pending:
        directory = pending.pop()
        try:
            entries = list(os.scandir(directory))
        except OSError as error:
            raise MediaImportError("media_staging_tree_invalid") from error
        folded_names = [entry.name.casefold() for entry in entries]
        if len(folded_names) != len(set(folded_names)):
            raise MediaImportError("media_staging_tree_invalid")
        for entry in entries:
            path = Path(entry.path)
            kind = _ordinary_path_kind(path)
            relative = path.relative_to(account_root).as_posix()
            parts = PurePosixPath(relative).parts
            if kind == "directory":
                if (
                        (len(parts) == 1 and parts != ("msg",)) or
                        (len(parts) == 2 and tuple(parts) not in _ALLOWED_ROOTS) or
                        (len(parts) > 1 and parts[0] != "msg") or
                        ":" in entry.name):
                    raise MediaImportError("media_staging_tree_invalid")
                pending.append(path)
            else:
                _validated_relative_path(relative)
                actual_files.append(relative)
    if tuple(sorted(actual_files)) != tuple(
            item.relative_path for item in expected_files):
        raise MediaImportError("media_staging_tree_invalid")
    return account_root


def _copy_verified(source: Path, temporary: Path,
                   expected: _StagedMediaFile) -> None:
    digest = sha256()
    byte_count = 0
    with source.open("rb") as reader, temporary.open("xb") as writer:
        while chunk := reader.read(1024 * 1024):
            writer.write(chunk)
            digest.update(chunk)
            byte_count += len(chunk)
        writer.flush()
        os.fsync(writer.fileno())
    if (
            byte_count != expected.size or
            digest.hexdigest().upper() != expected.sha256):
        raise MediaImportError("media_staging_file_mismatch")


def _verify_staging_source(
        path: Path, expected: _StagedMediaFile) -> None:
    descriptor = None
    try:
        before = path.lstat()
        if (
                path.is_symlink() or
                getattr(before, "st_file_attributes", 0) & _REPARSE_POINT or
                not stat.S_ISREG(before.st_mode) or
                before.st_size != expected.size):
            raise MediaImportError("media_staging_file_mismatch")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOINHERIT", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (
                not stat.S_ISREG(opened.st_mode) or
                (opened.st_dev, opened.st_ino) !=
                (before.st_dev, before.st_ino)):
            raise MediaImportError("media_staging_file_mismatch")
        digest = sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        after = os.fstat(descriptor)
        named = path.lstat()
        if (
                getattr(named, "st_file_attributes", 0) & _REPARSE_POINT or
                not stat.S_ISREG(named.st_mode) or
                (after.st_dev, after.st_ino, after.st_size) !=
                (opened.st_dev, opened.st_ino, opened.st_size) or
                (named.st_dev, named.st_ino, named.st_size) !=
                (opened.st_dev, opened.st_ino, opened.st_size) or
                digest.hexdigest().upper() != expected.sha256):
            raise MediaImportError("media_staging_file_mismatch")
    except MediaImportError:
        raise
    except OSError as error:
        raise MediaImportError("media_staging_file_mismatch") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _manifest_json(manifest: MediaStoreManifest) -> dict[str, object]:
    return {
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
    }


def _reject_duplicate_json_keys(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate_key")
        value[key] = item
    return value


def _read_manifest_bytes(path: Path) -> bytes:
    descriptor = None
    try:
        before = path.lstat()
        if (
                path.is_symlink() or
                getattr(before, "st_file_attributes", 0) & _REPARSE_POINT or
                not stat.S_ISREG(before.st_mode) or
                before.st_size > _MAX_MANIFEST_BYTES):
            raise ValueError
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOINHERIT", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (
                not stat.S_ISREG(opened.st_mode) or
                (opened.st_dev, opened.st_ino) !=
                (before.st_dev, before.st_ino)):
            raise ValueError
        chunks = []
        remaining = _MAX_MANIFEST_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        named = path.lstat()
        if (
                len(payload) > _MAX_MANIFEST_BYTES or
                (after.st_dev, after.st_ino, after.st_size) !=
                (opened.st_dev, opened.st_ino, len(payload)) or
                (named.st_dev, named.st_ino, named.st_size) !=
                (opened.st_dev, opened.st_ino, len(payload))):
            raise ValueError
        return payload
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _read_prior_manifest(
        path: Path, *, expected_account_name: str
        ) -> MediaStoreManifest | None:
    if not path.exists():
        return None
    try:
        raw = json.loads(
            _read_manifest_bytes(path).decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError),
        )
        if (
                type(raw) is not dict or
                set(raw) != {
                    "schemaVersion", "sourceAccountName", "fileCount",
                    "byteCount", "files",
                } or
                type(raw["schemaVersion"]) is not int or
                raw["schemaVersion"] != 1 or
                raw["sourceAccountName"] != expected_account_name or
                type(raw["fileCount"]) is not int or
                type(raw["byteCount"]) is not int or
                type(raw["files"]) is not list):
            raise ValueError
        files = []
        folded_paths = set()
        for value in raw["files"]:
            if (
                    type(value) is not dict or
                    set(value) != {
                        "relativePath", "size", "sha256",
                        "volumeSerial", "fileId",
                    } or
                    type(value["size"]) is not int or value["size"] < 0 or
                    type(value["sha256"]) is not str or
                    _SHA256_RE.fullmatch(value["sha256"]) is None or
                    type(value["volumeSerial"]) is not int or
                    value["volumeSerial"] < 0 or
                    type(value["fileId"]) is not int or
                    value["fileId"] < 0):
                raise ValueError
            relative = _validated_relative_path(value["relativePath"])
            folded = relative.as_posix().casefold()
            if folded in folded_paths:
                raise ValueError
            folded_paths.add(folded)
            files.append(MediaStoreFile(
                relative.as_posix(), value["size"], value["sha256"],
                value["volumeSerial"], value["fileId"]))
        if (
                files != sorted(files, key=lambda item: item.relative_path) or
                len(files) != raw["fileCount"] or
                sum(item.size for item in files) != raw["byteCount"]):
            raise ValueError
        return MediaStoreManifest(
            schema_version=1,
            source_account_name=expected_account_name,
            files=tuple(files),
            file_count=len(files),
            byte_count=sum(item.size for item in files),
        )
    except (AttributeError, json.JSONDecodeError, OSError, TypeError,
            UnicodeError, ValueError) as error:
        raise MediaImportError("media_store_manifest_invalid") from error


def _same_content(left: MediaStoreFile,
                  right: _StagedMediaFile) -> bool:
    return (
        left.relative_path == right.relative_path and
        left.size == right.size and
        left.sha256 == right.sha256
    )


def _published_store_file(
        path: Path, expected: _StagedMediaFile, *,
        expected_identity: MediaStoreFile | None = None,
        ) -> MediaStoreFile:
    descriptor = None
    try:
        before = path.lstat()
        if (
                path.is_symlink() or
                getattr(before, "st_file_attributes", 0) & _REPARSE_POINT or
                not stat.S_ISREG(before.st_mode) or
                before.st_size != expected.size):
            raise MediaImportError("media_store_manifest_mismatch")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOINHERIT", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (
                not stat.S_ISREG(opened.st_mode) or
                (opened.st_dev, opened.st_ino) !=
                (before.st_dev, before.st_ino)):
            raise MediaImportError("media_store_manifest_mismatch")
        digest = sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        after = os.fstat(descriptor)
        named = path.lstat()
        if (
                getattr(named, "st_file_attributes", 0) & _REPARSE_POINT or
                not stat.S_ISREG(named.st_mode) or
                (after.st_dev, after.st_ino, after.st_size) !=
                (opened.st_dev, opened.st_ino, opened.st_size) or
                (named.st_dev, named.st_ino, named.st_size) !=
                (opened.st_dev, opened.st_ino, opened.st_size) or
                digest.hexdigest().upper() != expected.sha256):
            raise MediaImportError("media_store_manifest_mismatch")
        published = MediaStoreFile(
            relative_path=expected.relative_path,
            size=expected.size,
            sha256=expected.sha256,
            volume_serial=opened.st_dev,
            file_id=opened.st_ino,
        )
        if (
                expected_identity is not None and
                (
                    published.volume_serial !=
                    expected_identity.volume_serial or
                    published.file_id != expected_identity.file_id
                )):
            raise MediaImportError("media_store_manifest_mismatch")
        return published
    except MediaImportError:
        raise
    except OSError as error:
        raise MediaImportError("media_store_manifest_mismatch") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _store_path_kind(path: Path) -> str:
    try:
        info = path.lstat()
    except OSError as error:
        raise MediaImportError("media_store_manifest_mismatch") from error
    if path.is_symlink() or (
            getattr(info, "st_file_attributes", 0) & _REPARSE_POINT):
        raise MediaImportError("media_store_manifest_mismatch")
    if stat.S_ISDIR(info.st_mode):
        return "directory"
    if stat.S_ISREG(info.st_mode):
        return "file"
    raise MediaImportError("media_store_manifest_mismatch")


def _reject_store_reparse_chain(path: Path) -> None:
    absolute = path.absolute()
    for current in (absolute, *absolute.parents):
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            raise MediaImportError(
                "media_store_manifest_mismatch") from error
        if current.is_symlink() or (
                getattr(info, "st_file_attributes", 0) & _REPARSE_POINT):
            raise MediaImportError("media_store_manifest_mismatch")


def _prepare_store_account(
        root: Path, *, account_name: str,
        create_missing: bool) -> tuple[Path, Path]:
    _reject_store_reparse_chain(root)
    if not root.exists():
        if not create_missing:
            raise MediaImportError("media_store_manifest_mismatch")
        root.mkdir(parents=True)
    _reject_store_reparse_chain(root)
    if _store_path_kind(root) != "directory":
        raise MediaImportError("media_store_manifest_mismatch")
    manifest_path = root / "media-manifest.json"
    account = root / account_name
    try:
        entries = list(os.scandir(root))
    except OSError as error:
        raise MediaImportError("media_store_manifest_mismatch") from error
    folded = [entry.name.casefold() for entry in entries]
    if len(folded) != len(set(folded)):
        raise MediaImportError("media_store_manifest_mismatch")
    for entry in entries:
        path = Path(entry.path)
        if entry.name == manifest_path.name:
            if _store_path_kind(path) != "file":
                raise MediaImportError("media_store_manifest_mismatch")
        elif entry.name == account_name:
            if _store_path_kind(path) != "directory":
                raise MediaImportError("media_store_manifest_mismatch")
        else:
            raise MediaImportError("media_store_manifest_mismatch")
    return account, manifest_path


def _validate_store_account(
        account: Path, *,
        expected_files: tuple[MediaStoreFile, ...],
        create_missing: bool) -> None:
    if not account.exists():
        if expected_files or not create_missing:
            raise MediaImportError("media_store_manifest_mismatch")
        account.mkdir()
        return
    if _store_path_kind(account) != "directory":
        raise MediaImportError("media_store_manifest_mismatch")
    pending = [account]
    actual_files = []
    actual_directories = set()
    while pending:
        directory = pending.pop()
        try:
            entries = list(os.scandir(directory))
        except OSError as error:
            raise MediaImportError("media_store_manifest_mismatch") from error
        folded = [entry.name.casefold() for entry in entries]
        if len(folded) != len(set(folded)):
            raise MediaImportError("media_store_manifest_mismatch")
        for entry in entries:
            path = Path(entry.path)
            relative = path.relative_to(account).as_posix()
            kind = _store_path_kind(path)
            if kind == "directory":
                actual_directories.add(relative)
                pending.append(path)
            else:
                _validated_relative_path(relative)
                actual_files.append(relative)
    expected_paths = {item.relative_path for item in expected_files}
    expected_directories = set()
    for relative in expected_paths:
        parent = PurePosixPath(relative).parent
        while parent.parts:
            expected_directories.add(parent.as_posix())
            parent = parent.parent
    if (
            set(actual_files) != expected_paths or
            actual_directories != expected_directories):
        raise MediaImportError("media_store_manifest_mismatch")


def read_media_store_receipt(
        media_store_root: Path,
        source_account_name: str) -> MediaStoreReceipt | None:
    if (
            type(source_account_name) is not str or
            _ACCOUNT_RE.fullmatch(source_account_name) is None):
        raise MediaImportError("media_store_manifest_mismatch")
    root = Path(media_store_root)
    _reject_store_reparse_chain(root)
    if not root.exists():
        return None
    account, manifest_path = _prepare_store_account(
        root, account_name=source_account_name, create_missing=False)
    if not manifest_path.exists():
        try:
            entries = tuple(os.scandir(root))
        except OSError as error:
            raise MediaImportError(
                "media_store_manifest_mismatch") from error
        if entries:
            raise MediaImportError("media_store_manifest_mismatch")
        return None
    manifest_bytes = _read_manifest_bytes(manifest_path)
    manifest = _read_prior_manifest(
        manifest_path, expected_account_name=source_account_name)
    if manifest is None:
        raise MediaImportError("media_store_manifest_mismatch")
    canonical_manifest_bytes = json.dumps(
        _manifest_json(manifest),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if manifest_bytes != canonical_manifest_bytes:
        raise MediaImportError("media_store_manifest_mismatch")
    _validate_store_account(
        account, expected_files=manifest.files, create_missing=False)
    for item in manifest.files:
        _published_store_file(
            account.joinpath(*PurePosixPath(item.relative_path).parts),
            _StagedMediaFile(item.relative_path, item.size, item.sha256),
            expected_identity=item,
        )
    _validate_store_account(
        account, expected_files=manifest.files, create_missing=False)
    second_account, second_manifest_path = _prepare_store_account(
        root, account_name=source_account_name, create_missing=False)
    if second_account != account or second_manifest_path != manifest_path:
        raise MediaImportError("media_store_manifest_mismatch")
    if _read_manifest_bytes(manifest_path) != manifest_bytes:
        raise MediaImportError("media_store_manifest_mismatch")
    return MediaStoreReceipt(
        schema_version=1,
        manifest_path=manifest_path,
        manifest_sha256=sha256(manifest_bytes).hexdigest().upper(),
        manifest=manifest,
        file_count=manifest.file_count,
        byte_count=manifest.byte_count,
        published_count=0,
        skipped_count=manifest.file_count,
    )


def import_media_staging(
        staging_receipt, *, media_store_root: Path) -> MediaStoreReceipt:
    files = _validated_staging_files(staging_receipt)
    staging_root = Path(staging_receipt.staging_path)
    account_name = staging_receipt.source_account_name
    source_account = _validate_staging_tree(
        staging_root, account_name=account_name, expected_files=files)
    media_store_root = Path(media_store_root)
    store_account, manifest_path = _prepare_store_account(
        media_store_root, account_name=account_name, create_missing=True)
    prior = _read_prior_manifest(
        manifest_path, expected_account_name=account_name)
    _validate_store_account(
        store_account,
        expected_files=prior.files if prior is not None else (),
        create_missing=True,
    )
    prior_by_path = {
        item.relative_path: item for item in prior.files
    } if prior is not None else {}
    incoming_by_path = {item.relative_path: item for item in files}
    reconciled_prior = {}
    for item in prior_by_path.values():
        destination = store_account.joinpath(
            *PurePosixPath(item.relative_path).parts)
        prior_content = _StagedMediaFile(
            item.relative_path, item.size, item.sha256)
        try:
            current = _published_store_file(
                destination,
                prior_content,
                expected_identity=item,
            )
        except MediaImportError:
            incoming = incoming_by_path.get(item.relative_path)
            if incoming is None or _same_content(item, incoming):
                raise
            current = _published_store_file(destination, incoming)
            if (
                    current.volume_serial != item.volume_serial or
                    current.file_id == item.file_id):
                raise MediaImportError("media_store_manifest_mismatch")
            _verify_staging_source(
                source_account.joinpath(
                    *PurePosixPath(incoming.relative_path).parts),
                incoming,
            )
        reconciled_prior[item.relative_path] = current
    prior_by_path = reconciled_prior

    prepared = []
    published_paths = set()
    skipped_count = 0
    try:
        for item in files:
            relative = PurePosixPath(item.relative_path)
            source = source_account.joinpath(*relative.parts)
            destination = store_account.joinpath(*relative.parts)
            prior_item = prior_by_path.get(item.relative_path)
            if (
                    prior_item is not None and
                    _same_content(prior_item, item)):
                skipped_count += 1
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            temporary = destination.with_name(
                f".{destination.name}.{os.urandom(8).hex()}.partial")
            _copy_verified(source, temporary, item)
            prepared.append((temporary, destination))
        for temporary, destination in prepared:
            replace_write_through(temporary, destination)
            published_paths.add(
                destination.relative_to(store_account).as_posix())
    except BaseException:
        for temporary, _destination in prepared:
            if temporary.exists():
                temporary.unlink()
        raise

    merged_content = {
        item.relative_path: _StagedMediaFile(
            item.relative_path, item.size, item.sha256)
        for item in prior_by_path.values()
    }
    merged_content.update((item.relative_path, item) for item in files)
    published_files = []
    for relative_path in sorted(merged_content):
        item = merged_content[relative_path]
        destination = store_account.joinpath(
            *PurePosixPath(relative_path).parts)
        prior_identity = prior_by_path.get(relative_path)
        if relative_path in published_paths:
            prior_identity = None
        published_files.append(_published_store_file(
            destination, item, expected_identity=prior_identity))
    manifest_files = tuple(published_files)
    manifest = MediaStoreManifest(
        schema_version=1,
        source_account_name=account_name,
        files=manifest_files,
        file_count=len(manifest_files),
        byte_count=sum(item.size for item in manifest_files),
    )
    atomic_write_json(manifest_path, _manifest_json(manifest))
    try:
        manifest_bytes = _read_manifest_bytes(manifest_path)
    except (OSError, ValueError) as error:
        raise MediaImportError("media_manifest_reread_mismatch") from error
    expected_bytes = json.dumps(
        _manifest_json(manifest), ensure_ascii=False, sort_keys=True,
        separators=(",", ":")).encode("utf-8")
    if manifest_bytes != expected_bytes:
        raise MediaImportError("media_manifest_reread_mismatch")
    reread = _read_prior_manifest(
        manifest_path, expected_account_name=account_name)
    if reread != manifest:
        raise MediaImportError("media_manifest_reread_mismatch")
    for item in reread.files:
        _published_store_file(
            store_account.joinpath(
                *PurePosixPath(item.relative_path).parts),
            _StagedMediaFile(
                item.relative_path, item.size, item.sha256),
            expected_identity=item,
        )
    return MediaStoreReceipt(
        schema_version=1,
        manifest_path=manifest_path,
        manifest_sha256=sha256(manifest_bytes).hexdigest().upper(),
        manifest=manifest,
        file_count=manifest.file_count,
        byte_count=manifest.byte_count,
        published_count=len(prepared),
        skipped_count=skipped_count,
    )

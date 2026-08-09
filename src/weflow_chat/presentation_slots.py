import ctypes
from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import uuid

from weflow_chat.atomic_io import (
    atomic_write_bytes,
    replace_write_through,
)
from weflow_chat.manifest import (
    CopyVerificationError,
    FileSetManifest,
    build_manifest,
    content_signature,
    validate_account_role_tree,
    validate_scandir_entry,
)
from weflow_chat.media import (
    MediaImportError,
    MediaStoreReceipt,
    read_media_store_receipt,
)
from weflow_chat.models import CopyRole
from weflow_chat.paths import (
    PathBoundaryError,
    assert_descendant,
    canonical_existing,
    canonical_future,
)


_ACCOUNT_RE = re.compile(r"wxid_[A-Za-z0-9_]{1,128}")
_GENERATION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_SLOT_NAMES = frozenset({"A", "B"})
_SLOT_LOCK_NAME = ".slot.lock"
_LEGACY_WINDOWS_FILE_PATH_MAX = 259
_LEGACY_WINDOWS_DIRECTORY_PATH_MAX = 247
_CONTROL_TEMP_RE = re.compile(
    r"\.(?:slot-manifest\.json|READY)\.[a-z0-9_]{8}"
)
_REPARSE_POINT = getattr(
    stat,
    "FILE_ATTRIBUTE_REPARSE_POINT",
    0x400,
)


class PresentationSlotError(RuntimeError):
    pass


def _require_slot_path_budget(
        *,
        slots_root: Path,
        slot_name: str,
        account_name: str,
        active: FileSetManifest,
        media: MediaStoreReceipt,
) -> None:
    if os.name != "nt":
        return
    slot_root = slots_root / slot_name
    presentation_root = slot_root / "presentation"
    relative_files = tuple(
        PurePosixPath(item.relative_path)
        for item in active.files
    ) + tuple(
        PurePosixPath(
            account_name,
            *PurePosixPath(item.relative_path).parts,
        )
        for item in media.manifest.files
    )
    directories = {slot_root, presentation_root}
    for relative in relative_files:
        destination = presentation_root.joinpath(*relative.parts)
        temporary = destination.with_name(
            f".{destination.name}.{'0' * 32}.partial"
        )
        if (
            len(str(destination)) > _LEGACY_WINDOWS_FILE_PATH_MAX
            or len(str(temporary)) > _LEGACY_WINDOWS_FILE_PATH_MAX
        ):
            raise PresentationSlotError("slot_path_budget_exceeded")
        parent = destination.parent
        while parent != slot_root:
            directories.add(parent)
            parent = parent.parent
    control_files = (
        slot_root / _SLOT_LOCK_NAME,
        slot_root / "slot-manifest.json",
        slot_root / "READY",
        slot_root / ".slot-manifest.json.00000000",
        slot_root / ".READY.00000000",
    )
    if (
        any(
            len(str(path)) > _LEGACY_WINDOWS_DIRECTORY_PATH_MAX
            for path in directories
        )
        or any(
            len(str(path)) > _LEGACY_WINDOWS_FILE_PATH_MAX
            for path in control_files
        )
    ):
        raise PresentationSlotError("slot_path_budget_exceeded")


class _WindowsFileTime(ctypes.Structure):
    _fields_ = [
        ("low", ctypes.c_uint32),
        ("high", ctypes.c_uint32),
    ]


class _WindowsFileInformation(ctypes.Structure):
    _fields_ = [
        ("attributes", ctypes.c_uint32),
        ("creation_time", _WindowsFileTime),
        ("access_time", _WindowsFileTime),
        ("write_time", _WindowsFileTime),
        ("volume_serial", ctypes.c_uint32),
        ("size_high", ctypes.c_uint32),
        ("size_low", ctypes.c_uint32),
        ("link_count", ctypes.c_uint32),
        ("file_index_high", ctypes.c_uint32),
        ("file_index_low", ctypes.c_uint32),
    ]


def _windows_handle_information(
        handle,
) -> _WindowsFileInformation:
    get_information = ctypes.WinDLL(
        "kernel32",
        use_last_error=True,
    ).GetFileInformationByHandle
    get_information.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(_WindowsFileInformation),
    ]
    get_information.restype = ctypes.c_int
    information = _WindowsFileInformation()
    if not get_information(handle, ctypes.byref(information)):
        raise ctypes.WinError(ctypes.get_last_error())
    return information


def _windows_file_id(
        information: _WindowsFileInformation,
) -> int:
    return (
        information.file_index_high << 32
        | information.file_index_low
    )


class _PinnedDirectory:
    def __init__(
            self,
            path: Path,
            *,
            expected_identity: tuple[int, int] | None = None,
    ) -> None:
        try:
            self.path = canonical_existing(Path(path))
            named = self.path.lstat()
            if (
                self.path.is_symlink()
                or getattr(
                    named,
                    "st_file_attributes",
                    0,
                ) & _REPARSE_POINT
                or not stat.S_ISDIR(named.st_mode)
            ):
                raise ValueError("slot_parent_not_ordinary")
            self.identity = (named.st_dev, named.st_ino)
            if (
                expected_identity is not None
                and self.identity != expected_identity
            ):
                raise ValueError("slot_parent_identity_changed")
        except (OSError, PathBoundaryError, ValueError) as error:
            raise PresentationSlotError("slot_parent_changed") from error
        self._handle = None
        self._descriptor = None
        try:
            if os.name == "nt":
                self._open_windows()
            else:
                self._open_portable()
            self.verify()
        except BaseException:
            self.close()
            raise

    def _open_windows(self) -> None:
        create_file = ctypes.WinDLL(
            "kernel32",
            use_last_error=True,
        ).CreateFileW
        create_file.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
        ]
        create_file.restype = ctypes.c_void_p
        handle = create_file(
            str(self.path),
            0x10080,
            0x3,
            None,
            3,
            0x02200000,
            None,
        )
        if handle == ctypes.c_void_p(-1).value:
            raise PresentationSlotError("slot_parent_pin_failed") from (
                ctypes.WinError(ctypes.get_last_error())
            )
        self._handle = handle

    def _open_portable(self) -> None:
        flags = os.O_RDONLY
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_DIRECTORY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            self._descriptor = os.open(self.path, flags)
        except OSError as error:
            raise PresentationSlotError(
                "slot_parent_pin_failed"
            ) from error

    def verify(self) -> None:
        try:
            named = self.path.lstat()
            if (
                self.path.is_symlink()
                or getattr(
                    named,
                    "st_file_attributes",
                    0,
                ) & _REPARSE_POINT
                or not stat.S_ISDIR(named.st_mode)
                or (named.st_dev, named.st_ino) != self.identity
            ):
                raise ValueError("slot_parent_identity_changed")
            if self._handle is not None:
                opened = _windows_handle_information(self._handle)
                if (
                    not opened.attributes & 0x10
                    or opened.attributes & _REPARSE_POINT
                    or _windows_file_id(opened) != named.st_ino
                ):
                    raise ValueError("slot_parent_handle_changed")
            elif self._descriptor is not None:
                opened = os.fstat(self._descriptor)
                if (
                    not stat.S_ISDIR(opened.st_mode)
                    or (opened.st_dev, opened.st_ino)
                    != self.identity
                ):
                    raise ValueError("slot_parent_handle_changed")
        except (OSError, ValueError) as error:
            raise PresentationSlotError("slot_parent_changed") from error

    def close(self) -> None:
        if self._handle is not None:
            handle = self._handle
            self._handle = None
            close_handle = ctypes.WinDLL(
                "kernel32",
                use_last_error=True,
            ).CloseHandle
            close_handle.argtypes = [ctypes.c_void_p]
            close_handle.restype = ctypes.c_int
            close_handle(handle)
        if self._descriptor is not None:
            descriptor = self._descriptor
            self._descriptor = None
            os.close(descriptor)

    def __enter__(self) -> "_PinnedDirectory":
        return self

    def __exit__(self, *_args) -> None:
        self.close()


class _ExclusiveSlotLock:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._handle = None
        self._descriptor = None
        if os.name == "nt":
            self._acquire_windows()
        else:
            self._acquire_portable()

    def _acquire_windows(self) -> None:
        create_file = ctypes.WinDLL(
            "kernel32",
            use_last_error=True,
        ).CreateFileW
        create_file.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
        ]
        create_file.restype = ctypes.c_void_p
        handle = create_file(
            str(self.path),
            0xC0000000,
            0,
            None,
            4,
            0x00200000,
            None,
        )
        if handle == ctypes.c_void_p(-1).value:
            error_code = ctypes.get_last_error()
            if error_code in (32, 33):
                raise PresentationSlotError("slot_busy")
            raise PresentationSlotError("slot_lock_failed") from (
                ctypes.WinError(error_code)
            )
        self._handle = handle
        try:
            self._validate_named_lock()
        except BaseException:
            self.close()
            raise

    def _acquire_portable(self) -> None:
        import fcntl

        flags = os.O_RDWR | os.O_CREAT
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.path, flags, 0o600)
        except OSError as error:
            raise PresentationSlotError("slot_lock_failed") from error
        self._descriptor = descriptor
        try:
            fcntl.flock(
                descriptor,
                fcntl.LOCK_EX | fcntl.LOCK_NB,
            )
        except BlockingIOError as error:
            self.close()
            raise PresentationSlotError("slot_busy") from error
        except OSError as error:
            self.close()
            raise PresentationSlotError("slot_lock_failed") from error
        try:
            self._validate_named_lock()
        except BaseException:
            self.close()
            raise

    def _validate_named_lock(self) -> None:
        try:
            information = self.path.lstat()
            if (
                self.path.is_symlink()
                or getattr(
                    information,
                    "st_file_attributes",
                    0,
                ) & _REPARSE_POINT
                or not stat.S_ISREG(information.st_mode)
                or information.st_nlink != 1
            ):
                raise ValueError("slot_lock_not_ordinary")
            if self._handle is not None:
                opened = _windows_handle_information(self._handle)
                if (
                    opened.attributes & (0x10 | _REPARSE_POINT)
                    or opened.link_count != 1
                    or _windows_file_id(opened) != information.st_ino
                ):
                    raise ValueError("slot_lock_handle_changed")
            elif self._descriptor is not None:
                opened = os.fstat(self._descriptor)
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or opened.st_nlink != 1
                    or (opened.st_dev, opened.st_ino)
                    != (information.st_dev, information.st_ino)
                ):
                    raise ValueError("slot_lock_handle_changed")
        except (OSError, ValueError) as error:
            raise PresentationSlotError("slot_lock_invalid") from error

    def close(self) -> None:
        if self._handle is not None:
            handle = self._handle
            self._handle = None
            close_handle = ctypes.WinDLL(
                "kernel32",
                use_last_error=True,
            ).CloseHandle
            close_handle.argtypes = [ctypes.c_void_p]
            close_handle.restype = ctypes.c_int
            close_handle(handle)
        if self._descriptor is not None:
            descriptor = self._descriptor
            self._descriptor = None
            os.close(descriptor)

    def __enter__(self) -> "_ExclusiveSlotLock":
        return self

    def __exit__(self, *_args) -> None:
        self.close()


@dataclass(frozen=True, slots=True)
class PresentationSlotFile:
    relative_path: str
    kind: str
    size: int
    sha256: str
    volume_serial: int
    file_id: int


@dataclass(frozen=True, slots=True)
class PresentationSlotManifest:
    schema_version: int
    slot_name: str
    generation_id: str
    source_account_name: str
    media_store_manifest_sha256: str
    files: tuple[PresentationSlotFile, ...]
    file_count: int
    byte_count: int
    bytes_written: int


@dataclass(frozen=True, slots=True)
class PresentationSlotReceipt:
    schema_version: int
    slot_name: str
    generation_id: str
    slot_root: Path
    presentation_root: Path
    manifest_path: Path
    ready_path: Path
    manifest_sha256: str
    media_store_manifest_sha256: str
    manifest: PresentationSlotManifest
    file_count: int
    byte_count: int
    bytes_written: int

    @property
    def presentation_manifest_sha256(self) -> str:
        return self.manifest_sha256


@dataclass(frozen=True, slots=True)
class _FileSnapshot:
    size: int
    sha256: str
    volume_serial: int
    file_id: int
    link_count: int


def _sha256_file_descriptor(descriptor: int) -> str:
    digest = sha256()
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
    return digest.hexdigest().upper()


def _ordinary_file_snapshot(path: Path) -> _FileSnapshot:
    descriptor = None
    try:
        before = path.lstat()
        if (
            path.is_symlink()
            or getattr(before, "st_file_attributes", 0) & _REPARSE_POINT
            or not stat.S_ISREG(before.st_mode)
        ):
            raise PresentationSlotError("slot_file_not_ordinary")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOINHERIT", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (
                opened.st_dev,
                opened.st_ino,
                opened.st_size,
                opened.st_nlink,
            )
            != (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_nlink,
            )
        ):
            raise PresentationSlotError("slot_file_changed")
        digest = _sha256_file_descriptor(descriptor)
        after = os.fstat(descriptor)
        named = path.lstat()
        if (
            path.is_symlink()
            or getattr(named, "st_file_attributes", 0) & _REPARSE_POINT
            or not stat.S_ISREG(named.st_mode)
            or (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_nlink,
            )
            != (
                opened.st_dev,
                opened.st_ino,
                opened.st_size,
                opened.st_nlink,
            )
            or (
                named.st_dev,
                named.st_ino,
                named.st_size,
                named.st_nlink,
            )
            != (
                opened.st_dev,
                opened.st_ino,
                opened.st_size,
                opened.st_nlink,
            )
        ):
            raise PresentationSlotError("slot_file_changed")
        return _FileSnapshot(
            size=opened.st_size,
            sha256=digest,
            volume_serial=opened.st_dev,
            file_id=opened.st_ino,
            link_count=opened.st_nlink,
        )
    except PresentationSlotError:
        raise
    except OSError as error:
        raise PresentationSlotError("slot_file_invalid") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _matches_expected(
        snapshot: _FileSnapshot,
        *,
        size: int,
        expected_sha256: str,
) -> bool:
    return (
        snapshot.size == size
        and snapshot.sha256 == expected_sha256
    )


def _exclusive_create_file_descriptor(path: Path) -> int:
    if os.name == "nt":
        import msvcrt

        create_file = ctypes.WinDLL(
            "kernel32",
            use_last_error=True,
        ).CreateFileW
        create_file.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
        ]
        create_file.restype = ctypes.c_void_p
        handle = create_file(
            str(path),
            0xC0000000,
            0,
            None,
            1,
            0x80200080,
            None,
        )
        if handle == ctypes.c_void_p(-1).value:
            error_code = ctypes.get_last_error()
            if error_code in (80, 183):
                raise FileExistsError(
                    error_code,
                    "exclusive_temp_exists",
                    str(path),
                )
            raise ctypes.WinError(error_code)
        try:
            return msvcrt.open_osfhandle(
                handle,
                os.O_RDWR
                | getattr(os, "O_BINARY", 0)
                | getattr(os, "O_NOINHERIT", 0),
            )
        except BaseException:
            close_handle = ctypes.WinDLL(
                "kernel32",
                use_last_error=True,
            ).CloseHandle
            close_handle.argtypes = [ctypes.c_void_p]
            close_handle.restype = ctypes.c_int
            close_handle(handle)
            raise

    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    return os.open(path, flags, 0o600)


def _copy_source_to_exclusive_temp(
        source: Path,
        temporary: Path,
        *,
        expected_source: _FileSnapshot,
) -> _FileSnapshot:
    source_descriptor = None
    temporary_descriptor = None
    try:
        temporary_descriptor = _exclusive_create_file_descriptor(
            temporary
        )
        created = os.fstat(temporary_descriptor)
        named = temporary.lstat()
        if (
            temporary.is_symlink()
            or getattr(
                named,
                "st_file_attributes",
                0,
            ) & _REPARSE_POINT
            or not stat.S_ISREG(created.st_mode)
            or not stat.S_ISREG(named.st_mode)
            or created.st_nlink != 1
            or (
                created.st_dev,
                created.st_ino,
                created.st_size,
                created.st_nlink,
            )
            != (
                named.st_dev,
                named.st_ino,
                named.st_size,
                named.st_nlink,
            )
        ):
            raise PresentationSlotError("slot_copy_mismatch")

        source_flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        source_flags |= getattr(os, "O_NOINHERIT", 0)
        source_flags |= getattr(os, "O_NOFOLLOW", 0)
        source_descriptor = os.open(source, source_flags)
        opened_source = os.fstat(source_descriptor)
        if (
            not stat.S_ISREG(opened_source.st_mode)
            or (
                opened_source.st_dev,
                opened_source.st_ino,
                opened_source.st_size,
                opened_source.st_nlink,
            )
            != (
                expected_source.volume_serial,
                expected_source.file_id,
                expected_source.size,
                expected_source.link_count,
            )
        ):
            raise PresentationSlotError("slot_source_mismatch")

        while True:
            chunk = os.read(source_descriptor, 1024 * 1024)
            if not chunk:
                break
            pending = memoryview(chunk)
            while pending:
                written = os.write(temporary_descriptor, pending)
                if written <= 0:
                    raise OSError("slot_temp_write_failed")
                pending = pending[written:]
        os.fsync(temporary_descriptor)

        source_after = os.fstat(source_descriptor)
        if (
            source_after.st_dev,
            source_after.st_ino,
            source_after.st_size,
            source_after.st_nlink,
        ) != (
            opened_source.st_dev,
            opened_source.st_ino,
            opened_source.st_size,
            opened_source.st_nlink,
        ):
            raise PresentationSlotError("slot_source_mismatch")

        os.lseek(temporary_descriptor, 0, os.SEEK_SET)
        digest = _sha256_file_descriptor(temporary_descriptor)
        copied = os.fstat(temporary_descriptor)
        named = temporary.lstat()
        if (
            temporary.is_symlink()
            or getattr(
                named,
                "st_file_attributes",
                0,
            ) & _REPARSE_POINT
            or not stat.S_ISREG(copied.st_mode)
            or not stat.S_ISREG(named.st_mode)
            or copied.st_nlink != 1
            or (
                copied.st_dev,
                copied.st_ino,
                copied.st_size,
                copied.st_nlink,
            )
            != (
                created.st_dev,
                created.st_ino,
                copied.st_size,
                1,
            )
            or (
                named.st_dev,
                named.st_ino,
                named.st_size,
                named.st_nlink,
            )
            != (
                copied.st_dev,
                copied.st_ino,
                copied.st_size,
                copied.st_nlink,
            )
        ):
            raise PresentationSlotError("slot_copy_mismatch")
        return _FileSnapshot(
            size=copied.st_size,
            sha256=digest,
            volume_serial=copied.st_dev,
            file_id=copied.st_ino,
            link_count=copied.st_nlink,
        )
    finally:
        if source_descriptor is not None:
            os.close(source_descriptor)
        if temporary_descriptor is not None:
            os.close(temporary_descriptor)


def _rollback_failed_publication(
        destination: Path,
        *,
        destination_root: Path,
        pinned_parent: _PinnedDirectory,
        observed_publication: _FileSnapshot,
        source: Path,
        expected_source: _FileSnapshot,
) -> None:
    try:
        _assert_slot_destination(destination, destination_root)
        pinned_parent.verify()
        current = _ordinary_file_snapshot(destination)
        if current != observed_publication:
            raise ValueError(
                "slot_failed_publication_identity_changed"
            )
        destination.unlink()
        pinned_parent.verify()
        if os.path.lexists(destination):
            raise ValueError(
                "slot_failed_publication_still_present"
            )
        restored_source = _ordinary_file_snapshot(source)
        if restored_source != expected_source:
            raise ValueError("slot_source_not_restored")
    except (
        OSError,
        PathBoundaryError,
        PresentationSlotError,
        ValueError,
    ) as error:
        raise PresentationSlotError(
            "slot_publication_rollback_failed"
        ) from error


def _copy_and_replace(
        source: Path,
        destination: Path,
        *,
        destination_root: Path,
        expected_size: int,
        expected_sha256: str,
        expected_source_identity: tuple[int, int] | None = None,
) -> _FileSnapshot:
    _assert_slot_destination(destination, destination_root)
    before = _ordinary_file_snapshot(source)
    if (
        not _matches_expected(
            before,
            size=expected_size,
            expected_sha256=expected_sha256,
        )
        or (
            expected_source_identity is not None
            and (
                before.volume_serial,
                before.file_id,
            ) != expected_source_identity
        )
    ):
        raise PresentationSlotError("slot_source_mismatch")
    temporary = destination.with_name(
        f".{destination.name}.{uuid.uuid4().hex}.partial"
    )
    with _PinnedDirectory(destination.parent) as pinned_parent:
        try:
            _assert_slot_destination(destination, destination_root)
            pinned_parent.verify()
            bound_copy = _copy_source_to_exclusive_temp(
                source,
                temporary,
                expected_source=before,
            )
            pinned_parent.verify()
            copied = _ordinary_file_snapshot(temporary)
            after = _ordinary_file_snapshot(source)
            if (
                after != before
                or copied != bound_copy
                or not _matches_expected(
                    copied,
                    size=expected_size,
                    expected_sha256=expected_sha256,
                )
                or copied.link_count != 1
                or (
                    copied.volume_serial,
                    copied.file_id,
                ) == (
                    before.volume_serial,
                    before.file_id,
                )
            ):
                raise PresentationSlotError("slot_copy_mismatch")
            _assert_slot_destination(destination, destination_root)
            pinned_parent.verify()
            replace_write_through(temporary, destination)
            pinned_parent.verify()
            published = _ordinary_file_snapshot(destination)
            final_source = _ordinary_file_snapshot(source)
            if (
                final_source != before
                or published != copied
                or published.link_count != 1
                or (
                    published.volume_serial,
                    published.file_id,
                ) == (
                    final_source.volume_serial,
                    final_source.file_id,
                )
            ):
                _rollback_failed_publication(
                    destination,
                    destination_root=destination_root,
                    pinned_parent=pinned_parent,
                    observed_publication=published,
                    source=source,
                    expected_source=before,
                )
                raise PresentationSlotError(
                    "slot_publication_mismatch"
                )
            return published
        except PresentationSlotError:
            raise
        except OSError as error:
            raise PresentationSlotError("slot_copy_failed") from error
        finally:
            if os.path.lexists(temporary):
                try:
                    pinned_parent.verify()
                    temporary.unlink()
                    pinned_parent.verify()
                except OSError:
                    pass


def _reuse_or_copy_media(
        source: Path,
        destination: Path,
        *,
        destination_root: Path,
        expected_size: int,
        expected_sha256: str,
        expected_source_identity: tuple[int, int],
        forbidden_source_identities: frozenset[tuple[int, int]],
) -> tuple[_FileSnapshot, int]:
    _assert_slot_destination(destination, destination_root)
    before = _ordinary_file_snapshot(source)
    if (
        not _matches_expected(
            before,
            size=expected_size,
            expected_sha256=expected_sha256,
        )
        or (
            before.volume_serial,
            before.file_id,
        ) != expected_source_identity
    ):
        raise PresentationSlotError("slot_source_mismatch")
    if os.path.lexists(destination):
        published = _ordinary_file_snapshot(destination)
        if (
            published.volume_serial,
            published.file_id,
        ) in forbidden_source_identities:
            raise PresentationSlotError(
                "slot_media_source_hardlink"
            )
        after = _ordinary_file_snapshot(source)
        if after != before:
            raise PresentationSlotError("media_store_changed")
        if (
            _matches_expected(
                published,
                size=expected_size,
                expected_sha256=expected_sha256,
            )
            and published.link_count == 1
            and (
                published.volume_serial,
                published.file_id,
            ) != (
                before.volume_serial,
                before.file_id,
            )
        ):
            return published, 0
    published = _copy_and_replace(
        source,
        destination,
        destination_root=destination_root,
        expected_size=expected_size,
        expected_sha256=expected_sha256,
        expected_source_identity=expected_source_identity,
    )
    return published, expected_size


def _manifest_value(
        manifest: PresentationSlotManifest,
) -> dict[str, object]:
    return {
        "schemaVersion": manifest.schema_version,
        "slotName": manifest.slot_name,
        "generationId": manifest.generation_id,
        "sourceAccountName": manifest.source_account_name,
        "mediaStoreManifestSha256": (
            manifest.media_store_manifest_sha256
        ),
        "fileCount": manifest.file_count,
        "byteCount": manifest.byte_count,
        "bytesWritten": manifest.bytes_written,
        "files": [
            {
                "relativePath": item.relative_path,
                "kind": item.kind,
                "size": item.size,
                "sha256": item.sha256,
                "volumeSerial": item.volume_serial,
                "fileId": item.file_id,
            }
            for item in manifest.files
        ],
    }


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _ready_value(
        manifest: PresentationSlotManifest,
        manifest_sha256: str,
) -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "slotName": manifest.slot_name,
        "generationId": manifest.generation_id,
        "sourceAccountName": manifest.source_account_name,
        "presentationManifestSha256": manifest_sha256,
        "mediaStoreManifestSha256": (
            manifest.media_store_manifest_sha256
        ),
        "fileCount": manifest.file_count,
        "byteCount": manifest.byte_count,
        "bytesWritten": manifest.bytes_written,
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


def _strict_media_receipt(
        receipt: MediaStoreReceipt,
        *,
        account_name: str,
) -> MediaStoreReceipt:
    if type(receipt) is not MediaStoreReceipt:
        raise PresentationSlotError("media_store_receipt_invalid")
    try:
        manifest_path = canonical_existing(receipt.manifest_path)
        reread = read_media_store_receipt(
            manifest_path.parent,
            account_name,
        )
    except (MediaImportError, OSError, PathBoundaryError, ValueError) as error:
        raise PresentationSlotError(
            "media_store_receipt_invalid"
        ) from error
    if (
        reread is None
        or reread.schema_version != receipt.schema_version
        or reread.manifest_path != manifest_path
        or reread.manifest_sha256 != receipt.manifest_sha256
        or reread.manifest != receipt.manifest
        or reread.file_count != receipt.file_count
        or reread.byte_count != receipt.byte_count
    ):
        raise PresentationSlotError("media_store_receipt_invalid")
    return reread


def _expected_tree(
        files: tuple[PresentationSlotFile, ...],
        *,
        account_name: str,
) -> tuple[set[str], set[str]]:
    expected_files = {item.relative_path for item in files}
    expected_directories = {
        account_name,
        f"{account_name}/db_storage",
        f"{account_name}/msg",
        f"{account_name}/msg/attach",
        f"{account_name}/msg/video",
    }
    for relative_text in expected_files:
        parent = PurePosixPath(relative_text).parent
        while parent != PurePosixPath("."):
            expected_directories.add(parent.as_posix())
            parent = parent.parent
    return expected_directories, expected_files


def _scan_presentation(
        presentation_root: Path,
) -> tuple[set[str], set[str]]:
    root = canonical_existing(presentation_root)
    directories = set()
    files = set()
    pending = [root]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as opened:
            entries = list(opened)
        if len({item.name.casefold() for item in entries}) != len(entries):
            raise PresentationSlotError("slot_name_collision")
        for entry in entries:
            try:
                kind = validate_scandir_entry(entry)
                path = Path(entry.path)
                assert_descendant(path, root)
            except (OSError, PathBoundaryError, ValueError) as error:
                raise PresentationSlotError("slot_tree_invalid") from error
            relative = path.relative_to(root).as_posix()
            if kind == "directory":
                directories.add(relative)
                pending.append(path)
            else:
                files.add(relative)
    return directories, files


def _reconcile_presentation(
        presentation_root: Path,
        *,
        expected_directories: set[str],
        expected_files: set[str],
) -> None:
    try:
        root = canonical_existing(presentation_root)
        directories, files = _scan_presentation(root)
        for relative_text in sorted(files - expected_files):
            path = root.joinpath(
                *PurePosixPath(relative_text).parts
            )
            with _PinnedDirectory(path.parent) as pinned_parent:
                _assert_slot_destination(path, root)
                pinned_parent.verify()
                information = path.lstat()
                if (
                    path.is_symlink()
                    or getattr(
                        information,
                        "st_file_attributes",
                        0,
                    ) & _REPARSE_POINT
                    or not stat.S_ISREG(information.st_mode)
                ):
                    raise ValueError("slot_stale_file_invalid")
                path.unlink()
                pinned_parent.verify()
                if os.path.lexists(path):
                    raise ValueError(
                        "slot_stale_file_removal_failed"
                    )

        stale_directories = sorted(
            directories - expected_directories,
            key=lambda value: (value.count("/"), value),
            reverse=True,
        )
        for relative_text in stale_directories:
            path = root.joinpath(
                *PurePosixPath(relative_text).parts
            )
            with _PinnedDirectory(path.parent) as pinned_parent:
                _assert_slot_destination(path, root)
                pinned_parent.verify()
                information = path.lstat()
                if (
                    path.is_symlink()
                    or getattr(
                        information,
                        "st_file_attributes",
                        0,
                    ) & _REPARSE_POINT
                    or not stat.S_ISDIR(information.st_mode)
                ):
                    raise ValueError(
                        "slot_stale_directory_invalid"
                    )
                with os.scandir(path) as opened:
                    if next(opened, None) is not None:
                        raise ValueError(
                            "slot_stale_directory_not_empty"
                        )
                path.rmdir()
                pinned_parent.verify()
                if os.path.lexists(path):
                    raise ValueError(
                        "slot_stale_directory_removal_failed"
                    )

        remaining_directories, remaining_files = _scan_presentation(
            root
        )
        if (
            not remaining_directories.issubset(expected_directories)
            or not remaining_files.issubset(expected_files)
        ):
            raise ValueError("slot_reconciliation_incomplete")
    except PresentationSlotError:
        raise
    except (OSError, PathBoundaryError, ValueError) as error:
        raise PresentationSlotError("slot_tree_invalid") from error


def _strict_rescan(
        presentation_root: Path,
        files: tuple[PresentationSlotFile, ...],
        *,
        account_name: str,
) -> tuple[PresentationSlotFile, ...]:
    expected_directories, expected_files = _expected_tree(
        files,
        account_name=account_name,
    )
    directories, actual_files = _scan_presentation(presentation_root)
    if (
        directories != expected_directories
        or actual_files != expected_files
    ):
        raise PresentationSlotError("slot_tree_mismatch")
    rescanned = []
    for item in files:
        snapshot = _ordinary_file_snapshot(
            presentation_root.joinpath(
                *PurePosixPath(item.relative_path).parts
            )
        )
        if (
            not _matches_expected(
                snapshot,
                size=item.size,
                expected_sha256=item.sha256,
            )
            or snapshot.link_count != 1
            or snapshot.volume_serial != item.volume_serial
            or snapshot.file_id != item.file_id
        ):
            raise PresentationSlotError("slot_publication_mismatch")
        rescanned.append(item)
    return tuple(rescanned)


def _prepare_slot_root(
        slots_root: Path,
        *,
        slot_name: str,
) -> tuple[Path, Path, Path, Path]:
    try:
        slots_root = canonical_existing(Path(slots_root))
        if not slots_root.is_dir():
            raise ValueError("slots_root_not_directory")
        matches = [
            entry.name
            for entry in os.scandir(slots_root)
            if entry.name.casefold() == slot_name.casefold()
        ]
        if matches and matches != [slot_name]:
            raise ValueError("slot_name_collision")
        slot_root = canonical_future(slots_root / slot_name)
        assert_descendant(slot_root, slots_root)
        if not os.path.lexists(slot_root):
            slot_root.mkdir()
        slot_root = canonical_existing(slot_root)
        if not slot_root.is_dir():
            raise ValueError("slot_root_not_directory")
        assert_descendant(slot_root, slots_root)
        allowed = {
            _SLOT_LOCK_NAME,
            "presentation",
            "slot-manifest.json",
            "READY",
        }
        with os.scandir(slot_root) as opened:
            entries = list(opened)
        if len(
            {entry.name.casefold() for entry in entries}
        ) != len(entries):
            raise ValueError("slot_root_schema_invalid")
        owned_temps = [
            entry
            for entry in entries
            if _CONTROL_TEMP_RE.fullmatch(entry.name) is not None
        ]
        if any(
            entry.name not in allowed
            and entry not in owned_temps
            for entry in entries
        ):
            raise ValueError("slot_root_schema_invalid")
        for entry in owned_temps:
            path = Path(entry.path)
            information = path.lstat()
            if (
                path.is_symlink()
                or getattr(
                    information,
                    "st_file_attributes",
                    0,
                ) & _REPARSE_POINT
                or not stat.S_ISREG(information.st_mode)
                or information.st_nlink != 1
            ):
                raise ValueError("slot_control_temp_invalid")
        if owned_temps:
            with _PinnedDirectory(slot_root) as pinned_root:
                for entry in owned_temps:
                    pinned_root.verify()
                    Path(entry.path).unlink()
                    pinned_root.verify()
            with os.scandir(slot_root) as opened:
                remaining_names = {entry.name for entry in opened}
            if not remaining_names.issubset(allowed):
                raise ValueError("slot_control_temp_removal_failed")
        manifest_path = slot_root / "slot-manifest.json"
        ready_path = slot_root / "READY"
        for control_path in (
            slot_root / _SLOT_LOCK_NAME,
            manifest_path,
            ready_path,
        ):
            if not os.path.lexists(control_path):
                continue
            information = control_path.lstat()
            if (
                control_path.is_symlink()
                or getattr(
                    information,
                    "st_file_attributes",
                    0,
                ) & _REPARSE_POINT
                or not stat.S_ISREG(information.st_mode)
            ):
                raise ValueError("slot_control_file_invalid")
        _invalidate_ready(ready_path)
        presentation_root = slot_root / "presentation"
        if not os.path.lexists(presentation_root):
            with _PinnedDirectory(slot_root) as pinned_slot:
                pinned_slot.verify()
                presentation_root.mkdir()
                pinned_slot.verify()
        presentation_root = canonical_existing(presentation_root)
        if not presentation_root.is_dir():
            raise ValueError("presentation_root_not_directory")
        assert_descendant(presentation_root, slot_root)
        return (
            slot_root,
            presentation_root,
            manifest_path,
            ready_path,
        )
    except (
        OSError,
        PathBoundaryError,
        ValueError,
    ) as error:
        raise PresentationSlotError("slot_root_invalid") from error


def _invalidate_ready(ready_path: Path) -> None:
    if not os.path.lexists(ready_path):
        return
    with _PinnedDirectory(ready_path.parent) as pinned_parent:
        snapshot = ready_path.lstat()
        if (
            ready_path.is_symlink()
            or getattr(
                snapshot,
                "st_file_attributes",
                0,
            ) & _REPARSE_POINT
            or not stat.S_ISREG(snapshot.st_mode)
        ):
            raise PresentationSlotError("slot_ready_invalid")
        try:
            pinned_parent.verify()
            ready_path.unlink()
            pinned_parent.verify()
        except OSError as error:
            raise PresentationSlotError(
                "slot_ready_invalidation_failed"
            ) from error
        if os.path.lexists(ready_path):
            raise PresentationSlotError(
                "slot_ready_invalidation_failed"
            )


def _directory_identity(path: Path) -> tuple[int, int]:
    with _PinnedDirectory(path) as pinned:
        return pinned.identity


def _atomic_write_control(
        path: Path,
        payload: bytes,
        *,
        expected_parent_identity: tuple[int, int],
) -> None:
    with _PinnedDirectory(
        path.parent,
        expected_identity=expected_parent_identity,
    ) as pinned_parent:
        if pinned_parent.path != path.parent:
            raise PresentationSlotError("slot_parent_changed")
        pinned_parent.verify()
        atomic_write_bytes(path, payload)
        pinned_parent.verify()


def _read_control(
        path: Path,
        *,
        expected_parent_identity: tuple[int, int],
) -> bytes:
    with _PinnedDirectory(
        path.parent,
        expected_identity=expected_parent_identity,
    ) as pinned_parent:
        if pinned_parent.path != path.parent:
            raise PresentationSlotError("slot_parent_changed")
        pinned_parent.verify()
        payload = path.read_bytes()
        pinned_parent.verify()
        return payload


def _ensure_directories(
        presentation_root: Path,
        relative_directories: set[str],
) -> None:
    try:
        root = canonical_existing(presentation_root)
        for relative_text in sorted(
            relative_directories,
            key=lambda value: (value.count("/"), value),
        ):
            path = root.joinpath(
                *PurePosixPath(relative_text).parts
            )
            assert_descendant(path, root)
            if not os.path.lexists(path):
                with _PinnedDirectory(
                    path.parent
                ) as pinned_parent:
                    pinned_parent.verify()
                    path.mkdir()
                    pinned_parent.verify()
            if (
                canonical_existing(path) != path
                or not path.is_dir()
            ):
                raise ValueError("slot_directory_invalid")
    except (OSError, PathBoundaryError, ValueError) as error:
        raise PresentationSlotError("slot_tree_invalid") from error


def _assert_slot_destination(
        destination: Path,
        presentation_root: Path,
) -> None:
    try:
        root = canonical_existing(presentation_root)
        parent = canonical_existing(destination.parent)
        assert_descendant(destination, root)
        if parent != destination.parent:
            raise ValueError("slot_destination_parent_invalid")
    except (OSError, PathBoundaryError, ValueError) as error:
        raise PresentationSlotError(
            "slot_destination_invalid"
        ) from error


def _paths_overlap(left: Path, right: Path) -> bool:
    left_value = os.path.normcase(str(left))
    right_value = os.path.normcase(str(right))
    try:
        common = os.path.commonpath((left_value, right_value))
    except ValueError:
        return False
    return common in (left_value, right_value)


def _validated_separate_slots_root(
        slots_root: Path,
        *,
        slot_name: str,
        active_root: Path,
        media_store_root: Path,
) -> Path:
    try:
        root = canonical_existing(Path(slots_root))
        prospective_slot = canonical_future(root / slot_name)
        assert_descendant(prospective_slot, root)
    except (OSError, PathBoundaryError, ValueError) as error:
        raise PresentationSlotError("slot_root_invalid") from error
    if any(
        _paths_overlap(candidate, source_root)
        for candidate in (root, prospective_slot)
        for source_root in (active_root, media_store_root)
    ):
        raise PresentationSlotError("slot_source_overlap")
    return root


def _open_exclusive_slot_lock(
        slots_root: Path,
        *,
        slot_name: str,
) -> _ExclusiveSlotLock:
    lock = None
    try:
        with _PinnedDirectory(slots_root) as pinned_slots:
            slot_root = canonical_future(slots_root / slot_name)
            assert_descendant(slot_root, slots_root)
            if not os.path.lexists(slot_root):
                try:
                    pinned_slots.verify()
                    slot_root.mkdir()
                    pinned_slots.verify()
                except FileExistsError:
                    pass
            slot_root = canonical_existing(slot_root)
            if not slot_root.is_dir():
                raise ValueError("slot_root_not_directory")
            assert_descendant(slot_root, slots_root)
            with _PinnedDirectory(slot_root) as pinned_slot:
                lock = _ExclusiveSlotLock(
                    slot_root / _SLOT_LOCK_NAME
                )
                pinned_slot.verify()
            pinned_slots.verify()
    except PresentationSlotError:
        if lock is not None:
            lock.close()
        raise
    except (OSError, PathBoundaryError, ValueError) as error:
        if lock is not None:
            lock.close()
        raise PresentationSlotError("slot_root_invalid") from error
    return lock


def _rebuild_validated_slot(
        active_root: Path,
        active_before: FileSetManifest,
        media: MediaStoreReceipt,
        slots_root: Path,
        slot_name: str,
        account_name: str,
        generation_id: str,
) -> PresentationSlotReceipt:
    (
        slot_root,
        presentation_root,
        manifest_path,
        ready_path,
    ) = _prepare_slot_root(
        slots_root,
        slot_name=slot_name,
    )
    slot_root_identity = _directory_identity(slot_root)

    database_files = tuple(active_before.files)
    media_files = tuple(media.manifest.files)
    prospective = tuple(
        PresentationSlotFile(
            relative_path=item.relative_path,
            kind="database",
            size=item.size,
            sha256=item.sha256,
            volume_serial=0,
            file_id=0,
        )
        for item in database_files
    ) + tuple(
        PresentationSlotFile(
            relative_path=PurePosixPath(
                account_name,
                *PurePosixPath(item.relative_path).parts,
            ).as_posix(),
            kind="media",
            size=item.size,
            sha256=item.sha256,
            volume_serial=0,
            file_id=0,
        )
        for item in media_files
    )
    expected_directories, expected_files = _expected_tree(
        prospective,
        account_name=account_name,
    )
    try:
        _reconcile_presentation(
            presentation_root,
            expected_directories=expected_directories,
            expected_files=expected_files,
        )
        _ensure_directories(
            presentation_root,
            expected_directories,
        )
        entries = []
        for item in database_files:
            destination = presentation_root.joinpath(
                *PurePosixPath(item.relative_path).parts
            )
            published = _copy_and_replace(
                active_root.joinpath(
                    *PurePosixPath(item.relative_path).parts
                ),
                destination,
                destination_root=presentation_root,
                expected_size=item.size,
                expected_sha256=item.sha256,
            )
            entries.append(PresentationSlotFile(
                relative_path=item.relative_path,
                kind="database",
                size=item.size,
                sha256=item.sha256,
                volume_serial=published.volume_serial,
                file_id=published.file_id,
            ))

        store_account = media.manifest_path.parent / account_name
        media_source_identities = frozenset(
            (item.volume_serial, item.file_id)
            for item in media_files
        )
        bytes_written = 0
        for item in media_files:
            presentation_relative = PurePosixPath(
                account_name,
                *PurePosixPath(item.relative_path).parts,
            ).as_posix()
            destination = presentation_root.joinpath(
                *PurePosixPath(presentation_relative).parts
            )
            published, written = _reuse_or_copy_media(
                store_account.joinpath(
                    *PurePosixPath(item.relative_path).parts
                ),
                destination,
                destination_root=presentation_root,
                expected_size=item.size,
                expected_sha256=item.sha256,
                expected_source_identity=(
                    item.volume_serial,
                    item.file_id,
                ),
                forbidden_source_identities=(
                    media_source_identities
                ),
            )
            bytes_written += written
            entries.append(PresentationSlotFile(
                relative_path=presentation_relative,
                kind="media",
                size=item.size,
                sha256=item.sha256,
                volume_serial=published.volume_serial,
                file_id=published.file_id,
            ))

        active_after = build_manifest(
            active_root,
            role=CopyRole.ACTIVE,
        )
        if (
            content_signature(active_after)
            != content_signature(active_before)
        ):
            raise PresentationSlotError("slot_active_changed")
        reread_media = _strict_media_receipt(
            media,
            account_name=account_name,
        )
        if reread_media.manifest_sha256 != media.manifest_sha256:
            raise PresentationSlotError("media_store_changed")

        entries.sort(key=lambda item: item.relative_path)
        stable_entries = _strict_rescan(
            presentation_root,
            tuple(entries),
            account_name=account_name,
        )
        manifest = PresentationSlotManifest(
            schema_version=1,
            slot_name=slot_name,
            generation_id=generation_id,
            source_account_name=account_name,
            media_store_manifest_sha256=media.manifest_sha256,
            files=stable_entries,
            file_count=len(stable_entries),
            byte_count=sum(item.size for item in stable_entries),
            bytes_written=bytes_written,
        )
        manifest_bytes = _canonical_json(_manifest_value(manifest))
        manifest_sha256 = sha256(manifest_bytes).hexdigest().upper()
        _atomic_write_control(
            manifest_path,
            manifest_bytes,
            expected_parent_identity=slot_root_identity,
        )
        if _read_control(
            manifest_path,
            expected_parent_identity=slot_root_identity,
        ) != manifest_bytes:
            raise PresentationSlotError("slot_manifest_reread_mismatch")
        ready_bytes = _canonical_json(
            _ready_value(manifest, manifest_sha256)
        )
        _strict_rescan(
            presentation_root,
            stable_entries,
            account_name=account_name,
        )
        if _read_control(
            manifest_path,
            expected_parent_identity=slot_root_identity,
        ) != manifest_bytes:
            raise PresentationSlotError("slot_manifest_reread_mismatch")
        receipt = PresentationSlotReceipt(
            schema_version=1,
            slot_name=slot_name,
            generation_id=generation_id,
            slot_root=slot_root,
            presentation_root=presentation_root,
            manifest_path=manifest_path,
            ready_path=ready_path,
            manifest_sha256=manifest_sha256,
            media_store_manifest_sha256=(
                media.manifest_sha256
            ),
            manifest=manifest,
            file_count=manifest.file_count,
            byte_count=manifest.byte_count,
            bytes_written=manifest.bytes_written,
        )
        _atomic_write_control(
            ready_path,
            ready_bytes,
            expected_parent_identity=slot_root_identity,
        )
        return receipt
    except BaseException as error:
        if os.path.lexists(ready_path):
            try:
                _invalidate_ready(ready_path)
            except PresentationSlotError as cleanup_error:
                raise cleanup_error from error
        raise


def rebuild_inactive_slot(
        active_root: Path,
        media_receipt: MediaStoreReceipt,
        slots_root: Path,
        slot_name: str,
        account_name: str,
        generation_id: str,
) -> PresentationSlotReceipt:
    if (
        type(slot_name) is not str
        or slot_name not in _SLOT_NAMES
        or type(account_name) is not str
        or _ACCOUNT_RE.fullmatch(account_name) is None
        or type(generation_id) is not str
        or _GENERATION_RE.fullmatch(generation_id) is None
    ):
        raise PresentationSlotError("slot_arguments_invalid")
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
    except (
        CopyVerificationError,
        OSError,
        PathBoundaryError,
        ValueError,
    ) as error:
        raise PresentationSlotError("slot_active_invalid") from error
    media = _strict_media_receipt(
        media_receipt,
        account_name=account_name,
    )
    slots_root = _validated_separate_slots_root(
        Path(slots_root),
        slot_name=slot_name,
        active_root=active_root,
        media_store_root=media.manifest_path.parent,
    )
    _require_slot_path_budget(
        slots_root=slots_root,
        slot_name=slot_name,
        account_name=account_name,
        active=active_before,
        media=media,
    )
    with _open_exclusive_slot_lock(
        slots_root,
        slot_name=slot_name,
    ):
        return _rebuild_validated_slot(
            active_root,
            active_before,
            media,
            slots_root,
            slot_name,
            account_name,
            generation_id,
        )

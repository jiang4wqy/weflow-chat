from __future__ import annotations

from contextlib import ExitStack
import ctypes
from ctypes import wintypes
from hashlib import sha256
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
from typing import Callable, Iterable
import uuid

from weflow_chat.paths import (
    RunLayout,
    assert_descendant,
    canonical_existing,
    canonical_future,
)
from weflow_chat.presentation import read_presentation_receipt
from weflow_chat.validator.contracts import (
    FingerprintSet,
    ValidationReceipt,
    ValidatorLayout,
)
from weflow_chat.validator.install_copy import (
    verify_copied_runtime_contract,
)
from weflow_chat.validator.processes import (
    _is_formal_weflow_running_for_test,
    formal_weflow_is_running,
)
from weflow_chat.validator.profile import (
    _PATH_KEYED_CACHE_FIELDS,
    ConfigCopyReceipt,
    build_envelope_profile,
)
from weflow_chat.validator.result import (
    ValidationResultError,
    _validate_avatar_aggregate,
    _validate_media_openability,
    read_validation_result,
)
from weflow_chat.validator.security import (
    _close_windows_handle,
    _pin_directory,
    ensure_private_directory,
)
from weflow_chat.weixin_trust import (
    STORED_ENVELOPE_REFRESH,
)


class ValidatorBlockedError(RuntimeError):
    pass


_DATA_OPERATIONS = {
    "avatar-aggregate",
    "media-openability",
    "validate-snapshot",
}
_OPERATIONS = {
    "avatar-aggregate",
    "media-openability",
    "smoke",
    "safe-envelope-roundtrip",
    "validate-snapshot",
}
_MAX_REQUEST_BYTES = 4096
_MAX_BOUND_PROFILE_BYTES = 4 * 1024 * 1024
_GENERIC_READ = 0x80000000
_FILE_SHARE_READ = 0x1
_OPEN_EXISTING = 3
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


def _valid_profile_changed_fields(value: object) -> bool:
    return (
        isinstance(value, tuple)
        and value[:2] == ("dbPath", "cachePath")
        and value[2:]
        == tuple(
            field
            for field in _PATH_KEYED_CACHE_FIELDS
            if field in value[2:]
        )
    )


def _canonical_uuid(value: object) -> bool:
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value
    except (ValueError, AttributeError, TypeError):
        return False


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(path))


def _same_identity(left, right) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _request_bytes_and_area(payload: dict) -> tuple[bytes, str]:
    if not isinstance(payload, dict):
        raise ValidatorBlockedError("request_schema_mismatch")
    operation = payload.get("operation")
    keys = (
        {"operation", "runId", "area"}
        if operation in _DATA_OPERATIONS
        else {"operation", "runId"}
    )
    if (
        set(payload) != keys
        or operation not in _OPERATIONS
        or not _canonical_uuid(payload.get("runId"))
    ):
        raise ValidatorBlockedError("request_schema_mismatch")
    area = payload.get("area", "validation")
    if area not in {"validation", "active", "presentation"} or (
        operation not in _DATA_OPERATIONS and area != "validation"
    ) or (
        operation == "media-openability" and area != "presentation"
    ):
        raise ValidatorBlockedError("request_schema_mismatch")
    encoded = json.dumps(
        payload, ensure_ascii=True, separators=(",", ":")
    ).encode("ascii")
    if len(encoded) > _MAX_REQUEST_BYTES:
        raise ValidatorBlockedError("request_schema_mismatch")
    return encoded, area


def _assert_exact_layout(
    layout: ValidatorLayout, request_payload: dict
) -> bytes:
    encoded, area = _request_bytes_and_area(request_payload)
    try:
        attempt_id = layout.attempt_root.name
    except AttributeError as error:
        raise ValidatorBlockedError("validator_layout_mismatch") from error
    if not _canonical_uuid(attempt_id):
        raise ValidatorBlockedError("validator_layout_mismatch")
    run_root = _absolute(layout.run_root)
    attempt = run_root / "validator" / area / attempt_id
    expected = {
        "run_root": run_root,
        "attempt_root": attempt,
        "runtime_exe": run_root / "runtime" / "WeFlow" / "WeFlow.exe",
        "request_path": attempt / "request" / "request.json",
        "result_path": attempt / "result" / "result.json",
        "user_data_dir": attempt / "profile",
        "documents_dir": attempt / "documents",
        "cache_dir": attempt / "cache",
    }
    if any(
        _absolute(getattr(layout, name)) != value
        for name, value in expected.items()
    ):
        raise ValidatorBlockedError("validator_layout_mismatch")
    return encoded


def _assert_no_reparse_chain(
    root: Path, target: Path, *, require_target: bool = False
) -> None:
    lexical_root = Path(os.path.abspath(root))
    lexical_target = Path(os.path.abspath(target))
    try:
        lexical_target.relative_to(lexical_root)
    except ValueError as error:
        raise ValidatorBlockedError("validator_path_rejected") from error
    cursor = Path(lexical_target.anchor)
    for part in lexical_target.parts[1:]:
        cursor = cursor / part
        if not os.path.lexists(cursor):
            continue
        info = cursor.lstat()
        if cursor.is_symlink() or (
            getattr(info, "st_file_attributes", 0)
            & stat.FILE_ATTRIBUTE_REPARSE_POINT
        ):
            raise ValidatorBlockedError("validator_reparse_rejected")
    if require_target and not os.path.lexists(lexical_target):
        raise ValidatorBlockedError("validator_path_missing")


def _run_scope(
    layout: RunLayout,
    run_id: str,
) -> tuple[str, str, int, int]:
    if not _canonical_uuid(run_id):
        raise ValidatorBlockedError(
            "validated_scope_mismatch"
        )
    root = _absolute(layout.root)
    try:
        _assert_no_reparse_chain(
            root, root, require_target=True
        )
        information = root.lstat()
    except (OSError, ValueError) as error:
        raise ValidatorBlockedError(
            "validated_scope_mismatch"
        ) from error
    if not stat.S_ISDIR(information.st_mode):
        raise ValidatorBlockedError(
            "validated_scope_mismatch"
        )
    return (
        run_id,
        str(root),
        information.st_dev,
        information.st_ino,
    )


def _ordinary_file_binding(
    path: Path,
) -> tuple[int, int, int, str]:
    descriptor = None
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or path.is_symlink()
            or (
                getattr(before, "st_file_attributes", 0)
                & stat.FILE_ATTRIBUTE_REPARSE_POINT
            )
            or before.st_size > _MAX_BOUND_PROFILE_BYTES
        ):
            raise ValidatorBlockedError(
                "avatar_data_binding_changed"
            )
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOINHERIT", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or not _same_identity(before, opened)
            or opened.st_size != before.st_size
        ):
            raise ValidatorBlockedError(
                "avatar_data_binding_changed"
            )
        remaining = opened.st_size
        digest = sha256()
        while remaining:
            chunk = os.read(
                descriptor,
                min(64 * 1024, remaining),
            )
            if not chunk:
                raise ValidatorBlockedError(
                    "avatar_data_binding_changed"
                )
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ValidatorBlockedError(
                "avatar_data_binding_changed"
            )
        after = os.fstat(descriptor)
        named = path.lstat()
        if (
            not stat.S_ISREG(named.st_mode)
            or not _same_identity(before, after)
            or not _same_identity(before, named)
            or after.st_size != before.st_size
            or named.st_size != before.st_size
        ):
            raise ValidatorBlockedError(
                "avatar_data_binding_changed"
            )
        return (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            digest.hexdigest().upper(),
        )
    except ValidatorBlockedError:
        raise
    except OSError as error:
        raise ValidatorBlockedError(
            "avatar_data_binding_changed"
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _ordinary_directory_binding(
    path: Path,
) -> tuple[int, int]:
    try:
        information = path.lstat()
    except OSError as error:
        raise ValidatorBlockedError(
            "avatar_data_binding_changed"
        ) from error
    if (
        path.is_symlink()
        or (
            getattr(information, "st_file_attributes", 0)
            & stat.FILE_ATTRIBUTE_REPARSE_POINT
        )
        or not stat.S_ISDIR(information.st_mode)
    ):
        raise ValidatorBlockedError(
            "avatar_data_binding_changed"
        )
    return information.st_dev, information.st_ino


def _formal_profile_binding(formal_config: Path) -> tuple[object, ...]:
    formal_local_state = formal_config.parent / "Local State"
    return (
        _ordinary_directory_binding(formal_config.parent),
        _ordinary_file_binding(formal_config),
        _ordinary_file_binding(formal_local_state),
    )


class _WindowsOrdinaryFilePin:
    def __init__(self, path: Path):
        self.path = path
        self.descriptor: int | None = None
        self.identity: tuple[int, int, int, int] | None = None

    def __enter__(self):
        import msvcrt

        before = self.path.lstat()
        if (
            self.path.is_symlink()
            or (
                getattr(before, "st_file_attributes", 0)
                & stat.FILE_ATTRIBUTE_REPARSE_POINT
            )
            or not stat.S_ISREG(before.st_mode)
        ):
            raise PermissionError(
                "validator_file_pin_failed"
            )
        kernel32 = ctypes.WinDLL(
            "kernel32", use_last_error=True
        )
        create_file = kernel32.CreateFileW
        create_file.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        ]
        create_file.restype = wintypes.HANDLE
        handle = create_file(
            str(self.path),
            _GENERIC_READ,
            _FILE_SHARE_READ,
            None,
            _OPEN_EXISTING,
            _FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
        if handle == _INVALID_HANDLE_VALUE:
            raise PermissionError(
                "validator_file_pin_failed"
            ) from ctypes.WinError(ctypes.get_last_error())
        try:
            self.descriptor = msvcrt.open_osfhandle(
                int(handle),
                os.O_RDONLY | getattr(os, "O_BINARY", 0),
            )
        except (OSError, ValueError) as error:
            _close_windows_handle(handle)
            raise PermissionError(
                "validator_file_pin_failed"
            ) from error
        try:
            opened = os.fstat(self.descriptor)
            named = self.path.lstat()
            self.identity = (
                opened.st_dev,
                opened.st_ino,
                opened.st_size,
                opened.st_nlink,
            )
            if (
                not stat.S_ISREG(opened.st_mode)
                or not stat.S_ISREG(named.st_mode)
                or self.path.is_symlink()
                or (
                    getattr(
                        named, "st_file_attributes", 0
                    )
                    & stat.FILE_ATTRIBUTE_REPARSE_POINT
                )
                or self.identity
                != (
                    before.st_dev,
                    before.st_ino,
                    before.st_size,
                    before.st_nlink,
                )
                or self.identity
                != (
                    named.st_dev,
                    named.st_ino,
                    named.st_size,
                    named.st_nlink,
                )
            ):
                raise PermissionError(
                    "validator_file_pin_failed"
                )
            return self
        except BaseException:
            os.close(self.descriptor)
            self.descriptor = None
            self.identity = None
            raise

    def verify(self) -> None:
        if self.descriptor is None or self.identity is None:
            raise PermissionError(
                "validator_file_pin_failed"
            )
        opened = os.fstat(self.descriptor)
        named = self.path.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or not stat.S_ISREG(named.st_mode)
            or self.path.is_symlink()
            or (
                getattr(named, "st_file_attributes", 0)
                & stat.FILE_ATTRIBUTE_REPARSE_POINT
            )
            or (
                opened.st_dev,
                opened.st_ino,
                opened.st_size,
                opened.st_nlink,
            )
            != self.identity
            or (
                named.st_dev,
                named.st_ino,
                named.st_size,
                named.st_nlink,
            )
            != self.identity
        ):
            raise PermissionError(
                "validator_file_identity_changed"
            )

    def __exit__(self, *_args: object) -> bool:
        if self.descriptor is not None:
            os.close(self.descriptor)
            self.descriptor = None
        return False


class _PortableOrdinaryFilePin:
    def __init__(self, path: Path):
        self.path = path
        self.descriptor: int | None = None
        self.identity: tuple[int, int, int, int] | None = None

    def __enter__(self):
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        self.descriptor = os.open(self.path, flags)
        opened = os.fstat(self.descriptor)
        self.identity = (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_nlink,
        )
        self.verify()
        return self

    def verify(self) -> None:
        if self.descriptor is None or self.identity is None:
            raise PermissionError(
                "validator_file_pin_failed"
            )
        opened = os.fstat(self.descriptor)
        named = self.path.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or not stat.S_ISREG(named.st_mode)
            or self.path.is_symlink()
            or (
                opened.st_dev,
                opened.st_ino,
                opened.st_size,
                opened.st_nlink,
            )
            != self.identity
            or (
                named.st_dev,
                named.st_ino,
                named.st_size,
                named.st_nlink,
            )
            != self.identity
        ):
            raise PermissionError(
                "validator_file_identity_changed"
            )

    def __exit__(self, *_args: object) -> bool:
        if self.descriptor is not None:
            os.close(self.descriptor)
            self.descriptor = None
        return False


def _pin_ordinary_file(path: Path):
    if os.name == "nt":
        return _WindowsOrdinaryFilePin(path)
    return _PortableOrdinaryFilePin(path)


def _build_validator_layout_for_test(
    *,
    layout: RunLayout,
    area: str,
    run_id: str,
    attempt_id: str,
    secure: Callable[[Path], object] = ensure_private_directory,
    reparse_check: Callable[..., None] = _assert_no_reparse_chain,
) -> ValidatorLayout:
    if area not in {"validation", "active", "presentation"}:
        raise ValidatorBlockedError("request_area_rejected")
    try:
        if (
            str(uuid.UUID(run_id)) != run_id
            or str(uuid.UUID(attempt_id)) != attempt_id
        ):
            raise ValueError
    except (ValueError, AttributeError) as error:
        raise ValidatorBlockedError("identifier_not_canonical") from error
    requested_attempt = layout.root / "validator" / area / attempt_id
    reparse_check(layout.root, requested_attempt, require_target=False)
    attempt = canonical_future(requested_attempt)
    assert_descendant(attempt, layout.root)
    reparse_check(layout.root, attempt, require_target=False)
    if attempt.exists():
        raise ValidatorBlockedError("validator_attempt_exists")
    secure(attempt)
    reparse_check(layout.root, attempt, require_target=True)
    paths = {
        name: attempt / name
        for name in ("request", "result", "profile", "documents", "cache")
    }
    for directory in paths.values():
        reparse_check(layout.root, directory, require_target=False)
        secure(directory)
        reparse_check(layout.root, directory, require_target=True)
    return ValidatorLayout(
        run_root=layout.root,
        attempt_root=attempt,
        runtime_exe=layout.root / "runtime" / "WeFlow" / "WeFlow.exe",
        request_path=paths["request"] / "request.json",
        result_path=paths["result"] / "result.json",
        user_data_dir=paths["profile"],
        documents_dir=paths["documents"],
        cache_dir=paths["cache"],
    )


def build_validator_layout(
    layout: RunLayout, area: str, run_id: str
) -> ValidatorLayout:
    return _build_validator_layout_for_test(
        layout=layout,
        area=area,
        run_id=run_id,
        attempt_id=str(uuid.uuid4()),
    )


def _write_request(
    layout: ValidatorLayout,
    payload: dict,
    reparse_check: Callable[..., None] = _assert_no_reparse_chain,
) -> None:
    encoded = _assert_exact_layout(layout, payload)
    temporary = layout.request_path.parent / (
        f".request.{uuid.uuid4()}.tmp"
    )
    descriptor = None
    published = False
    held = None
    reparse_check(
        layout.run_root, layout.request_path.parent, require_target=True
    )
    reparse_check(layout.run_root, temporary, require_target=False)
    try:
        flags = os.O_CREAT | os.O_EXCL | os.O_RDWR
        flags |= getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOINHERIT", 0)
        descriptor = os.open(temporary, flags, 0o600)
        offset = 0
        while offset < len(encoded):
            written = os.write(descriptor, encoded[offset:])
            if written == 0:
                raise ValidatorBlockedError("request_publication_failed")
            offset += written
        os.fsync(descriptor)
        held = os.fstat(descriptor)
        named = temporary.lstat()
        if (
            not stat.S_ISREG(held.st_mode)
            or not stat.S_ISREG(named.st_mode)
            or (held.st_dev, held.st_ino, held.st_size)
            != (named.st_dev, named.st_ino, named.st_size)
            or held.st_size != len(encoded)
        ):
            raise ValidatorBlockedError("request_temporary_changed")
        reparse_check(layout.run_root, temporary, require_target=True)
        reparse_check(
            layout.run_root, layout.request_path, require_target=False
        )
        os.lseek(descriptor, 0, os.SEEK_SET)
        if os.read(descriptor, len(encoded) + 1) != encoded:
            raise ValidatorBlockedError("request_temporary_changed")
        os.link(temporary, layout.request_path)
        os.lseek(descriptor, 0, os.SEEK_SET)
        exact_bytes = os.read(descriptor, len(encoded) + 1)
        held_after_link = os.fstat(descriptor)
        published_info = layout.request_path.lstat()
        source_info = temporary.lstat()
        if (
            not stat.S_ISREG(published_info.st_mode)
            or exact_bytes != encoded
            or (
                held.st_dev,
                held.st_ino,
                held.st_size,
            )
            != (
                held_after_link.st_dev,
                held_after_link.st_ino,
                held_after_link.st_size,
            )
            or (held.st_dev, held.st_ino, held.st_size)
            != (
                published_info.st_dev,
                published_info.st_ino,
                published_info.st_size,
            )
            or (
                source_info.st_dev,
                source_info.st_ino,
                source_info.st_size,
            )
            != (
                published_info.st_dev,
                published_info.st_ino,
                published_info.st_size,
            )
        ):
            if (
                source_info.st_dev,
                source_info.st_ino,
                source_info.st_size,
            ) == (
                published_info.st_dev,
                published_info.st_ino,
                published_info.st_size,
            ):
                layout.request_path.unlink()
            raise ValidatorBlockedError("request_temporary_changed")
        published = True
    except ValidatorBlockedError:
        raise
    except FileExistsError as error:
        raise ValidatorBlockedError("request_target_exists") from error
    except OSError as error:
        raise ValidatorBlockedError("request_publication_failed") from error
    finally:
        try:
            if held is not None and os.path.lexists(temporary):
                current = temporary.lstat()
                if _same_identity(held, current):
                    try:
                        temporary.unlink()
                    except OSError:
                        if descriptor is not None:
                            os.close(descriptor)
                            descriptor = None
                        if os.path.lexists(temporary):
                            current = temporary.lstat()
                            if _same_identity(held, current):
                                temporary.unlink()
        finally:
            if descriptor is not None:
                os.close(descriptor)
        if not published and os.path.lexists(layout.request_path):
            current = layout.request_path.lstat()
            if held is not None and _same_identity(held, current):
                layout.request_path.unlink()


def _stop_and_reap(process) -> None:
    stages = (
        (lambda: process.send_signal(signal.CTRL_BREAK_EVENT), 30),
        (lambda: process.terminate(), 10),
        (lambda: process.kill(), 10),
    )
    for action, timeout in stages:
        try:
            action()
        except (OSError, AttributeError):
            pass
        try:
            process.wait(timeout=timeout)
            return
        except (subprocess.TimeoutExpired, OSError):
            continue
    raise ValidatorBlockedError("validator_process_still_running")


def _launch_validator_for_test(
    *,
    layout: ValidatorLayout,
    request_payload: dict,
    process_paths: Iterable[str | Path],
    formal_weflow: Path = Path("WeFlow.exe"),
    verify_runtime: Callable[[ValidatorLayout], object],
    runner: Callable[..., object],
    environment: dict[str, str] | None = None,
    reparse_check: Callable[..., None] = _assert_no_reparse_chain,
) -> int:
    _assert_exact_layout(layout, request_payload)
    if _is_formal_weflow_running_for_test(
        process_paths, formal_weflow=formal_weflow
    ):
        raise ValidatorBlockedError("formal_weflow_running")
    reparse_check(layout.run_root, layout.attempt_root, require_target=True)
    verify_runtime(layout)
    reparse_check(layout.run_root, layout.runtime_exe, require_target=True)
    reparse_check(layout.run_root, layout.request_path, require_target=False)
    _write_request(layout, request_payload)
    reparse_check(layout.run_root, layout.request_path, require_target=True)
    for target in (
        layout.runtime_exe,
        layout.attempt_root,
        layout.user_data_dir,
        layout.documents_dir,
        layout.request_path,
    ):
        reparse_check(layout.run_root, target, require_target=True)
    runner_arguments = {
        "cwd": str(layout.attempt_root),
        "creationflags": subprocess.CREATE_NEW_PROCESS_GROUP,
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
    }
    if environment is not None:
        runner_arguments["env"] = environment
    process = runner(
        [
            str(layout.runtime_exe),
            "--weflow-validator-request",
            str(layout.request_path),
            f"--user-data-dir={layout.user_data_dir}",
        ],
        **runner_arguments,
    )
    try:
        for target in (
            layout.runtime_exe,
            layout.attempt_root,
            layout.user_data_dir,
            layout.documents_dir,
            layout.request_path,
        ):
            reparse_check(layout.run_root, target, require_target=True)
    except Exception:
        _stop_and_reap(process)
        raise
    try:
        code = process.wait(timeout=600)
    except subprocess.TimeoutExpired as error:
        _stop_and_reap(process)
        raise ValidatorBlockedError("validator_timeout") from error
    except Exception:
        _stop_and_reap(process)
        raise
    if code not in (0, 70):
        raise ValidatorBlockedError("validator_process_failed")
    reparse_check(layout.run_root, layout.result_path, require_target=True)
    return code


def launch_validator(
    layout: ValidatorLayout,
    request_payload: dict,
    *,
    formal_weflow: Path,
    snapshots_root: Path,
) -> dict:
    _assert_production_ancestry(
        layout, request_payload, snapshots_root=snapshots_root
    )
    paths = ()
    if formal_weflow_is_running(formal_weflow=formal_weflow):
        paths = (formal_weflow,)
    environment = os.environ.copy()
    environment["WEFLOW_CHAT_SNAPSHOTS_ROOT"] = str(
        canonical_existing(snapshots_root)
    )
    code = _launch_validator_for_test(
        layout=layout,
        request_payload=request_payload,
        process_paths=paths,
        formal_weflow=formal_weflow,
        verify_runtime=lambda value: _verify_runtime_before_launch(
            value, formal_weflow=formal_weflow
        ),
        runner=subprocess.Popen,
        environment=environment,
    )
    value = read_validation_result(
        layout.result_path,
        expected_run_id=request_payload["runId"],
        expected_operation=request_payload["operation"],
    )
    return _bind_exit_result_for_test(code, value)


def launch_avatar_aggregate(
    layout: ValidatorLayout,
    request_payload: dict,
    *,
    formal_weflow: Path,
    snapshots_root: Path,
) -> dict:
    if request_payload.get("operation") != "avatar-aggregate":
        raise ValidatorBlockedError("request_schema_mismatch")
    value = launch_validator(
        layout,
        request_payload,
        formal_weflow=formal_weflow,
        snapshots_root=snapshots_root,
    )
    if value["status"] != "ok":
        raise ValidatorBlockedError(
            value["reasonCode"] or "avatar_aggregate_blocked"
        )
    return value["validation"]


def _assert_production_ancestry(
    layout: ValidatorLayout,
    request_payload: dict,
    *,
    snapshots_root: Path,
) -> None:
    _assert_exact_layout(layout, request_payload)
    run_id = request_payload["runId"]
    snapshots = canonical_existing(snapshots_root)
    run_root = _absolute(layout.run_root)
    if run_root.parent != snapshots or not run_root.name.endswith(
        f"-{run_id}"
    ):
        raise ValidatorBlockedError("validator_run_root_mismatch")


def _verify_runtime_before_launch(
    layout: ValidatorLayout, *, formal_weflow: Path
) -> None:
    verify_copied_runtime_contract(
        layout=RunLayout.from_existing_root(layout.run_root)
    )
    if formal_weflow_is_running(formal_weflow=formal_weflow):
        raise ValidatorBlockedError("formal_weflow_running")


def _bind_exit_result_for_test(code: int, value: dict) -> dict:
    if (
        code not in (0, 70)
        or not isinstance(value, dict)
        or (code, value.get("status"))
        not in {(0, "ok"), (70, "compatibility_blocked")}
    ):
        raise ValidatorBlockedError("validator_exit_result_mismatch")
    return value


def _retryable_startup_timeout(
    error: ValidatorBlockedError,
    attempt: ValidatorLayout,
) -> bool:
    if error.args != ("validator_timeout",):
        return False
    progress_paths = (
        attempt.result_path,
        attempt.user_data_dir / "validator-stage.log",
    )
    try:
        for path in progress_paths:
            _assert_no_reparse_chain(
                attempt.run_root, path, require_target=False
            )
        return all(not os.path.lexists(path) for path in progress_paths)
    except (OSError, ValueError, ValidatorBlockedError):
        return False


class _CopiedBackendCore:
    def __init__(
        self,
        *,
        layout_builder=build_validator_layout,
        profile_builder=build_envelope_profile,
        launcher=launch_validator,
        avatar_launcher=launch_avatar_aggregate,
        result_reader=read_validation_result,
        presentation_reader=read_presentation_receipt,
        formal_profile_binding=_formal_profile_binding,
        pin_directory=_pin_directory,
        pin_file=_pin_ordinary_file,
    ):
        self._layout_builder = layout_builder
        self._profile_builder = profile_builder
        self._launcher = launcher
        self._avatar_launcher = avatar_launcher
        self._result_reader = result_reader
        self._presentation_reader = presentation_reader
        self._formal_profile_binding = formal_profile_binding
        self._pin_directory = pin_directory
        self._pin_file = pin_file
        self._stored_envelope_scope: (
            tuple[str, str, int, int] | None
        ) = None
        self.request_audit: list[dict[str, object]] = []
        self._attempt_audit: list[dict[str, object]] = []

    @property
    def attempt_audit(self) -> tuple[dict[str, object], ...]:
        return tuple(dict(item) for item in self._attempt_audit)

    def _build_followup_profile(
        self,
        *,
        layout: RunLayout,
        attempt: ValidatorLayout,
        area: str,
        run_id: str,
    ) -> ConfigCopyReceipt:
        if self._stored_envelope_scope is None:
            raise ValidatorBlockedError(
                "stored_envelope_validation_required"
            )
        if _run_scope(layout, run_id) != self._stored_envelope_scope:
            raise ValidatorBlockedError(
                "validated_scope_mismatch"
            )
        return self._profile_builder(
            run_layout=layout,
            validator_layout=attempt,
            area=area,
        )

    def avatar_aggregate(
        self,
        *,
        area: str,
        layout: RunLayout,
        run_id: str,
        _startup_retry_allowed: bool = True,
    ) -> dict:
        if area not in {"validation", "active", "presentation"}:
            raise ValidatorBlockedError("request_area_rejected")
        attempt = self._layout_builder(layout, area, run_id)
        profile_receipt = self._build_followup_profile(
            layout=layout,
            attempt=attempt,
            area=area,
            run_id=run_id,
        )
        expected_db_path = (
            layout.root / "presentation"
            if area == "presentation"
            else getattr(layout, area)
        )
        expected_cache_path = attempt.cache_dir
        config_path = (
            attempt.user_data_dir / "WeFlow-config.json"
        )
        try:
            for path in (
                expected_db_path,
                expected_cache_path,
                attempt.user_data_dir,
            ):
                _assert_no_reparse_chain(
                    layout.root, path, require_target=True
                )
                if not path.is_dir():
                    raise ValidatorBlockedError(
                        "validator_profile_receipt_invalid"
                    )
        except (OSError, ValueError) as error:
            raise ValidatorBlockedError(
                "validator_profile_receipt_invalid"
            ) from error
        if (
            not isinstance(profile_receipt, ConfigCopyReceipt)
            or not _valid_profile_changed_fields(
                profile_receipt.changed_fields
            )
            or profile_receipt.effective_db_path != str(expected_db_path)
            or profile_receipt.effective_cache_path
            != str(expected_cache_path)
            or profile_receipt.source_path_absent is not True
            or any(
                not isinstance(value, str)
                or len(value) != 64
                or any(
                    character not in "0123456789ABCDEF"
                    for character in value
                )
                for value in (
                    profile_receipt.source_sha256,
                    profile_receipt.destination_sha256,
                )
            )
        ):
            raise ValidatorBlockedError(
                "validator_profile_receipt_invalid"
            )
        _assert_no_reparse_chain(
            layout.root, config_path, require_target=True
        )
        config_binding = _ordinary_file_binding(config_path)
        if (
            config_binding[3]
            != profile_receipt.destination_sha256
        ):
            raise ValidatorBlockedError(
                "validator_profile_receipt_invalid"
            )
        request = {
            "operation": "avatar-aggregate",
            "runId": run_id,
            "area": area,
        }
        self.request_audit.append(dict(request))
        directory_paths = (
            expected_db_path,
            expected_cache_path,
            attempt.user_data_dir,
        )
        directory_bindings = tuple(
            _ordinary_directory_binding(path)
            for path in directory_paths
        )
        try:
            with ExitStack() as stack:
                pins = tuple(
                    stack.enter_context(
                        self._pin_directory(path)
                    )
                    for path in directory_paths
                )
                file_pin = stack.enter_context(
                    self._pin_file(config_path)
                )
                for pinned in pins:
                    pinned.verify()
                file_pin.verify()
                if (
                    tuple(
                        _ordinary_directory_binding(path)
                        for path in directory_paths
                    )
                    != directory_bindings
                    or
                    _ordinary_file_binding(config_path)
                    != config_binding
                ):
                    raise ValidatorBlockedError(
                        "avatar_data_binding_changed"
                    )
                aggregate = self._avatar_launcher(
                    attempt, request_payload=request
                )
                for pinned in pins:
                    pinned.verify()
                file_pin.verify()
                if (
                    tuple(
                        _ordinary_directory_binding(path)
                        for path in directory_paths
                    )
                    != directory_bindings
                    or
                    _ordinary_file_binding(config_path)
                    != config_binding
                ):
                    raise ValidatorBlockedError(
                        "avatar_data_binding_changed"
                    )
        except ValidatorBlockedError as error:
            if (
                _startup_retry_allowed
                and area == "presentation"
                and _retryable_startup_timeout(error, attempt)
            ):
                return self.avatar_aggregate(
                    area=area,
                    layout=layout,
                    run_id=run_id,
                    _startup_retry_allowed=False,
                )
            raise
        except (OSError, PermissionError, ValueError) as error:
            raise ValidatorBlockedError(
                "avatar_data_binding_changed"
            ) from error
        try:
            return _validate_avatar_aggregate(aggregate)
        except ValidationResultError as error:
            raise ValidatorBlockedError(
                "avatar_aggregate_invalid"
            ) from error

    def media_openability(
        self,
        *,
        area: str,
        layout: RunLayout,
        run_id: str,
        _startup_retry_allowed: bool = True,
    ) -> dict:
        if area != "presentation":
            raise ValidatorBlockedError("request_area_rejected")
        attempt = self._layout_builder(layout, area, run_id)
        expected_db_path = layout.root / "presentation"
        try:
            account_roots = tuple(expected_db_path.iterdir())
            if (
                len(account_roots) != 1
                or account_roots[0].is_symlink()
                or not account_roots[0].is_dir()
            ):
                raise ValueError("presentation_account_invalid")
            account_name = account_roots[0].name
        except (OSError, ValueError) as error:
            raise ValidatorBlockedError(
                "media_data_binding_changed"
            ) from error

        def capture_integrity():
            try:
                return (
                    self._presentation_reader(
                        layout.root / "presentation-manifest.json",
                        expected_presentation_root=expected_db_path,
                        account_name=account_name,
                    ),
                    self._formal_profile_binding(),
                )
            except Exception as error:
                raise ValidatorBlockedError(
                    "media_data_binding_changed"
                ) from error

        integrity_before = capture_integrity()
        profile_receipt = self._build_followup_profile(
            layout=layout,
            attempt=attempt,
            area=area,
            run_id=run_id,
        )
        expected_cache_path = attempt.cache_dir
        config_path = (
            attempt.user_data_dir / "WeFlow-config.json"
        )
        try:
            for path in (
                expected_db_path,
                expected_cache_path,
                attempt.user_data_dir,
            ):
                _assert_no_reparse_chain(
                    layout.root, path, require_target=True
                )
                if not path.is_dir():
                    raise ValidatorBlockedError(
                        "validator_profile_receipt_invalid"
                    )
        except (OSError, ValueError) as error:
            raise ValidatorBlockedError(
                "validator_profile_receipt_invalid"
            ) from error
        if (
            not isinstance(profile_receipt, ConfigCopyReceipt)
            or not _valid_profile_changed_fields(
                profile_receipt.changed_fields
            )
            or profile_receipt.effective_db_path
            != str(expected_db_path)
            or profile_receipt.effective_cache_path
            != str(expected_cache_path)
            or profile_receipt.source_path_absent is not True
            or any(
                not isinstance(value, str)
                or len(value) != 64
                or any(
                    character not in "0123456789ABCDEF"
                    for character in value
                )
                for value in (
                    profile_receipt.source_sha256,
                    profile_receipt.destination_sha256,
                )
            )
        ):
            raise ValidatorBlockedError(
                "validator_profile_receipt_invalid"
            )
        _assert_no_reparse_chain(
            layout.root, config_path, require_target=True
        )
        config_binding = _ordinary_file_binding(config_path)
        if config_binding[3] != profile_receipt.destination_sha256:
            raise ValidatorBlockedError(
                "validator_profile_receipt_invalid"
            )
        request = {
            "operation": "media-openability",
            "runId": run_id,
            "area": "presentation",
        }
        self.request_audit.append(dict(request))
        directory_paths = (
            expected_db_path,
            expected_cache_path,
            attempt.user_data_dir,
        )
        directory_bindings = tuple(
            _ordinary_directory_binding(path)
            for path in directory_paths
        )
        try:
            with ExitStack() as stack:
                pins = tuple(
                    stack.enter_context(self._pin_directory(path))
                    for path in directory_paths
                )
                file_pin = stack.enter_context(
                    self._pin_file(config_path)
                )
                for pinned in pins:
                    pinned.verify()
                file_pin.verify()
                if (
                    tuple(
                        _ordinary_directory_binding(path)
                        for path in directory_paths
                    )
                    != directory_bindings
                    or _ordinary_file_binding(config_path)
                    != config_binding
                ):
                    raise ValidatorBlockedError(
                        "media_data_binding_changed"
                    )
                try:
                    launched = self._launcher(
                        attempt, request_payload=request
                    )
                    value = (
                        launched
                        if isinstance(launched, dict)
                        else self._result_reader(
                            attempt.result_path,
                            expected_run_id=run_id,
                            expected_operation="media-openability",
                        )
                    )
                finally:
                    if capture_integrity() != integrity_before:
                        raise ValidatorBlockedError(
                            "media_data_binding_changed"
                        )
                for pinned in pins:
                    pinned.verify()
                file_pin.verify()
                if (
                    tuple(
                        _ordinary_directory_binding(path)
                        for path in directory_paths
                    )
                    != directory_bindings
                    or _ordinary_file_binding(config_path)
                    != config_binding
                ):
                    raise ValidatorBlockedError(
                        "media_data_binding_changed"
                    )
        except ValidatorBlockedError as error:
            if (
                _startup_retry_allowed
                and _retryable_startup_timeout(error, attempt)
            ):
                return self.media_openability(
                    area=area,
                    layout=layout,
                    run_id=run_id,
                    _startup_retry_allowed=False,
                )
            raise
        except ValidationResultError as error:
            raise ValidatorBlockedError(
                "media_openability_invalid"
            ) from error
        except (OSError, PermissionError, ValueError) as error:
            raise ValidatorBlockedError(
                "media_data_binding_changed"
            ) from error
        if value["status"] != "ok":
            raise ValidatorBlockedError(
                value["reasonCode"] or "media_openability_blocked"
            )
        try:
            return _validate_media_openability(value["validation"])
        except (KeyError, TypeError, ValidationResultError) as error:
            raise ValidatorBlockedError(
                "media_openability_invalid"
            ) from error

    def validate(
        self, *, area: str, layout: RunLayout, run_id: str
    ) -> ValidationReceipt:
        attempt = self._layout_builder(layout, area, run_id)
        self._stored_envelope_scope = None
        profile_receipt = self._profile_builder(
            run_layout=layout, validator_layout=attempt, area=area
        )
        expected_db_path = str(
            layout.root / "presentation"
            if area == "presentation"
            else getattr(layout, area)
        )
        if (
            not isinstance(profile_receipt, ConfigCopyReceipt)
            or not _valid_profile_changed_fields(
                profile_receipt.changed_fields
            )
            or profile_receipt.effective_db_path != expected_db_path
            or profile_receipt.effective_cache_path != str(attempt.cache_dir)
            or profile_receipt.source_path_absent is not True
            or any(
                not isinstance(value, str)
                or len(value) != 64
                or any(character not in "0123456789ABCDEF" for character in value)
                for value in (
                    profile_receipt.source_sha256,
                    profile_receipt.destination_sha256,
                )
            )
        ):
            raise ValidatorBlockedError("validator_profile_receipt_invalid")
        attempt_audit = {
            "area": area,
            "attemptRoot": str(attempt.attempt_root),
            "configPath": str(
                attempt.user_data_dir / "WeFlow-config.json"
            ),
            "effectiveDbPath": profile_receipt.effective_db_path,
            "effectiveCachePath": profile_receipt.effective_cache_path,
            "sourcePathAbsent": profile_receipt.source_path_absent,
            "changedFields": profile_receipt.changed_fields,
            "sourceSha256": profile_receipt.source_sha256,
            "destinationSha256": profile_receipt.destination_sha256,
        }
        request = {
            "operation": "validate-snapshot",
            "runId": run_id,
            "area": area,
        }
        self.request_audit.append(dict(request))
        launched = self._launcher(attempt, request_payload=request)
        value = (
            launched
            if isinstance(launched, dict)
            else self._result_reader(
                attempt.result_path,
                expected_run_id=run_id,
                expected_operation="validate-snapshot",
            )
        )
        self._attempt_audit.append(attempt_audit)
        if value["status"] != "ok":
            return ValidationReceipt(
                value["status"], value["reasonCode"], None
            )
        expected_gates = {
            "userDataIsolated": True,
            "documentsIsolated": True,
            "singleInstanceLockAcquired": True,
            "safeStorageAvailable": True,
            "syntheticEnvelopeRoundtrip": False,
            "nativeProtectionAuthenticated": True,
            "workerSetPathsCalled": True,
        }
        if (
            value["gates"] != expected_gates
            or value["callsBeforeOpen"] != ["setPaths", "testConnection"]
        ):
            raise ValidatorBlockedError("validator_gate_failed")
        self._stored_envelope_scope = _run_scope(layout, run_id)
        result = value["validation"]
        return ValidationReceipt(
            "ok",
            None,
            FingerprintSet(
                schemaFingerprint=result["schemaFingerprint"],
                aggregateFingerprint=result["aggregateFingerprint"],
                databaseCoverageFingerprint=result[
                    "databaseCoverageFingerprint"
                ],
            ),
        )


class CopiedWeFlowValidatorBackend:
    def __init__(
        self,
        *,
        formal_config: Path,
        formal_weflow: Path,
        snapshots_root: Path,
        capabilities: frozenset[str] = frozenset(),
    ) -> None:
        if (
            not isinstance(capabilities, frozenset)
            or not capabilities <= {STORED_ENVELOPE_REFRESH}
        ):
            raise ValueError("validator_capabilities_invalid")
        try:
            bound_config = canonical_existing(formal_config)
            bound_weflow = canonical_existing(formal_weflow)
            bound_snapshots = canonical_existing(snapshots_root)
        except (OSError, TypeError, ValueError) as error:
            raise ValueError("validator_host_contract_invalid") from error
        if (
            bound_config.name != "WeFlow-config.json"
            or bound_weflow.name.casefold() != "weflow.exe"
            or not bound_snapshots.is_dir()
        ):
            raise ValueError("validator_host_contract_invalid")

        def profile_builder(**values):
            return build_envelope_profile(
                source_config_path=bound_config,
                **values,
            )

        def validator_launcher(layout, request_payload):
            return launch_validator(
                layout,
                request_payload,
                formal_weflow=bound_weflow,
                snapshots_root=bound_snapshots,
            )

        def avatar_launcher(layout, request_payload):
            return launch_avatar_aggregate(
                layout,
                request_payload,
                formal_weflow=bound_weflow,
                snapshots_root=bound_snapshots,
            )

        self._capabilities = capabilities
        self._core = _CopiedBackendCore(
            profile_builder=profile_builder,
            launcher=validator_launcher,
            avatar_launcher=avatar_launcher,
            formal_profile_binding=lambda: _formal_profile_binding(
                bound_config
            ),
        )
        self._validated_scope: (
            tuple[str, str, int, int] | None
        ) = None

    @property
    def request_audit(self) -> tuple[dict[str, object], ...]:
        return tuple(dict(item) for item in self._core.request_audit)

    @property
    def attempt_audit(self) -> tuple[dict[str, object], ...]:
        return tuple(dict(item) for item in self._core.attempt_audit)

    def avatar_aggregate(
        self, *, area: str, layout: RunLayout, run_id: str
    ) -> dict:
        if self._validated_scope is None:
            raise ValidatorBlockedError(
                "stored_envelope_validation_required"
            )
        if (
            _run_scope(layout, run_id)
            != self._validated_scope
        ):
            raise ValidatorBlockedError(
                "validated_scope_mismatch"
            )
        return self._core.avatar_aggregate(
            area=area, layout=layout, run_id=run_id
        )

    def media_openability(
        self, *, area: str, layout: RunLayout, run_id: str
    ) -> dict:
        if self._validated_scope is None:
            raise ValidatorBlockedError(
                "stored_envelope_validation_required"
            )
        if (
            _run_scope(layout, run_id)
            != self._validated_scope
        ):
            raise ValidatorBlockedError(
                "validated_scope_mismatch"
            )
        if area != "presentation":
            raise ValidatorBlockedError("request_area_rejected")
        return self._core.media_openability(
            area=area, layout=layout, run_id=run_id
        )

    def validate(
        self, *, area: str, layout: RunLayout, run_id: str
    ) -> ValidationReceipt:
        if area == "validation":
            self._validated_scope = None
        receipt = self._core.validate(
            area=area, layout=layout, run_id=run_id
        )
        if area == "validation" and receipt.status == "ok":
            self._validated_scope = _run_scope(
                layout, run_id
            )
        return receipt

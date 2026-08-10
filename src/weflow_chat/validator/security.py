from dataclasses import dataclass
import ctypes
from ctypes import wintypes
import json
import locale
import os
from pathlib import Path
import stat
import subprocess
from typing import Callable, Protocol


_FULL_CONTROL = 0x1F01FF
_CONTAINER_AND_OBJECT_INHERIT = 0x3
_FILE_READ_ATTRIBUTES = 0x80
_DELETE = 0x10000
_FILE_SHARE_READ = 0x1
_FILE_SHARE_WRITE = 0x2
_FILE_SHARE_DELETE = 0x4
_OPEN_EXISTING = 3
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_ATTRIBUTE_DIRECTORY = 0x10
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class _ByHandleFileInformation(ctypes.Structure):
    _fields_ = [
        ("file_attributes", wintypes.DWORD),
        ("creation_time", wintypes.FILETIME),
        ("last_access_time", wintypes.FILETIME),
        ("last_write_time", wintypes.FILETIME),
        ("volume_serial_number", wintypes.DWORD),
        ("file_size_high", wintypes.DWORD),
        ("file_size_low", wintypes.DWORD),
        ("number_of_links", wintypes.DWORD),
        ("file_index_high", wintypes.DWORD),
        ("file_index_low", wintypes.DWORD),
    ]


@dataclass(frozen=True, slots=True)
class _DirectoryIdentity:
    volume_serial_number: int
    file_index_high: int
    file_index_low: int


class _DirectoryPin(Protocol):
    def __enter__(self) -> "_DirectoryPin": ...

    def verify(self) -> None: ...

    def __exit__(self, *args: object) -> bool: ...


def _windows_directory_handle(
    path: Path,
    *,
    lock_rename: bool = True,
) -> tuple[int, _DirectoryIdentity]:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
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
        str(path),
        _FILE_READ_ATTRIBUTES | (_DELETE if lock_rename else 0),
        _FILE_SHARE_READ
        | _FILE_SHARE_WRITE
        | (0 if lock_rename else _FILE_SHARE_DELETE),
        None,
        _OPEN_EXISTING,
        _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    if handle == _INVALID_HANDLE_VALUE:
        raise PermissionError(
            "validator_directory_pin_failed"
        ) from ctypes.WinError(ctypes.get_last_error())
    get_information = kernel32.GetFileInformationByHandle
    get_information.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_ByHandleFileInformation),
    ]
    get_information.restype = wintypes.BOOL
    information = _ByHandleFileInformation()
    if not get_information(handle, ctypes.byref(information)):
        error = ctypes.WinError(ctypes.get_last_error())
        _close_windows_handle(handle)
        raise PermissionError("validator_directory_pin_failed") from error
    if (
        information.file_attributes & _FILE_ATTRIBUTE_REPARSE_POINT
        or not information.file_attributes & _FILE_ATTRIBUTE_DIRECTORY
    ):
        _close_windows_handle(handle)
        raise PermissionError("validator_reparse_rejected")
    return handle, _DirectoryIdentity(
        information.volume_serial_number,
        information.file_index_high,
        information.file_index_low,
    )


def _close_windows_handle(handle: int) -> None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL
    if not close_handle(handle):
        raise PermissionError(
            "validator_directory_close_failed"
        ) from ctypes.WinError(ctypes.get_last_error())


class _WindowsDirectoryPin:
    def __init__(self, path: Path):
        self.path = path
        self.handle: int | None = None
        self.identity: _DirectoryIdentity | None = None

    def __enter__(self) -> "_WindowsDirectoryPin":
        self.handle, self.identity = _windows_directory_handle(self.path)
        return self

    def verify(self) -> None:
        if self.handle is None or self.identity is None:
            raise PermissionError("validator_directory_pin_failed")
        current_handle, current_identity = _windows_directory_handle(
            self.path, lock_rename=False
        )
        try:
            if current_identity != self.identity:
                raise PermissionError(
                    "validator_directory_identity_changed"
                )
        finally:
            _close_windows_handle(current_handle)

    def __exit__(self, *_args: object) -> bool:
        if self.handle is not None:
            _close_windows_handle(self.handle)
            self.handle = None
        return False


class _PortableDirectoryPin:
    def __init__(self, path: Path):
        self.path = path
        self.identity: tuple[int, int] | None = None

    def __enter__(self) -> "_PortableDirectoryPin":
        information = self.path.lstat()
        if stat.S_ISLNK(information.st_mode):
            raise PermissionError("validator_reparse_rejected")
        self.identity = (information.st_dev, information.st_ino)
        return self

    def verify(self) -> None:
        information = self.path.lstat()
        if (
            stat.S_ISLNK(information.st_mode)
            or (information.st_dev, information.st_ino) != self.identity
        ):
            raise PermissionError(
                "validator_directory_identity_changed"
            )

    def __exit__(self, *_args: object) -> bool:
        return False


def _pin_directory(path: Path) -> _DirectoryPin:
    if os.name == "nt":
        return _WindowsDirectoryPin(path)
    return _PortableDirectoryPin(path)


@dataclass(frozen=True, slots=True)
class AclAce:
    sid: str
    access_type: str
    rights: int
    inheritance_flags: int
    propagation_flags: int
    inherited: bool


@dataclass(frozen=True, slots=True)
class AclReceipt:
    owner: str
    protected: bool
    aces: tuple[AclAce, ...]


class _AclAdapter(Protocol):
    def current_user_sid(self) -> str: ...

    def apply(self, path: Path) -> AclReceipt: ...

    def read(self, path: Path) -> AclReceipt: ...


def _reject_absolute_reparse_for_test(
    target: Path, *, require_target: bool
) -> None:
    absolute = Path(os.path.abspath(target))
    cursor = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        cursor = cursor / part
        if not os.path.lexists(cursor):
            continue
        info = cursor.lstat()
        if cursor.is_symlink() or (
            getattr(info, "st_file_attributes", 0)
            & stat.FILE_ATTRIBUTE_REPARSE_POINT
        ):
            raise PermissionError("validator_reparse_rejected")
    if require_target and not os.path.lexists(absolute):
        raise PermissionError("validator_path_missing")


_APPLY = r"""
$ErrorActionPreference='Stop'
$p=[System.IO.Path]::GetFullPath(
  [Environment]::GetEnvironmentVariable(
    'WEFLOW_VALIDATOR_ACL_PATH','Process'))
$u=[System.Security.Principal.WindowsIdentity]::GetCurrent().User
$s=New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
$acl=New-Object System.Security.AccessControl.DirectorySecurity
$acl.SetOwner($u)
$acl.SetAccessRuleProtection($true,$false)
$inherit=[System.Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
$prop=[System.Security.AccessControl.PropagationFlags]::None
$type=[System.Security.AccessControl.AccessControlType]::Allow
foreach($id in @($u,$s)) {
  $rule=New-Object System.Security.AccessControl.FileSystemAccessRule(
    $id,'FullControl',$inherit,$prop,$type)
  [void]$acl.AddAccessRule($rule)
}
$directory=New-Object System.IO.DirectoryInfo($p)
$directory.SetAccessControl($acl)
"""

_READ = r"""
$ErrorActionPreference='Stop'
$p=[System.IO.Path]::GetFullPath(
  [Environment]::GetEnvironmentVariable(
    'WEFLOW_VALIDATOR_ACL_PATH','Process'))
$acl=Get-Acl -LiteralPath $p
$rules=@($acl.GetAccessRules($true,$true,
  [System.Security.Principal.SecurityIdentifier]) | ForEach-Object {
    [pscustomobject]@{sid=$_.IdentityReference.Value;
      type=$_.AccessControlType.ToString();
      rights=[int64]$_.FileSystemRights;
      inheritanceFlags=[int]$_.InheritanceFlags;
      propagationFlags=[int]$_.PropagationFlags;
      inherited=[bool]$_.IsInherited}
  })
[pscustomobject]@{
  owner=$acl.GetOwner(
    [System.Security.Principal.SecurityIdentifier]).Value;
  protected=$acl.AreAccessRulesProtected;rules=$rules} |
  ConvertTo-Json -Compress -Depth 4
"""


class _WindowsAclAdapter:
    @staticmethod
    def _run(script: str, path: Path) -> str:
        environment = os.environ.copy()
        environment["WEFLOW_VALIDATOR_ACL_PATH"] = str(path)
        completed = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ],
            check=True,
            capture_output=True,
            env=environment,
            text=True,
            encoding=locale.getencoding(),
            errors="replace",
            timeout=30,
        )
        return completed.stdout

    def apply(self, path: Path) -> AclReceipt:
        self._run(_APPLY, path)
        return self.read(path)

    def read(self, path: Path) -> AclReceipt:
        try:
            raw = json.loads(self._run(_READ, path))
        except (json.JSONDecodeError, UnicodeError) as error:
            raise PermissionError("validator_acl_schema_mismatch") from error
        if (
            not isinstance(raw, dict)
            or set(raw) != {"owner", "protected", "rules"}
            or not isinstance(raw["owner"], str)
            or not isinstance(raw["protected"], bool)
            or not isinstance(raw["rules"], list)
        ):
            raise PermissionError("validator_acl_schema_mismatch")
        required = {
            "sid",
            "type",
            "rights",
            "inheritanceFlags",
            "propagationFlags",
            "inherited",
        }
        rules = raw["rules"]
        if any(
            not isinstance(rule, dict)
            or set(rule) != required
            or not isinstance(rule["sid"], str)
            or not isinstance(rule["type"], str)
            or type(rule["rights"]) is not int
            or type(rule["inheritanceFlags"]) is not int
            or type(rule["propagationFlags"]) is not int
            or not isinstance(rule["inherited"], bool)
            for rule in rules
        ):
            raise PermissionError("validator_acl_schema_mismatch")
        return AclReceipt(
            owner=raw["owner"],
            protected=raw["protected"],
            aces=tuple(
                AclAce(
                    sid=rule["sid"],
                    access_type=rule["type"],
                    rights=rule["rights"],
                    inheritance_flags=rule["inheritanceFlags"],
                    propagation_flags=rule["propagationFlags"],
                    inherited=rule["inherited"],
                )
                for rule in rules
            ),
        )

    def current_user_sid(self) -> str:
        return self._run(
            (
                "[System.Security.Principal.WindowsIdentity]::"
                "GetCurrent().User.Value"
            ),
            Path("."),
        ).strip()


def _ensure_private_directory_for_test(
    path: Path,
    adapter: _AclAdapter,
    reparse_check: Callable[..., None] = _reject_absolute_reparse_for_test,
    pin_directory: Callable[[Path], _DirectoryPin] = _pin_directory,
) -> AclReceipt:
    reparse_check(path, require_target=False)
    path.mkdir(parents=True, exist_ok=True)
    reparse_check(path, require_target=True)
    with pin_directory(path) as pinned:
        pinned.verify()
        applied = adapter.apply(path)
        pinned.verify()
        reread = adapter.read(path)
        pinned.verify()
        current_sid = adapter.current_user_sid()
        expected_aces = tuple(
            sorted(
                (
                    AclAce(
                        current_sid,
                        "Allow",
                        _FULL_CONTROL,
                        _CONTAINER_AND_OBJECT_INHERIT,
                        0,
                        False,
                    ),
                    AclAce(
                        "S-1-5-18",
                        "Allow",
                        _FULL_CONTROL,
                        _CONTAINER_AND_OBJECT_INHERIT,
                        0,
                        False,
                    ),
                ),
                key=lambda ace: ace.sid,
            )
        )
        actual_aces = tuple(
            sorted(
                reread.aces,
                key=lambda ace: (
                    ace.sid,
                    ace.access_type,
                    ace.rights,
                    ace.inheritance_flags,
                    ace.propagation_flags,
                    ace.inherited,
                ),
            )
        )
        if (
            applied != reread
            or reread.owner != current_sid
            or not reread.protected
            or len(reread.aces) != 2
            or actual_aces != expected_aces
        ):
            raise PermissionError("validator_acl_contract_mismatch")
        return reread


def ensure_private_directory(path: Path) -> AclReceipt:
    return _ensure_private_directory_for_test(path, _WindowsAclAdapter())

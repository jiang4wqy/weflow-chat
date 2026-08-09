from __future__ import annotations

import ctypes
from ctypes import wintypes
import hashlib
import json
import locale
import os
from pathlib import Path
import re
import shutil
import subprocess
import time

from weflow_chat.preflight import (
    HostContract,
    SourceEnumeration,
)
from weflow_chat.processes import ProcessIdentity
from weflow_chat.paths import canonical_existing
from weflow_chat.security import SecurityMetadata


POWERSHELL = Path(
    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
)
ICACLS = Path(
    r"C:\Windows\System32\icacls.exe"
)
_OPERATION_MUTEX_TIMEOUT_MS = 5_000
_OPERATION_MUTEX_PREFIX = (
    "Local\\OpenAI.WeFlowRecovery.LiveMutation.v1."
)
_PS_ARGUMENT_ENV_PREFIX = (
    "WEFLOW_RECOVERY_PS_ARGUMENT_V1_"
)


def _ps_json(script: str, *arguments: str):
    environment = os.environ.copy()
    environment[
        _PS_ARGUMENT_ENV_PREFIX + "COUNT"
    ] = str(len(arguments))
    for index, value in enumerate(arguments):
        environment[
            _PS_ARGUMENT_ENV_PREFIX + str(index)
        ] = value
    wrapped_script = (
        "$__count=[int]"
        "[Environment]::GetEnvironmentVariable("
        f"'{_PS_ARGUMENT_ENV_PREFIX}COUNT',"
        "'Process');"
        "$args=@(for($__index=0;"
        "$__index -lt $__count;$__index++){"
        "[Environment]::GetEnvironmentVariable("
        f"('{_PS_ARGUMENT_ENV_PREFIX}'+$__index),"
        "'Process')});"
        + script
    )
    result = subprocess.run(
        [
            str(POWERSHELL),
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            wrapped_script,
        ],
        check=False,
        text=True,
        encoding=locale.getencoding(),
        errors="strict",
        capture_output=True,
        env=environment,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if result.returncode != 0:
        raise RuntimeError("fixed_powershell_probe_failed")
    text = result.stdout.strip()
    return None if not text else json.loads(text)


class _SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("nLength", wintypes.DWORD),
        ("lpSecurityDescriptor", ctypes.c_void_p),
        ("bInheritHandle", wintypes.BOOL),
    ]


class _OwnedMutexLease:
    def __init__(self, handle, *, release, close) -> None:
        self._handle = handle
        self._release = release
        self._close = close

    def __enter__(self):
        if self._handle is None:
            raise RuntimeError("operation_lock_lease_not_owned")
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        handle, self._handle = self._handle, None
        release_failed = not self._release(handle)
        close_failed = not self._close(handle)
        if exc_type is None and (release_failed or close_failed):
            raise RuntimeError("operation_lock_release_failed")
        return False


def _open_win32_mutex(
    *,
    name: str,
    sddl: str,
    timeout_ms: int,
) -> _OwnedMutexLease:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    convert = (
        advapi32
        .ConvertStringSecurityDescriptorToSecurityDescriptorW
    )
    convert.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD),
    ]
    convert.restype = wintypes.BOOL
    kernel32.CreateMutexW.argtypes = [
        ctypes.POINTER(_SECURITY_ATTRIBUTES),
        wintypes.BOOL,
        wintypes.LPCWSTR,
    ]
    kernel32.CreateMutexW.restype = wintypes.HANDLE
    kernel32.WaitForSingleObject.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
    ]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.ReleaseMutex.argtypes = [wintypes.HANDLE]
    kernel32.ReleaseMutex.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    descriptor = ctypes.c_void_p()
    if not convert(sddl, 1, ctypes.byref(descriptor), None):
        raise RuntimeError("operation_lock_acl_creation_failed")
    attributes = _SECURITY_ATTRIBUTES(
        ctypes.sizeof(_SECURITY_ATTRIBUTES),
        descriptor,
        False,
    )
    try:
        handle = kernel32.CreateMutexW(
            ctypes.byref(attributes),
            False,
            name,
        )
    finally:
        kernel32.LocalFree(descriptor)
    if not handle:
        raise RuntimeError("operation_lock_open_failed")
    wait = kernel32.WaitForSingleObject(handle, timeout_ms)
    if wait == 0x00000102:
        kernel32.CloseHandle(handle)
        raise RuntimeError("operation_lock_timeout")
    if wait not in {0x00000000, 0x00000080}:
        kernel32.CloseHandle(handle)
        raise RuntimeError("operation_lock_wait_failed")
    return _OwnedMutexLease(
        handle,
        release=kernel32.ReleaseMutex,
        close=kernel32.CloseHandle,
    )


class FixedUserOperationMutex:
    """One fixed mutation mutex per Windows user and local logon session."""

    def __init__(
        self,
        *,
        sid_reader=None,
        opener=_open_win32_mutex,
    ) -> None:
        self._sid_reader = sid_reader or (
            lambda: _ps_json(
                "$s=[Security.Principal.WindowsIdentity]"
                "::GetCurrent().User.Value;"
                "@{sid=$s}|ConvertTo-Json -Compress"
            )["sid"]
        )
        self._opener = opener

    def acquire(self):
        sid = self._sid_reader()
        if (
            not isinstance(sid, str)
            or re.fullmatch(r"S-\d(?:-\d+)+", sid) is None
        ):
            raise RuntimeError("operation_lock_user_sid_invalid")
        digest = hashlib.sha256(
            sid.encode("ascii")
        ).hexdigest()[:32]
        return self._opener(
            name=_OPERATION_MUTEX_PREFIX + digest,
            sddl=f"D:P(A;;GA;;;SY)(A;;GA;;;{sid})",
            timeout_ms=_OPERATION_MUTEX_TIMEOUT_MS,
        )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(
            lambda: stream.read(1024 * 1024),
            b"",
        ):
            digest.update(chunk)
    return digest.hexdigest().upper()


def _pe_architecture(path: Path) -> str:
    with path.open("rb") as stream:
        stream.seek(0x3C)
        pe_offset = int.from_bytes(
            stream.read(4),
            "little",
        )
        stream.seek(pe_offset)
        if stream.read(4) != b"PE\x00\x00":
            raise RuntimeError("pe_signature_invalid")
        machine = int.from_bytes(
            stream.read(2),
            "little",
        )
    if machine != 0x8664:
        raise RuntimeError("pe_architecture_not_x64")
    return "x64"


def _ordinary_source_entries(
    root: Path,
) -> tuple[tuple[str, int, int], ...]:
    result = []
    pending = [root]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as opened:
            entries = sorted(
                opened,
                key=lambda item: item.name.casefold(),
            )
        for entry in entries:
            info = entry.stat(follow_symlinks=False)
            if (
                entry.is_symlink()
                or getattr(
                    info,
                    "st_file_attributes",
                    0,
                ) & 0x400
            ):
                raise RuntimeError("source_reparse_entry")
            path = Path(entry.path)
            if entry.is_dir(follow_symlinks=False):
                pending.append(path)
            elif entry.is_file(follow_symlinks=False):
                result.append(
                    (
                        path.relative_to(root).as_posix(),
                        info.st_size,
                        info.st_mtime_ns,
                    )
                )
            else:
                raise RuntimeError(
                    "source_non_ordinary_entry"
                )
    return tuple(sorted(result))


def _classify_db_path_shape(
    value: object,
    *,
    contract: HostContract,
    managed_active_paths: frozenset[Path],
) -> str:
    if not isinstance(value, str):
        return "invalid"
    supplied = Path(value)
    try:
        canonical = canonical_existing(supplied)
        source_account = canonical_existing(
            contract.source_account
        )
        snapshots_root = canonical_existing(
            contract.snapshots_root
        )
        allowed = frozenset(
            canonical_existing(Path(path))
            for path in managed_active_paths
        )
    except (OSError, ValueError):
        return "invalid"
    if canonical == source_account:
        return "account_dir_instead_of_parent"
    if (
        canonical.name.casefold()
        in {"active", "presentation"}
        and canonical.parent.parent == snapshots_root
        and canonical in allowed
    ):
        return "managed_active_parent"
    return "invalid"


class WindowsHostAdapters:
    def __init__(
        self,
        contract: HostContract,
        allocated_layout=None,
        *,
        runtime_prepared: bool = False,
        managed_active_paths: frozenset[Path] = frozenset(),
        local_trust_receipts: tuple = (),
        probe=_ps_json,
        entry_reader=_ordinary_source_entries,
        sha256=_sha256,
    ) -> None:
        self.contract = contract
        self.local_trust_receipts = tuple(local_trust_receipts)
        self._probe = probe
        self._entry_reader = entry_reader
        self._sha256 = sha256
        volume = probe(
            "$v=Get-Volume -DriveLetter F "
            "-ErrorAction Stop; "
            "@{fs=$v.FileSystem}|"
            "ConvertTo-Json -Compress"
        )
        self.fs = volume["fs"]
        self.vss = bool(
            probe(
                "$c=Get-CimClass Win32_ShadowCopy "
                "-ErrorAction Stop; "
                "@{ok=($null -ne $c)}|"
                "ConvertTo-Json -Compress"
            )["ok"]
        )
        self.free = shutil.disk_usage(
            contract.snapshots_root
        ).free
        allowed = {"transaction.json"}
        if runtime_prepared:
            allowed.add("runtime")
        self.target_exists = (
            False
            if allocated_layout is None
            else any(
                item.name not in allowed
                for item in allocated_layout.root.iterdir()
            )
        )
        self.config_regular = (
            contract.config_path.is_file()
            and not contract.config_path.is_symlink()
        )
        self.config_sha = (
            sha256(contract.config_path)
            if self.config_regular
            else ""
        )
        try:
            config = (
                json.loads(
                    contract.config_path.read_text(
                        encoding="utf-8"
                    )
                )
                if self.config_regular
                else {}
            )
        except (
            OSError,
            UnicodeError,
            json.JSONDecodeError,
        ):
            config = {}
            self.config_regular = False
            self.config_sha = ""
        db_path = config.get("dbPath")
        self.db_path_shape = _classify_db_path_shape(
            db_path,
            contract=contract,
            managed_active_paths=managed_active_paths,
        )
        selectors = config.get("wxidConfigs")
        self.account_matches = int(
            isinstance(selectors, dict)
            and contract.account_id in selectors
        )
        self.my_wxid_matches = (
            config.get("myWxid") == contract.account_id
        )
        processes = self._processes()
        formal_expected = str(
            contract.formal_weflow.resolve()
        ).casefold()
        weflow_named = [
            item
            for item in processes
            if (item.get("name") or "").casefold()
            == "weflow.exe"
        ]
        if any(
            not item.get("path")
            for item in weflow_named
        ):
            raise RuntimeError(
                "weflow_process_path_unreadable"
            )
        self.formal = tuple(
            sorted(
                item["pid"]
                for item in weflow_named
                if (
                    item.get("path") or ""
                ).casefold() == formal_expected
            )
        )
        self.validators = tuple(
            sorted(
                item["pid"]
                for item in weflow_named
                if (
                    (item.get("path") or "").casefold()
                    != formal_expected
                    or "--weflow-validator-request"
                    in (item.get("commandLine") or "")
                )
            )
        )
        self.weixin = self._weixin_identity(
            processes
        )
        self.session_exists = (
            contract.session_db.is_file()
        )
        self.old_upgrade_backup_exists = (
            contract.old_upgrade_backup.is_dir()
        )
        backup_parent = (
            contract.old_upgrade_backup.parent
        )
        history = (
            sorted(
                (
                    item
                    for item in backup_parent.iterdir()
                    if item.is_dir()
                ),
                key=lambda item: item.stat().st_mtime_ns,
            )
            if backup_parent.is_dir()
            else []
        )
        self.historical_backup_count = len(history)
        self.newest_historical_backup_timestamp_utc = (
            time.strftime(
                "%Y-%m-%dT%H:%M:%SZ",
                time.gmtime(
                    history[-1].stat().st_mtime
                ),
            )
            if history
            else None
        )

    @classmethod
    def for_preflight(
        cls,
        contract: HostContract,
        *,
        managed_active_paths: frozenset[Path] = frozenset(),
        local_trust_receipts: tuple = (),
    ) -> "WindowsHostAdapters":
        return cls(
            contract,
            None,
            managed_active_paths=managed_active_paths,
            local_trust_receipts=local_trust_receipts,
        )

    def enumerate_source(
        self,
    ) -> SourceEnumeration:
        root = self.contract.db_storage
        information = root.stat(
            follow_symlinks=False
        )
        return SourceEnumeration(
            root=root,
            rootIdentity=(
                information.st_dev,
                information.st_ino,
                information.st_ctime_ns,
            ),
            entries=self._entry_reader(root),
        )

    def _processes(self) -> list[dict]:
        value = self._probe(
            "Get-CimInstance Win32_Process | "
            "ForEach-Object {$p=$null;"
            "try{$p=Get-Process -Id $_.ProcessId "
            "-ErrorAction Stop}catch{};"
            "$created=$null;"
            "try{$created=([datetime]$_.CreationDate)"
            ".ToUniversalTime()"
            ".ToString('yyyy-MM-ddTHH:mm:ssZ')"
            "}catch{};"
            "@{pid=[int]$_.ProcessId;"
            "parentPid=[int]$_.ParentProcessId;"
            "name=$_.Name;path=$p.Path;"
            "commandLine=$_.CommandLine;"
            "creationTimeUtc=$created}} | "
            "ConvertTo-Json -Compress"
        )
        if value is None:
            return []
        return value if isinstance(value, list) else [value]

    def _weixin_identity(
        self,
        processes: list[dict],
    ) -> ProcessIdentity:
        executable = self.contract.weixin_executable
        expected = str(
            executable.resolve()
        ).casefold()
        named = [
            item
            for item in processes
            if (item.get("name") or "").casefold()
            == "weixin.exe"
        ]
        if (
            not named
            or any(not item.get("path") for item in named)
            or any(
                item["path"].casefold() != expected
                for item in named
            )
        ):
            raise RuntimeError(
                "unknown_or_unreadable_weixin_process"
            )
        mains = [
            item
            for item in named
            if "--type="
            not in (item.get("commandLine") or "")
        ]
        if len(mains) != 1:
            raise RuntimeError(
                "supported_weixin_main_not_unique"
            )
        main = mains[0]
        by_pid = {
            item["pid"]: item
            for item in named
        }
        for item in named:
            cursor = item
            seen = set()
            while cursor["pid"] != main["pid"]:
                if (
                    cursor["pid"] in seen
                    or cursor["parentPid"] not in by_pid
                ):
                    raise RuntimeError(
                        "weixin_descendant_family_mismatch"
                    )
                seen.add(cursor["pid"])
                cursor = by_pid[cursor["parentPid"]]
        module_script = (
            "$p=Get-Process -Id ([int]$args[0]) "
            "-ErrorAction Stop;"
            "$m=@($p.Modules|Where-Object{"
            "$_.ModuleName -ieq 'Weixin.dll'});"
            "if($m.Count -ne 1){"
            "throw 'weixin_module_not_unique'};"
            "$f=Get-Item -LiteralPath $m[0].FileName "
            "-Force -ErrorAction Stop;"
            "@{path=[IO.Path]::GetFullPath($f.FullName);"
            "size=[long]$f.Length}|"
            "ConvertTo-Json -Compress"
        )
        module = self._probe(
            module_script, str(main["pid"])
        )
        if (
            not isinstance(module, dict)
            or set(module) != {"path", "size"}
            or not isinstance(module["path"], str)
            or type(module["size"]) is not int
            or module["size"] <= 0
        ):
            raise RuntimeError("weixin_loaded_dll_identity_invalid")
        try:
            dll = canonical_existing(Path(module["path"]))
            install_root = canonical_existing(
                self.contract.weixin_install_root
            )
        except (OSError, ValueError) as error:
            raise RuntimeError(
                "weixin_loaded_dll_path_mismatch"
            ) from error
        if (
            dll.name.casefold() != "weixin.dll"
            or dll.parent.parent != install_root
            or dll.stat().st_size != module["size"]
        ):
            raise RuntimeError(
                "weixin_loaded_dll_path_mismatch"
            )
        signature = self._probe(
            "$e=Get-AuthenticodeSignature "
            "-LiteralPath $args[0];"
            "$d=Get-AuthenticodeSignature "
            "-LiteralPath $args[1];"
            "$h=[Security.Cryptography.SHA256]::Create();"
            "try{$c=([BitConverter]::ToString("
            "$h.ComputeHash($d.SignerCertificate.RawData)))"
            ".Replace('-','')}finally{$h.Dispose()};"
            "$v=[Diagnostics.FileVersionInfo]"
            "::GetVersionInfo($args[1]);"
            "@{status=[string]$e.Status;"
            "subject=[string]$e.SignerCertificate.Subject;"
            "dllStatus=[string]$d.Status;"
            "dllSubject=[string]"
            "$d.SignerCertificate.Subject;"
            "dllCertificateSha256=[string]$c;"
            "version=[string]$v.FileVersion}|"
            "ConvertTo-Json -Compress",
            str(executable),
            str(dll),
        )
        if (
            not isinstance(signature, dict)
            or set(signature)
            != {
                "status",
                "subject",
                "dllStatus",
                "dllSubject",
                "dllCertificateSha256",
                "version",
            }
            or not all(
                isinstance(value, str)
                for value in signature.values()
            )
            or re.fullmatch(
                r"[0-9A-F]{64}",
                signature["dllCertificateSha256"],
            )
            is None
            or re.fullmatch(
                r"[0-9]+(?:\.[0-9]+){3}",
                signature["version"],
            )
            is None
            or dll.parent.name != signature["version"]
        ):
            raise RuntimeError("weixin_loaded_dll_identity_invalid")
        digest = self._sha256(dll)
        repeated = self._probe(
            module_script, str(main["pid"])
        )
        if (
            repeated != module
            or canonical_existing(Path(repeated["path"])) != dll
            or dll.stat().st_size != module["size"]
            or self._sha256(dll) != digest
        ):
            raise RuntimeError("weixin_loaded_dll_identity_changed")
        return ProcessIdentity(
            pid=main["pid"],
            executable=executable,
            parent_pid=main["parentPid"],
            command_line=(
                main.get("commandLine") or ""
            ),
            architecture=_pe_architecture(executable),
            authenticode_status=signature["status"],
            signer_subject=signature["subject"],
            dll_authenticode_status=(
                signature["dllStatus"]
            ),
            dll_signer_subject=(
                signature["dllSubject"]
            ),
            dll_version=signature["version"],
            dll_sha256=digest,
            dll_path=dll,
            dll_size=module["size"],
            dll_signer_certificate_sha256=(
                signature["dllCertificateSha256"]
            ),
            isolated_user_data=None,
            creation_time_utc=(
                main.get("creationTimeUtc") or ""
            ),
        )


class RecoveryOnlyHostAdapters:
    """Existing-run recovery cannot touch live preflight boundaries."""

    def __getattr__(self, name):
        raise RuntimeError(
            "recovery_only_preflight_adapter_touched"
        )


class ValidationOnlyProcessGate:
    def request_normal_close_and_wait(
        self,
        timeout_seconds: float,
    ) -> bool:
        raise RuntimeError("validation_only_backend")


class ValidationOnlyFormalUiBackend:
    def launch_and_require_account_open(
        self,
        active_parent: Path,
    ) -> bool:
        raise RuntimeError("validation_only_backend")

    def relaunch_after_commit(self) -> None:
        raise RuntimeError("validation_only_backend")


class ValidationOnlySecurityAdapter:
    def capture(self, path: Path):
        raise RuntimeError("validation_only_backend")

    def restrict_backup_tree(
        self,
        path: Path,
    ) -> None:
        raise RuntimeError("validation_only_backend")

    def verify_restricted_backup_tree(
        self,
        path: Path,
    ) -> None:
        raise RuntimeError("validation_only_backend")

    def restore(self, path: Path, value) -> None:
        raise RuntimeError("validation_only_backend")

    def verify(self, path: Path, value) -> None:
        raise RuntimeError("validation_only_backend")


class WindowsProcessGate:
    def __init__(
        self,
        contract: HostContract,
        *,
        probe=_ps_json,
    ) -> None:
        self.executable = contract.formal_weflow
        self._probe = probe

    def request_normal_close_and_wait(
        self,
        timeout_seconds: float,
    ) -> bool:
        value = self._probe(
            "$expected=[IO.Path]::GetFullPath("
            "$args[0]);$limit=[double]$args[1];"
            "$rows=@(Get-CimInstance Win32_Process "
            "-Filter \"Name='WeFlow.exe'\" "
            "-ErrorAction Stop|ForEach-Object{"
            "$gp=$null;"
            "try{$gp=Get-Process -Id $_.ProcessId "
            "-ErrorAction Stop}catch{};"
            "$path=$null;try{$path=$gp.Path}catch{};"
            "@{pid=[int]$_.ProcessId;path=$path;"
            "cmd=$_.CommandLine;gp=$gp}});"
            "$unknown=@($rows|Where-Object{"
            "[string]::IsNullOrWhiteSpace($_.path)});"
            "$validators=@($rows|Where-Object{"
            "-not [string]::IsNullOrWhiteSpace($_.path) "
            "-and ([IO.Path]::GetFullPath($_.path) "
            "-ne $expected -or $_.cmd -like "
            "'*--weflow-validator-request*')});"
            "if($unknown.Count -or "
            "$validators.Count){"
            "@{closed=$false}|"
            "ConvertTo-Json -Compress;return};"
            "$formal=@($rows|Where-Object{"
            "[IO.Path]::GetFullPath($_.path) "
            "-eq $expected});"
            "foreach($row in $formal){"
            "[void]$row.gp.CloseMainWindow()};"
            "$end=[DateTime]::UtcNow"
            ".AddSeconds($limit);"
            "do{Start-Sleep -Milliseconds 200;"
            "$alive=@($formal|Where-Object{"
            "-not $_.gp.HasExited})}"
            "while($alive.Count -and "
            "[DateTime]::UtcNow -lt $end);"
            "$residual=@(Get-CimInstance "
            "Win32_Process -Filter "
            "\"Name='WeFlow.exe'\" "
            "-ErrorAction Stop);"
            "@{closed=($alive.Count -eq 0 "
            "-and $residual.Count -eq 0)}|"
            "ConvertTo-Json -Compress",
            str(self.executable),
            str(timeout_seconds),
        )
        return (
            isinstance(value, dict)
            and value.get("closed") is True
        )


class WindowsFormalUiBackend:
    def __init__(
        self,
        contract: HostContract,
        *,
        popen=subprocess.Popen,
        sleeper=time.sleep,
    ) -> None:
        self.executable = contract.formal_weflow
        self._popen = popen
        self._sleeper = sleeper
        self._process: subprocess.Popen | None = None

    def launch_and_require_account_open(
        self,
        active_parent: Path,
    ) -> bool:
        if not active_parent.is_dir():
            return False
        self._process = self._popen(
            [str(self.executable)],
            cwd=str(self.executable.parent),
            creationflags=getattr(
                subprocess,
                "CREATE_NEW_PROCESS_GROUP",
                0,
            ),
        )
        self._sleeper(2.0)
        return self._process.poll() is None

    def relaunch_after_commit(self) -> None:
        self._popen(
            [str(self.executable)],
            cwd=str(self.executable.parent),
            creationflags=getattr(
                subprocess,
                "CREATE_NEW_PROCESS_GROUP",
                0,
            ),
        )


class WindowsSecurityAdapter:
    def __init__(
        self,
        *,
        probe=_ps_json,
        runner=subprocess.run,
        set_attributes=None,
    ) -> None:
        self._probe = probe
        self._runner = runner
        self._set_attributes = (
            set_attributes
            or ctypes.windll.kernel32.SetFileAttributesW
        )

    def _sddl(self, path: Path) -> dict:
        return self._probe(
            "$a=Get-Acl -LiteralPath $args[0];"
            "$r=New-Object Security.AccessControl"
            ".RawSecurityDescriptor($a.Sddl);"
            "@{sddl=$a.Sddl;owner=$r.Owner.Value;"
            "group=$r.Group.Value}|"
            "ConvertTo-Json -Compress",
            str(path),
        )

    def capture(
        self,
        path: Path,
    ) -> SecurityMetadata:
        self._ordinary_tree(path)
        value = self._sddl(path)
        return SecurityMetadata(
            file_attributes=(
                path.stat().st_file_attributes
            ),
            owner_sid=value["owner"],
            group_sid=value["group"],
            dacl_sddl=value["sddl"],
        )

    def _current_sid(self) -> str:
        return self._probe(
            "$s=[Security.Principal.WindowsIdentity]"
            "::GetCurrent().User.Value;"
            "@{sid=$s}|ConvertTo-Json -Compress"
        )["sid"]

    def _acl_rules(self, path: Path) -> dict:
        return self._probe(
            "$a=Get-Acl -LiteralPath $args[0];"
            "$rules=@($a.Access|ForEach-Object{"
            "@{sid=$_.IdentityReference.Translate("
            "[Security.Principal.SecurityIdentifier]"
            ").Value;"
            "type=[string]$_.AccessControlType;"
            "rights=[string]$_.FileSystemRights;"
            "inheritance=[string]$_.InheritanceFlags;"
            "propagation=[string]$_.PropagationFlags;"
            "inherited=[bool]$_.IsInherited}});"
            "$raw=New-Object Security.AccessControl"
            ".RawSecurityDescriptor($a.Sddl);"
            "$owner=$raw.Owner.Value;"
            "@{owner=$owner;"
            "protected=$a.AreAccessRulesProtected;"
            "rules=$rules}|"
            "ConvertTo-Json -Depth 4 -Compress",
            str(path),
        )

    def _ordinary_tree(
        self,
        path: Path,
    ) -> tuple[Path, ...]:
        pending = [path]
        result = []
        while pending:
            item = pending.pop()
            info = item.lstat()
            if (
                item.is_symlink()
                or getattr(
                    info,
                    "st_file_attributes",
                    0,
                ) & 0x400
            ):
                raise RuntimeError(
                    "backup_tree_reparse_entry"
                )
            result.append(item)
            if item.is_dir():
                pending.extend(item.iterdir())
        return tuple(
            sorted(
                result,
                key=lambda value: (
                    str(value).casefold()
                ),
            )
        )

    def restrict_backup_tree(
        self,
        path: Path,
    ) -> None:
        user_sid = self._current_sid()
        for item in self._ordinary_tree(path):
            grant = (
                "(OI)(CI)F"
                if item.is_dir()
                else "F"
            )
            commands = (
                [
                    str(ICACLS),
                    str(item),
                    "/inheritance:r",
                    "/C",
                ],
                [
                    str(ICACLS),
                    str(item),
                    "/grant:r",
                    f"*{user_sid}:{grant}",
                    f"*S-1-5-18:{grant}",
                    "/C",
                ],
                [
                    str(ICACLS),
                    str(item),
                    "/setowner",
                    f"*{user_sid}",
                    "/C",
                ],
            )
            for command in commands:
                result = self._runner(
                    command,
                    check=False,
                    capture_output=True,
                    creationflags=getattr(
                        subprocess,
                        "CREATE_NO_WINDOW",
                        0,
                    ),
                )
                if result.returncode != 0:
                    raise RuntimeError(
                        "backup_acl_restriction_failed"
                    )

    def verify_restricted_backup_tree(
        self,
        path: Path,
    ) -> None:
        user_sid = self._current_sid()
        for item in self._ordinary_tree(path):
            inheritance = (
                "ContainerInherit, ObjectInherit"
                if item.is_dir()
                else "None"
            )
            expected = {
                (
                    user_sid,
                    "Allow",
                    "FullControl",
                    inheritance,
                    "None",
                    False,
                ),
                (
                    "S-1-5-18",
                    "Allow",
                    "FullControl",
                    inheritance,
                    "None",
                    False,
                ),
            }
            value = self._acl_rules(item)
            rules = value["rules"]
            if isinstance(rules, dict):
                rules = [rules]
            actual = {
                (
                    rule["sid"],
                    rule["type"],
                    rule["rights"],
                    rule["inheritance"],
                    rule["propagation"],
                    rule["inherited"],
                )
                for rule in rules
            }
            if (
                not value["protected"]
                or value["owner"] != user_sid
                or len(rules) != 2
                or actual != expected
            ):
                raise RuntimeError(
                    "backup_acl_verification_failed"
                )

    def restrict_local_trust_artifact(
        self,
        path: Path,
    ) -> None:
        information = path.lstat()
        if (
            path.is_symlink()
            or getattr(information, "st_file_attributes", 0) & 0x400
            or not (path.is_dir() or path.is_file())
        ):
            raise RuntimeError("local_trust_artifact_not_single")
        user_sid = self._current_sid()
        grant = "(OI)(CI)F" if path.is_dir() else "F"
        commands = (
            [str(ICACLS), str(path), "/inheritance:r", "/C"],
            [
                str(ICACLS),
                str(path),
                "/grant:r",
                f"*{user_sid}:{grant}",
                f"*S-1-5-18:{grant}",
                "/C",
            ],
            [
                str(ICACLS),
                str(path),
                "/setowner",
                f"*{user_sid}",
                "/C",
            ],
        )
        for command in commands:
            result = self._runner(
                command,
                check=False,
                capture_output=True,
                creationflags=getattr(
                    subprocess, "CREATE_NO_WINDOW", 0
                ),
            )
            if result.returncode != 0:
                raise RuntimeError(
                    "local_trust_acl_restriction_failed"
                )

    def verify_local_trust_artifact(
        self,
        path: Path,
    ) -> None:
        information = path.lstat()
        if (
            path.is_symlink()
            or getattr(information, "st_file_attributes", 0) & 0x400
            or not (path.is_dir() or path.is_file())
        ):
            raise RuntimeError("local_trust_artifact_not_single")
        user_sid = self._current_sid()
        inheritance = (
            "ContainerInherit, ObjectInherit"
            if path.is_dir()
            else "None"
        )
        expected = {
            (
                user_sid,
                "Allow",
                "FullControl",
                inheritance,
                "None",
                False,
            ),
            (
                "S-1-5-18",
                "Allow",
                "FullControl",
                inheritance,
                "None",
                False,
            ),
        }
        value = self._acl_rules(path)
        rules = value["rules"]
        if isinstance(rules, dict):
            rules = [rules]
        actual = {
            (
                rule["sid"],
                rule["type"],
                rule["rights"],
                rule["inheritance"],
                rule["propagation"],
                rule["inherited"],
            )
            for rule in rules
        }
        if (
            not value["protected"]
            or value["owner"] != user_sid
            or len(rules) != 2
            or actual != expected
        ):
            raise RuntimeError(
                "local_trust_acl_verification_failed"
            )

    def restore(
        self,
        path: Path,
        value: SecurityMetadata,
    ) -> None:
        self._probe(
            "$a=Get-Acl -LiteralPath $args[0];"
            "$a.SetSecurityDescriptorSddlForm("
            "$args[1]);"
            "Set-Acl -LiteralPath $args[0] "
            "-AclObject $a;"
            "@{ok=$true}|ConvertTo-Json -Compress",
            str(path),
            value.dacl_sddl,
        )
        if not self._set_attributes(
            str(path),
            value.file_attributes,
        ):
            raise ctypes.WinError()

    def verify(
        self,
        path: Path,
        value: SecurityMetadata,
    ) -> None:
        current = self.capture(path)
        if current != value:
            raise RuntimeError(
                "security_metadata_verification_failed"
            )

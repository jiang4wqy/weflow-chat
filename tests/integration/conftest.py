from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Callable
import uuid

import pytest

from tests.fakes import SyntheticFaultController, build_synthetic_flow
from weflow_chat.orchestrator import (
    RefreshOrchestrator,
    RefreshStage,
    RunRecord,
)


SNAPSHOTS_ROOT = Path("synthetic-snapshots-root")
_SOURCE_ACCOUNT_NAME = "wxid_test_snapshot"
_HEX64 = re.compile(r"^[0-9A-F]{64}$")


def _is_reparse(path: Path) -> bool:
    info = path.lstat()
    return path.is_symlink() or bool(
        getattr(info, "st_file_attributes", 0)
        & stat.FILE_ATTRIBUTE_REPARSE_POINT
    )


def _identity(path: Path) -> tuple[int, int]:
    info = path.lstat()
    return info.st_dev, info.st_ino


def _create_owned_run_root(
    *,
    snapshots_root: Path,
    name: str,
    pin_directory,
    secure,
):
    lexical = snapshots_root.absolute()
    if (
        not lexical.exists()
        or not lexical.is_dir()
        or _is_reparse(lexical)
        or lexical.resolve(strict=True) != lexical
    ):
        raise AssertionError("synthetic_snapshots_root_rejected")
    run_root = lexical / name
    run_root.mkdir(exist_ok=False)
    created_identity = _identity(run_root)
    pin_context = pin_directory(run_root)
    pin = None
    try:
        pin = pin_context.__enter__()
        pin.verify()
        if _identity(run_root) != created_identity:
            raise AssertionError("synthetic_run_identity_changed")
        secure(run_root, pin)
        pin.verify()
        if _identity(run_root) != created_identity:
            raise AssertionError("synthetic_run_identity_changed")
        return run_root, created_identity, pin_context, pin
    except Exception:
        if pin is not None:
            pin_context.__exit__(None, None, None)
        if (
            os.path.lexists(run_root)
            and _identity(run_root) == created_identity
            and not tuple(run_root.iterdir())
        ):
            run_root.rmdir()
        raise


def _delete_empty_pinned_root(run_root: Path, pin) -> bool:
    if os.name != "nt":
        return False
    handle = getattr(pin, "handle", None)
    if handle is None:
        raise AssertionError("synthetic_cleanup_pin_missing")

    class _FileDispositionInfo(ctypes.Structure):
        _fields_ = [("delete_file", ctypes.c_ubyte)]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    set_information = kernel32.SetFileInformationByHandle
    set_information.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    set_information.restype = wintypes.BOOL
    information = _FileDispositionInfo(1)
    if not set_information(
        handle,
        4,
        ctypes.byref(information),
        ctypes.sizeof(information),
    ):
        raise AssertionError("synthetic_cleanup_disposition_failed")
    return True


def _assert_no_reparse_chain(path: Path) -> None:
    absolute = path.absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        if not os.path.lexists(current):
            raise RuntimeError("required_gate_path_missing")
        if _is_reparse(current):
            raise RuntimeError("real_gate_reparse_rejected")


def _assert_regular_file(path: Path) -> None:
    _assert_no_reparse_chain(path)
    if not stat.S_ISREG(path.lstat().st_mode):
        raise RuntimeError("required_gate_file_invalid")


def _strict_gate_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise RuntimeError("real_gate_json_duplicate_key")
        value[key] = item
    return value


def _iter_gate_strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _iter_gate_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _iter_gate_strings(item)


def _read_stable_gate_json(path: Path):
    from weflow_chat.manifest import _read_bounded_ordinary_file

    _assert_regular_file(path)
    try:
        payload = _read_bounded_ordinary_file(path)
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_strict_gate_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                RuntimeError("real_gate_json_nonfinite")
            ),
        )
    except RuntimeError:
        raise
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise RuntimeError("real_gate_json_invalid") from error
    return payload, value


def _ordinary_child_names(parent: Path) -> set[str]:
    names = set()
    with os.scandir(parent) as entries:
        for entry in entries:
            info = entry.stat(follow_symlinks=False)
            if (
                entry.is_symlink()
                or getattr(info, "st_file_attributes", 0)
                & stat.FILE_ATTRIBUTE_REPARSE_POINT
                or not entry.is_dir(follow_symlinks=False)
            ):
                raise RuntimeError("role_account_layout_mismatch")
            names.add(entry.name)
    return names


def _assert_role_account_layout(
    role_root: Path, source_account_name: str
) -> Path:
    if (
        re.fullmatch(
            r"wxid_[A-Za-z0-9_]{1,128}", source_account_name
        )
        is None
    ):
        raise RuntimeError("source_account_name_invalid")
    account_root = role_root / source_account_name
    db_storage = account_root / "db_storage"
    for path in (role_root, account_root, db_storage):
        _assert_no_reparse_chain(path)
    if (
        _ordinary_child_names(role_root) != {source_account_name}
        or _ordinary_child_names(account_root) != {"db_storage"}
        or not stat.S_ISDIR(db_storage.lstat().st_mode)
    ):
        raise RuntimeError("role_account_layout_mismatch")
    return db_storage


def _read_exact_run_manifest(layout, expected_run_id: str):
    from weflow_chat import __version__
    from weflow_chat.manifest import (
        ResidualRisk,
        SnapshotMethod,
        build_manifest,
        read_run_manifest,
    )
    from weflow_chat.models import CopyRole

    for path in (
        layout.root,
        layout.manifest_path,
        layout.source,
        layout.validation,
        layout.active,
    ):
        _assert_no_reparse_chain(path)
    for role_root in (
        layout.source,
        layout.validation,
        layout.active,
    ):
        _assert_role_account_layout(
            role_root, _SOURCE_ACCOUNT_NAME
        )
    before_payload, before_raw = _read_stable_gate_json(
        layout.manifest_path
    )
    if not isinstance(before_raw, dict):
        raise RuntimeError("run_manifest_contract_mismatch")
    persisted, receipt = read_run_manifest(
        layout,
        expected_run_id=expected_run_id,
        expected_source_account_name=_SOURCE_ACCOUNT_NAME,
    )
    after_payload, after_raw = _read_stable_gate_json(
        layout.manifest_path
    )
    if before_payload != after_payload or before_raw != after_raw:
        raise RuntimeError("run_manifest_changed_during_read")
    try:
        captured = datetime.fromisoformat(
            persisted.captured_at_utc.replace("Z", "+00:00")
        )
        shadow = str(uuid.UUID(persisted.shadow_id.strip("{}")))
    except (ValueError, AttributeError) as error:
        raise RuntimeError("run_manifest_identity_invalid") from error
    if (
        persisted.schema_version != 1
        or persisted.tool_version != __version__
        or persisted.run_id != expected_run_id
        or not persisted.captured_at_utc.endswith("Z")
        or captured.tzinfo is None
        or captured.utcoffset() != timezone.utc.utcoffset(captured)
        or persisted.source_volume != "F:\\"
        or shadow != persisted.shadow_id.strip("{}").lower()
        or not _HEX64.fullmatch(persisted.staging_manifest_sha256)
        or persisted.snapshot_method
        is not SnapshotMethod.VSS_CRASH_CONSISTENT
        or persisted.residual_risk
        is not ResidualRisk.NO_CROSS_DATABASE_ATOMICITY_PROOF
        or not _HEX64.fullmatch(receipt.canonical_sha256)
        or not _HEX64.fullmatch(receipt.source_content_sha256)
    ):
        raise RuntimeError("run_manifest_contract_mismatch")
    actual = build_manifest(layout.source, role=CopyRole.SOURCE)
    expected_prefix = f"{_SOURCE_ACCOUNT_NAME}/db_storage/"
    if (
        not persisted.source.files
        or any(
            not item.relative_path.startswith(expected_prefix)
            for item in persisted.source.files
        )
        or persisted.source != actual
    ):
        raise RuntimeError("source_manifest_content_mismatch")
    return persisted


def _find_real_layout(run_id: str):
    from weflow_chat.paths import RunLayout

    _assert_no_reparse_chain(SNAPSHOTS_ROOT)
    if not SNAPSHOTS_ROOT.is_dir():
        raise RuntimeError("snapshots_root_invalid")
    suffix = f"-{run_id}"
    allowed_name = re.compile(
        rf"^[A-Za-z0-9._-]{{1,160}}{re.escape(suffix)}$"
    )
    matches = []
    with os.scandir(SNAPSHOTS_ROOT) as entries:
        for entry in entries:
            if not entry.name.endswith(suffix):
                continue
            child = Path(entry.path)
            info = child.lstat()
            if (
                allowed_name.fullmatch(entry.name) is None
                or entry.is_symlink()
                or getattr(info, "st_file_attributes", 0)
                & stat.FILE_ATTRIBUTE_REPARSE_POINT
                or not stat.S_ISDIR(info.st_mode)
            ):
                raise RuntimeError("real_run_candidate_invalid")
            matches.append((child, (info.st_dev, info.st_ino)))
    if len(matches) != 1:
        raise RuntimeError("real_run_manifest_not_unique")
    child, identity = matches[0]
    _assert_no_reparse_chain(child)
    if _identity(child) != identity:
        raise RuntimeError("real_run_identity_changed")
    return RunLayout.from_existing_root(child), identity


class RealRun:
    def assert_validator_never_received_source_path(self) -> None:
        requests = self.validator.request_audit[
            self.request_audit_start :
        ]
        assert len(requests) == 2
        for request in requests:
            assert set(request) == {"operation", "runId", "area"}
            assert request == {
                "operation": "validate-snapshot",
                "runId": self.run_id,
                "area": request["area"],
            }
            assert request["area"] in {"validation", "active"}
            assert all(
                "source" not in str(value).casefold()
                for value in request.values()
            )
        attempts = self.validator.attempt_audit[
            self.attempt_audit_start :
        ]
        assert len(attempts) == 2
        assert {item["area"] for item in attempts} == {
            "validation",
            "active",
        }
        source_text = str(self.layout.source).casefold()
        for attempt in attempts:
            area = attempt["area"]
            attempt_root = Path(attempt["attemptRoot"])
            config_path = Path(attempt["configPath"])
            request_path = attempt_root / "request" / "request.json"
            assert attempt == {
                "area": area,
                "attemptRoot": str(attempt_root),
                "configPath": str(config_path),
                "effectiveDbPath": str(getattr(self.layout, area)),
                "effectiveCachePath": str(attempt_root / "cache"),
                "sourcePathAbsent": True,
                "changedFields": ("dbPath", "cachePath"),
                "sourceSha256": attempt["sourceSha256"],
                "destinationSha256": attempt["destinationSha256"],
            }
            assert all(
                isinstance(attempt[name], str)
                and _HEX64.fullmatch(attempt[name])
                for name in ("sourceSha256", "destinationSha256")
            )
            assert all(
                source_text not in value.casefold()
                for value in attempt.values()
                if isinstance(value, str)
            )
            assert config_path == (
                attempt_root / "profile" / "WeFlow-config.json"
            )
            config_payload, config = _read_stable_gate_json(config_path)
            assert hashlib.sha256(config_payload).hexdigest().upper() == (
                attempt["destinationSha256"]
            )
            assert isinstance(config, dict)
            assert config.get("dbPath") == str(getattr(self.layout, area))
            assert config.get("cachePath") == str(attempt_root / "cache")
            assert all(
                source_text not in value.casefold()
                for value in _iter_gate_strings(config)
            )
            _request_payload, request = _read_stable_gate_json(request_path)
            assert request == {
                "operation": "validate-snapshot",
                "runId": self.run_id,
                "area": area,
            }


def _tree_hashes(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(
            path.read_bytes()
        ).hexdigest().upper()
        for path in sorted(item for item in root.rglob("*") if item.is_file())
    }


@dataclass(slots=True)
class SyntheticRefreshHarness:
    flow: RefreshOrchestrator
    faults: SyntheticFaultController
    flow_factory: Callable[[str], RefreshOrchestrator]
    source_hashes: dict[str, str]
    formal_hashes: dict[str, str]
    last_rollback_db_path: str | None = None

    def run(self, *, ui_response: str | None = None) -> RunRecord:
        try:
            self.flow.prepare_snapshot()
            if self.flow.stage is RefreshStage.COMPATIBILITY_BLOCKED:
                return self.flow.record
            validation = self.flow.validate_copies()
            if validation.status != "ok":
                return self.flow.record
            prepared = self.flow.prepare_cutover()
            if prepared.stage is not RefreshStage.CONFIG_REPLACED:
                return prepared
            self.flow.launch_formal_for_ui()
            confirmed = self.flow.record_ui_confirmation(ui_response or "")
            if confirmed.stage is RefreshStage.UI_CONFIRMED:
                return self.flow.finalize()
            return confirmed
        except BaseException as error:
            return self.flow.recover_after_exception(error)

    def run_successfully(self, *, timestamp: str) -> RunRecord:
        current = json.loads(
            (
                self.faults.production_root / "WeFlow-config.json"
            ).read_text(encoding="utf-8")
        )
        self.last_rollback_db_path = current["dbPath"]
        self.faults.active = None
        self.flow = self.flow_factory(timestamp)
        return self.run(ui_response=f"CONFIRM {self.flow.run_id}")

    def inject_fault(self, name: str) -> None:
        self.faults.active = name

    def assert_source_unchanged(self) -> None:
        assert _tree_hashes(self.flow.layout.source) == self.source_hashes

    def assert_complete_old_fileset(self) -> None:
        self.faults.assert_complete_old_fileset()

    def assert_no_real_host_paths_touched(self) -> None:
        self.faults.assert_no_production_paths()


@pytest.fixture
def synthetic_refresh(tmp_path: Path) -> SyntheticRefreshHarness:
    faults = SyntheticFaultController(tmp_path)
    try:
        def factory(stamp: str) -> RefreshOrchestrator:
            return build_synthetic_flow(
                tmp_path=tmp_path,
                timestamp=stamp,
                faults=faults,
            )

        flow = factory("20260721-110000")
        flow.prepare_snapshot()
        source_hashes = _tree_hashes(flow.layout.source)
        flow = factory("20260721-110001")
        yield SyntheticRefreshHarness(
            flow=flow,
            faults=faults,
            flow_factory=factory,
            source_hashes=source_hashes,
            formal_hashes=faults.capture_formal_hashes(),
        )
    finally:
        faults.close()

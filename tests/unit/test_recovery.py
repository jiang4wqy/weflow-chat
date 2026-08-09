from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from weflow_chat.atomic_io import atomic_write_bytes
from weflow_chat.config import PreparedChange
from weflow_chat.models import PlannedFile, TxState
from weflow_chat.recovery import (
    ExactDeleteError,
    LiveHashState,
    RecoveryAction,
    RestorePlanError,
    build_restore_plan,
    choose_recovery_action,
    classify_live_hashes,
    execute_cutover,
    read_current_hashes,
    recover_transaction,
    remove_new_file_exact,
    sha256_bytes,
)
from weflow_chat.security import (
    BackupBundle,
    BackupItem,
    BackupReceipt,
    SecurityMetadata,
)
from weflow_chat.transaction import (
    ConservativeTransactionView,
    MirrorWriteError,
    TransactionRecord,
)


def _record(*, state, planned_files=(), sequence=5):
    return TransactionRecord(
        schema_version=1,
        run_id="11111111-1111-1111-1111-111111111111",
        sequence=sequence,
        state=state,
        shadow_id="{22222222-2222-2222-2222-222222222222}",
        shadow_source_volume="F:\\",
        planned_files=tuple(planned_files),
        backup_manifest_sha256="C" * 64 if planned_files else None,
        backup_primary_manifest_path="primary-manifest" if planned_files else None,
        backup_recovery_manifest_path="recovery-manifest" if planned_files else None,
        source_manifest_sha256="D" * 64 if planned_files else None,
        active_manifest_sha256="D" * 64 if planned_files else None,
    )


def test_no_live_change_before_both_mirrors_replacing(tmp_path):
    config = tmp_path / "WeFlow-config.json"
    config.write_bytes(b"old")
    canonical = str(config.resolve())
    planned = PlannedFile(canonical, "replace", True, sha256_bytes(b"old"),
                          sha256_bytes(b"new"))
    record = _record(state=TxState.PREPARED, planned_files=(planned,),
                     sequence=5)
    change = PreparedChange(canonical, "replace", b"new",
                            planned.expected_old_sha256,
                            planned.expected_new_sha256)
    bundle = Mock(
        items=(SimpleNamespace(live_path=canonical),),
        receipt=SimpleNamespace(canonical_sha256="C" * 64,
                                primary_manifest_path="primary-manifest",
                                recovery_manifest_path="recovery-manifest"),
    )
    store = Mock()
    store.read_equal.return_value = SimpleNamespace(record=record)
    store.transition.side_effect = MirrorWriteError("synthetic")
    before = config.read_bytes()
    with pytest.raises(MirrorWriteError):
        execute_cutover((change,), bundle=bundle, store=store,
                        security_adapter=Mock(),
                        audit_path=tmp_path / "audit.jsonl")
    assert config.read_bytes() == before


def test_classify_live_hashes_detects_old_new_mix():
    first = PlannedFile("one", "replace", True, "OLD1", "NEW1")
    second = PlannedFile("two", "replace", True, "OLD2", "NEW2")
    assert classify_live_hashes((first, second),
                                {"one": "OLD1", "two": "NEW2"}) is (
        LiveHashState.MIXED)


@pytest.mark.parametrize("hash_state", [
    LiveHashState.ALL_OLD, LiveHashState.MIXED, LiveHashState.UNKNOWN,
])
def test_accepted_can_revalidate_only_from_all_new(hash_state):
    planned = PlannedFile("one", "replace", True, "A" * 64, "B" * 64)
    view = ConservativeTransactionView(_record(state=TxState.ACCEPTED,
                                                planned_files=(planned,),
                                                sequence=8), False, False)
    assert choose_recovery_action(view, hash_state) is RecoveryAction.FULL_ROLLBACK


def test_accepted_all_new_selects_fresh_revalidation():
    planned = PlannedFile("one", "replace", True, "A" * 64, "B" * 64)
    view = ConservativeTransactionView(_record(state=TxState.ACCEPTED,
                                                planned_files=(planned,),
                                                sequence=8), False, False)
    assert choose_recovery_action(view, LiveHashState.ALL_NEW) is (
        RecoveryAction.REVALIDATE_ACCEPTED)


def test_exact_delete_rejects_outside_or_hash_mismatch(tmp_path):
    allowed = tmp_path / "analytics_cache.json"
    allowed.write_bytes(b"unexpected")
    planned = PlannedFile(str(allowed.resolve()), "delete_if_created", False,
                          None, sha256_bytes(b"expected"))
    known = frozenset({str(allowed.resolve())})
    with pytest.raises(ExactDeleteError, match="hash_mismatch"):
        remove_new_file_exact(planned, allowed, known_live_paths=known)
    outside = tmp_path / "outside.json"
    outside.write_bytes(b"expected")
    with pytest.raises(ExactDeleteError, match="unplanned_path"):
        remove_new_file_exact(planned, outside, known_live_paths=known)
    assert allowed.exists() and outside.exists()


def test_exact_delete_removes_only_matching_created_file(tmp_path):
    created = tmp_path / "analytics_cache.json"
    created.write_bytes(b"derived")
    canonical = str(created.resolve())
    planned = PlannedFile(canonical, "delete_if_created", False, None,
                          sha256_bytes(b"derived"))
    remove_new_file_exact(planned, created,
                          known_live_paths=frozenset({canonical}))
    assert not created.exists()


def test_current_hash_reader_rejects_broken_reparse_as_missing(tmp_path,
                                                                monkeypatch):
    missing = tmp_path / "analytics_cache.json"
    planned = PlannedFile(str(missing.resolve()), "delete_if_created", False,
                          None, None)
    monkeypatch.setattr("weflow_chat.recovery.os.path.lexists",
                        lambda value: str(value) == planned.live_path)
    with pytest.raises(ExactDeleteError, match="reparse_or_dangling"):
        read_current_hashes((planned,))


class StoppedProcessGate:
    def request_normal_close_and_wait(self, timeout_seconds):
        return True


class RestoreSecurityAdapter:
    def __init__(self, restricted):
        self.restricted = {str(path.resolve()) for path in restricted}
        self.values = {}

    def verify_restricted_backup_tree(self, path):
        if str(path.resolve()) not in self.restricted:
            raise PermissionError("backup_acl_not_restricted")

    def restore(self, path, value):
        self.values[str(path.resolve())] = value

    def verify(self, path, value):
        if self.values.get(str(path.resolve())) != value:
            raise PermissionError("restored_acl_mismatch")


class StatefulRecoveryStore:
    def __init__(self, tmp_path, record):
        self.primary_path = tmp_path / "e-tx" / "transaction.json"
        self.recovery_path = tmp_path / "c-tx" / "transaction.json"
        self.record = record
        self._storage_available = lambda _: True

    def inspect_conservative(self):
        return ConservativeTransactionView(self.record, False, True)

    def force_conservative_state(self, target):
        self.record = replace(self.record, sequence=self.record.sequence + 1,
                              state=target)
        return self.record


def make_two_file_restore(tmp_path):
    live_root = tmp_path / "live"
    primary_root = tmp_path / "e-backup"
    recovery_root = tmp_path / "c-backup"
    for root in (live_root, primary_root, recovery_root):
        root.mkdir()
    old = {"first.json": b"old-first", "second.json": b"old-second"}
    new = {"first.json": b"new-first", "second.json": b"new-second"}
    metadata = SecurityMetadata(32, "S-1-5-21-test", "S-1-5-18",
                                "D:synthetic")
    items, planned = [], []
    for name in old:
        live = live_root / name
        primary, recovery = primary_root / name, recovery_root / name
        live.write_bytes(new[name])
        primary.write_bytes(old[name])
        recovery.write_bytes(old[name])
        items.append(BackupItem(str(live.resolve()), True,
                                str(primary.resolve()), str(recovery.resolve()),
                                sha256_bytes(old[name]), metadata))
        planned.append(PlannedFile(str(live.resolve()), "replace", True,
                                   sha256_bytes(old[name]),
                                   sha256_bytes(new[name])))
    run_id = "11111111-1111-1111-1111-111111111111"
    receipt = BackupReceipt(run_id,
        str((primary_root / "backup-manifest.json").resolve()),
        str((recovery_root / "backup-manifest.json").resolve()), "C" * 64, 2)
    bundle = BackupBundle(run_id, tuple(items), str(primary_root.resolve()),
                          str(recovery_root.resolve()), receipt)
    record = _record(state=TxState.REPLACING, planned_files=tuple(planned),
                     sequence=6)
    record = replace(record,
                     backup_primary_manifest_path=receipt.primary_manifest_path,
                     backup_recovery_manifest_path=receipt.recovery_manifest_path)
    security = RestoreSecurityAdapter((primary_root, recovery_root))
    return live_root, old, new, bundle, record, security


@pytest.mark.parametrize("corruption", [
    "planned_path", "existence", "action", "old_hash", "security",
    "backup_copy",
])
def test_complete_restore_plan_rejects_second_binding_before_any_write(
        tmp_path, corruption):
    live_root, old, _new, bundle, record, security = make_two_file_restore(tmp_path)
    items, planned = list(bundle.items), list(record.planned_files)
    if corruption == "planned_path":
        planned[1] = replace(planned[1], live_path=str(live_root / ".." / "x.json"))
    elif corruption == "existence":
        items[1] = replace(items[1], existed_before=False)
    elif corruption == "action":
        planned[1] = replace(planned[1], action="delete_if_created",
                             existed_before=False, expected_old_sha256=None)
    elif corruption == "old_hash":
        planned[1] = replace(planned[1], expected_old_sha256="F" * 64)
    elif corruption == "security":
        items[1] = replace(items[1], security=None)
    else:
        Path(items[1].primary_backup_path).write_bytes(b"corrupt")
        Path(items[1].recovery_backup_path).write_bytes(b"corrupt")
    before = {path.name: path.read_bytes() for path in live_root.iterdir()}
    with pytest.raises(RestorePlanError):
        build_restore_plan(replace(record, planned_files=tuple(planned)),
                           replace(bundle, items=tuple(items)), security)
    assert {path.name: path.read_bytes() for path in live_root.iterdir()} == before


def test_second_restore_write_failure_persists_pending_then_retries(tmp_path):
    live_root, old, new, bundle, record, security = make_two_file_restore(tmp_path)
    store = StatefulRecoveryStore(tmp_path, record)
    second, failed = (live_root / "second.json").resolve(), False

    def fail_second_once(path, payload):
        nonlocal failed
        if path == second and not failed:
            failed = True
            raise PermissionError("synthetic_second_acl_failure")
        atomic_write_bytes(path, payload)

    first = recover_transaction(store=store, bundle=bundle,
                                process_gate=StoppedProcessGate(),
                                security_adapter=security,
                                accepted_revalidator=lambda *_: False,
                                timeout_seconds=1.0,
                                audit_path=tmp_path / "audit.jsonl",
                                restore_bytes=fail_second_once)
    assert first.state is TxState.RECOVERY_PENDING
    assert (live_root / "first.json").read_bytes() == old["first.json"]
    assert (live_root / "second.json").read_bytes() == new["second.json"]
    result = recover_transaction(store=store, bundle=bundle,
                                 process_gate=StoppedProcessGate(),
                                 security_adapter=security,
                                 accepted_revalidator=lambda *_: False,
                                 timeout_seconds=1.0,
                                 audit_path=tmp_path / "audit.jsonl",
                                 restore_bytes=fail_second_once)
    assert result.state is TxState.ROLLED_BACK
    assert all((live_root / name).read_bytes() == value for name, value in old.items())


def test_structural_second_backup_failure_is_pending_with_zero_live_writes(tmp_path):
    live_root, _old, new, bundle, record, security = make_two_file_restore(tmp_path)
    second = bundle.items[1]
    Path(second.primary_backup_path).write_bytes(b"corrupt")
    Path(second.recovery_backup_path).write_bytes(b"corrupt")
    result = recover_transaction(store=StatefulRecoveryStore(tmp_path, record),
                                 bundle=bundle, process_gate=StoppedProcessGate(),
                                 security_adapter=security,
                                 accepted_revalidator=lambda *_: False,
                                 timeout_seconds=1.0,
                                 audit_path=tmp_path / "audit.jsonl")
    assert result.state is TxState.RECOVERY_PENDING
    assert all((live_root / name).read_bytes() == value for name, value in new.items())


def test_running_process_sets_recovery_pending(tmp_path):
    record = _record(state=TxState.REPLACING)
    pending = replace(record, sequence=record.sequence + 1,
                      state=TxState.RECOVERY_PENDING)
    store = Mock()
    store.inspect_conservative.return_value = ConservativeTransactionView(record, False, True)
    store.force_conservative_state.return_value = pending
    gate = Mock()
    gate.request_normal_close_and_wait.return_value = False
    result = recover_transaction(store=store, bundle=Mock(), process_gate=gate,
                                 security_adapter=Mock(),
                                 accepted_revalidator=lambda *_: False,
                                 timeout_seconds=1.0,
                                 audit_path=tmp_path / "audit.jsonl")
    assert result.state is TxState.RECOVERY_PENDING


def test_offline_primary_audit_falls_back_to_recovery_without_recreating_primary(
        tmp_path):
    offline_primary = tmp_path / "offline-primary"
    recovery_parent = tmp_path / "recovery"
    record = _record(state=TxState.REPLACING)
    pending = replace(record, sequence=record.sequence + 1,
                      state=TxState.RECOVERY_PENDING)
    store = Mock()
    store.primary_path = offline_primary / "transaction.json"
    store.recovery_path = recovery_parent / "transaction.json"
    store._storage_available.side_effect = (
        lambda path: path != offline_primary)
    store.inspect_conservative.return_value = ConservativeTransactionView(
        record, False, True)
    store.force_conservative_state.return_value = pending
    gate = Mock()
    gate.request_normal_close_and_wait.return_value = False

    result = recover_transaction(
        store=store, bundle=Mock(), process_gate=gate,
        security_adapter=Mock(), accepted_revalidator=lambda *_: False,
        timeout_seconds=1.0, audit_path=offline_primary / "audit.jsonl")

    assert result.state is TxState.RECOVERY_PENDING
    assert (recovery_parent / "recovery-audit.jsonl").exists()
    assert not offline_primary.exists()


def test_process_gate_exception_sets_pending_without_live_touch(tmp_path):
    live = tmp_path / "WeFlow-config.json"
    live.write_bytes(b"unchanged")
    record = _record(state=TxState.REPLACING)
    pending = replace(record, sequence=record.sequence + 1,
                      state=TxState.RECOVERY_PENDING)
    store = Mock()
    store.inspect_conservative.return_value = ConservativeTransactionView(
        record, False, True)
    store.force_conservative_state.return_value = pending
    gate = Mock()
    gate.request_normal_close_and_wait.side_effect = RuntimeError(
        "synthetic_process_probe_failure")

    result = recover_transaction(
        store=store, bundle=Mock(), process_gate=gate,
        security_adapter=Mock(), accepted_revalidator=lambda *_: False,
        timeout_seconds=1.0, audit_path=tmp_path / "audit.jsonl")

    assert result.state is TxState.RECOVERY_PENDING
    assert live.read_bytes() == b"unchanged"
    store.force_conservative_state.assert_called_once_with(
        TxState.RECOVERY_PENDING)
    assert "process_running" in (tmp_path / "audit.jsonl").read_text(
        encoding="utf-8")


@pytest.mark.parametrize("mismatch", ["action", "old_hash", "new_hash"])
def test_cutover_rejects_change_plan_binding_before_replacing(tmp_path,
                                                              mismatch):
    live = tmp_path / "WeFlow-config.json"
    live.write_bytes(b"old")
    canonical = str(live.resolve())
    old_hash = sha256_bytes(b"old")
    new_hash = sha256_bytes(b"new")
    planned = PlannedFile(canonical, "replace", True, old_hash, new_hash)
    record = _record(state=TxState.PREPARED, planned_files=(planned,),
                     sequence=5)
    if mismatch == "action":
        change = PreparedChange(canonical, "delete", None, old_hash, None)
    elif mismatch == "old_hash":
        change = PreparedChange(canonical, "replace", b"new", "F" * 64,
                                new_hash)
    else:
        change = PreparedChange(canonical, "replace", b"new", old_hash,
                                "F" * 64)
    bundle = Mock(
        items=(SimpleNamespace(live_path=canonical),),
        receipt=SimpleNamespace(canonical_sha256="C" * 64,
                                primary_manifest_path="primary-manifest",
                                recovery_manifest_path="recovery-manifest"),
    )
    store = Mock()
    store.read_equal.return_value = SimpleNamespace(record=record)

    with pytest.raises(ValueError, match="cutover_change_set_mismatch"):
        execute_cutover((change,), bundle=bundle, store=store,
                        security_adapter=Mock(),
                        audit_path=tmp_path / "audit.jsonl")

    assert live.read_bytes() == b"old"
    store.transition.assert_not_called()

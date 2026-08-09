from dataclasses import replace
import json
from types import SimpleNamespace

import pytest

from weflow_chat.atomic_io import atomic_write_json
from weflow_chat.models import CopyRole, PlannedFile, TxState
from weflow_chat.transaction import (
    InvalidTransitionError, MirrorDivergenceError, MirrorWriteError,
    MirroredTransactionStore, TransactionRecord,
    _record_json,
)

def make_record(state: TxState, *, sequence: int) -> TransactionRecord:
    shadowed = state is not TxState.DISCOVERED
    record = TransactionRecord(
        schema_version=1,
        run_id="11111111-1111-1111-1111-111111111111",
        sequence=sequence, state=state, shadow_id=None,
        shadow_source_volume=None, planned_files=(), applied_files=())
    if shadowed:
        record = replace(
            record,
            shadow_id="{22222222-2222-2222-2222-222222222222}",
            shadow_source_volume="F:\\")
    if state in {
            TxState.PREPARED, TxState.REPLACING,
            TxState.CONFIG_REPLACED, TxState.ACCEPTED,
            TxState.COMMITTED}:
        record = replace(
            record,
            planned_files=(PlannedFile(
                live_path=r"C:\synthetic\WeFlow-config.json",
                action="replace", existed_before=True,
                expected_old_sha256="A" * 64,
                expected_new_sha256="B" * 64),),
            backup_manifest_sha256="C" * 64,
            backup_primary_manifest_path=
                r"E:\run\config-backup\backup-manifest.json",
            backup_recovery_manifest_path=
                r"C:\recovery\backup-manifest.json",
            source_manifest_sha256="D" * 64,
            active_manifest_sha256="D" * 64,
            presentation_manifest_sha256="E" * 64,
            media_store_manifest_sha256="F" * 64)
    if state in {
            TxState.CONFIG_REPLACED, TxState.ACCEPTED,
            TxState.COMMITTED}:
        record = replace(
            record,
            applied_files=(record.planned_files[0].live_path,))
    if state in {TxState.ACCEPTED, TxState.COMMITTED}:
        record = replace(record, acceptance_sha256="9" * 64)
    return record

@pytest.fixture
def discovered_record():
    return make_record(TxState.DISCOVERED, sequence=0)

@pytest.fixture
def prepared_record():
    return make_record(TxState.PREPARED, sequence=5)

@pytest.fixture
def committed_record():
    return make_record(TxState.COMMITTED, sequence=10)

@pytest.fixture
def transaction_store(tmp_path):
    return MirroredTransactionStore(
        primary_path=tmp_path / "e" / "transaction.json",
        recovery_path=tmp_path / "c" / "transaction.json")

def seed_mirrors(store, record):
    payload = _record_json(record)
    atomic_write_json(store.recovery_path, payload)
    atomic_write_json(store.primary_path, payload)


def legacy_terminal_payload(record):
    payload = _record_json(record)
    for field in (
        "presentationManifestSha256",
        "mediaStoreManifestSha256",
        "acceptanceSha256",
    ):
        payload.pop(field)
    return payload


@pytest.mark.parametrize(
    "state",
    [TxState.COMMITTED, TxState.ROLLED_BACK],
)
def test_equal_legacy_terminal_mirrors_are_read_only_compatible(
        transaction_store, state):
    source = make_record(
        state,
        sequence=10 if state is TxState.COMMITTED else 3,
    )
    payload = legacy_terminal_payload(source)
    atomic_write_json(transaction_store.recovery_path, payload)
    atomic_write_json(transaction_store.primary_path, payload)
    before = {
        path: path.read_bytes()
        for path in (
            transaction_store.recovery_path,
            transaction_store.primary_path,
        )
    }

    transaction_store.assert_ready_for_new_run()
    record = transaction_store.read_equal().record

    assert record.schema_version == 0
    assert record.state is state
    assert record.presentation_manifest_sha256 is None
    assert record.media_store_manifest_sha256 is None
    assert record.acceptance_sha256 is None
    assert {
        path: path.read_bytes()
        for path in before
    } == before


def test_legacy_nonterminal_record_remains_rejected(
        transaction_store):
    payload = legacy_terminal_payload(
        make_record(TxState.PREPARED, sequence=5)
    )
    atomic_write_json(transaction_store.recovery_path, payload)

    with pytest.raises(
        MirrorDivergenceError,
        match=r"^invalid_transaction_record$",
    ):
        transaction_store._read_one(
            transaction_store.recovery_path
        )


def test_single_legacy_terminal_mirror_remains_unreconciled(
        transaction_store):
    payload = legacy_terminal_payload(
        make_record(TxState.ROLLED_BACK, sequence=3)
    )
    atomic_write_json(transaction_store.recovery_path, payload)
    before = transaction_store.recovery_path.read_bytes()

    with pytest.raises(
        InvalidTransitionError,
        match=r"^prior_run_not_reconciled$",
    ):
        transaction_store.assert_ready_for_new_run()
    assert transaction_store.recovery_path.read_bytes() == before
    assert not transaction_store.primary_path.exists()


def test_equal_sequence_legacy_and_current_mirrors_remain_divergent(
        transaction_store):
    record = make_record(TxState.COMMITTED, sequence=10)
    atomic_write_json(
        transaction_store.recovery_path,
        legacy_terminal_payload(record),
    )
    atomic_write_json(
        transaction_store.primary_path,
        _record_json(record),
    )
    before = {
        path: path.read_bytes()
        for path in (
            transaction_store.recovery_path,
            transaction_store.primary_path,
        )
    }

    with pytest.raises(
        MirrorDivergenceError,
        match=r"^equal_sequence_mirror_divergence$",
    ):
        transaction_store.inspect_conservative()
    assert {
        path: path.read_bytes()
        for path in before
    } == before


def test_legacy_degraded_reconciliation_is_rejected_before_write(
        transaction_store):
    payload = legacy_terminal_payload(
        replace(
            make_record(TxState.ROLLED_BACK, sequence=3),
            mirror_degraded=True,
        )
    )
    atomic_write_json(transaction_store.recovery_path, payload)
    atomic_write_json(transaction_store.primary_path, payload)
    before = {
        path: path.read_bytes()
        for path in (
            transaction_store.recovery_path,
            transaction_store.primary_path,
        )
    }

    with pytest.raises(
        InvalidTransitionError,
        match=r"^legacy_transaction_write_rejected$",
    ):
        transaction_store.reconcile_degraded_mirror(
            old_set_revalidated=True,
        )
    assert {
        path: path.read_bytes()
        for path in before
    } == before


def valid_cutover_arguments(record):
    planned = PlannedFile(
        live_path=r"C:\synthetic\WeFlow-config.json",
        action="replace",
        existed_before=True,
        expected_old_sha256="A" * 64,
        expected_new_sha256="B" * 64,
    )
    return {
        "expected": TxState.VALIDATED,
        "planned_files": (planned,),
        "backup_receipt": SimpleNamespace(
            run_id=record.run_id,
            primary_manifest_path=(
                r"E:\run\config-backup\backup-manifest.json"
            ),
            recovery_manifest_path=(
                r"C:\recovery\backup-manifest.json"
            ),
            canonical_sha256="C" * 64,
            item_count=1,
        ),
        "source_receipt": SimpleNamespace(
            role=CopyRole.SOURCE,
            content_sha256="D" * 64,
            total_files=4,
            total_bytes=100,
        ),
        "active_receipt": SimpleNamespace(
            role=CopyRole.ACTIVE,
            content_sha256="D" * 64,
            total_files=4,
            total_bytes=100,
        ),
        "presentation_receipt": SimpleNamespace(
            manifest_sha256="E" * 64,
            manifest=SimpleNamespace(
                media_store_manifest_sha256="F" * 64,
            ),
        ),
    }

def test_exclusive_publisher_create_flushes_c_then_rereads_then_e(
        transaction_store, discovered_record):
    events = []

    def publish(path, value):
        if path == transaction_store.primary_path:
            assert (
                transaction_store._read_one(
                    transaction_store.recovery_path
                ).record
                == discovered_record
            )
        events.append(path)
        atomic_write_json(path, value)

    created = transaction_store.create_with_exclusive_publisher(
        discovered_record, publish_json=publish
    )

    assert events == [
        transaction_store.recovery_path,
        transaction_store.primary_path,
    ]
    assert created == discovered_record


def test_exclusive_publisher_primary_failure_keeps_c_and_cause(
        transaction_store, discovered_record):
    primary_error = OSError("primary_publish")

    def publish(path, value):
        if path == transaction_store.primary_path:
            raise primary_error
        atomic_write_json(path, value)

    with pytest.raises(
        MirrorWriteError,
        match="mirrored_transaction_create_failed",
    ) as captured:
        transaction_store.create_with_exclusive_publisher(
            discovered_record, publish_json=publish
        )

    assert captured.value.__cause__ is primary_error
    assert (
        transaction_store._read_one(
            transaction_store.recovery_path
        ).record
        == discovered_record
    )
    assert not transaction_store.primary_path.exists()


def test_replacing_requires_equal_mirrors(transaction_store, prepared_record):
    seed_mirrors(transaction_store, prepared_record)
    transaction_store.recovery_path.write_text("{}", encoding="utf-8")
    with pytest.raises(MirrorDivergenceError):
        transaction_store.transition(TxState.PREPARED, TxState.REPLACING)

def test_terminal_state_rejects_transition(transaction_store,
                                           committed_record):
    seed_mirrors(transaction_store, committed_record)
    with pytest.raises(InvalidTransitionError):
        transaction_store.transition(TxState.COMMITTED,
                                     TxState.ROLLED_BACK)

def test_generic_transition_cannot_commit_accepted(
        transaction_store):
    accepted = make_record(TxState.ACCEPTED, sequence=9)
    seed_mirrors(transaction_store, accepted)
    with pytest.raises(InvalidTransitionError,
                       match="accepted_commit_requires_revalidation"):
        transaction_store.transition(TxState.ACCEPTED, TxState.COMMITTED)


def test_ui_acceptance_binds_receipt_and_state_in_one_mirrored_update(
        transaction_store):
    replaced = make_record(TxState.CONFIG_REPLACED, sequence=9)
    seed_mirrors(transaction_store, replaced)

    accepted = transaction_store.record_ui_acceptance(
        expected=TxState.CONFIG_REPLACED,
        acceptance_sha256="9" * 64,
    )

    assert accepted.sequence == replaced.sequence + 1
    assert accepted.state is TxState.ACCEPTED
    assert accepted.acceptance_sha256 == "9" * 64
    assert transaction_store.read_equal().record == accepted


def test_ui_acceptance_flushes_c_then_e_once(tmp_path):
    writes = []
    recovery = tmp_path / "c" / "transaction.json"
    primary = tmp_path / "e" / "transaction.json"

    def recording_write(path, value):
        writes.append(path)
        atomic_write_json(path, value)

    store = MirroredTransactionStore(
        primary_path=primary,
        recovery_path=recovery,
        write_json=recording_write,
    )
    replaced = make_record(TxState.CONFIG_REPLACED, sequence=9)
    seed_mirrors(store, replaced)

    accepted = store.record_ui_acceptance(
        acceptance_sha256="9" * 64,
    )

    assert writes == [recovery, primary]
    assert accepted.sequence == 10
    assert accepted.state is TxState.ACCEPTED


@pytest.mark.parametrize(
    ("expected", "acceptance_sha256"),
    [
        (TxState.ACCEPTED, "9" * 64),
        (TxState.CONFIG_REPLACED, True),
        (TxState.CONFIG_REPLACED, "9" * 63),
        (TxState.CONFIG_REPLACED, "a" * 64),
    ],
)
def test_ui_acceptance_rejects_wrong_state_or_malformed_hash(
        transaction_store, expected, acceptance_sha256):
    replaced = make_record(TxState.CONFIG_REPLACED, sequence=9)
    seed_mirrors(transaction_store, replaced)

    with pytest.raises(
        InvalidTransitionError,
        match="ui_acceptance_rejected",
    ):
        transaction_store.record_ui_acceptance(
            expected=expected,
            acceptance_sha256=acceptance_sha256,
        )

    assert transaction_store.read_equal().record == replaced


def test_ui_acceptance_cannot_be_recorded_twice(transaction_store):
    replaced = make_record(TxState.CONFIG_REPLACED, sequence=9)
    seed_mirrors(transaction_store, replaced)
    accepted = transaction_store.record_ui_acceptance(
        acceptance_sha256="9" * 64,
    )

    with pytest.raises(
        InvalidTransitionError,
        match="ui_acceptance_rejected",
    ):
        transaction_store.record_ui_acceptance(
            acceptance_sha256="8" * 64,
        )

    assert transaction_store.read_equal().record == accepted


def test_generic_transition_cannot_accept_without_receipt(
        transaction_store):
    replaced = make_record(TxState.CONFIG_REPLACED, sequence=9)
    seed_mirrors(transaction_store, replaced)

    with pytest.raises(
        InvalidTransitionError,
        match="ui_acceptance_receipt_required",
    ):
        transaction_store.transition(
            TxState.CONFIG_REPLACED,
            TxState.ACCEPTED,
        )

    assert transaction_store.read_equal().record == replaced


def test_cutover_plan_rejects_malformed_presentation_receipt(
        transaction_store):
    validated = make_record(TxState.VALIDATED, sequence=3)
    seed_mirrors(transaction_store, validated)
    arguments = valid_cutover_arguments(validated)
    arguments["presentation_receipt"] = SimpleNamespace(
        manifest_sha256="E" * 64,
    )

    with pytest.raises(
        InvalidTransitionError,
        match="invalid_cutover_receipt",
    ):
        transaction_store.record_cutover_plan(**arguments)

    assert transaction_store.read_equal().record == validated


@pytest.mark.parametrize(
    ("field", "bad_value"),
    [
        ("presentation", True),
        ("presentation", "e" * 64),
        ("presentation", "E" * 63),
        ("media_store", True),
        ("media_store", "f" * 64),
        ("media_store", "F" * 63),
    ],
)
def test_cutover_plan_rejects_noncanonical_presentation_hashes(
        transaction_store, field, bad_value):
    validated = make_record(TxState.VALIDATED, sequence=3)
    seed_mirrors(transaction_store, validated)
    arguments = valid_cutover_arguments(validated)
    presentation = arguments["presentation_receipt"]
    if field == "presentation":
        presentation.manifest_sha256 = bad_value
    else:
        presentation.manifest.media_store_manifest_sha256 = bad_value

    with pytest.raises(
        InvalidTransitionError,
        match="invalid_cutover_receipt",
    ):
        transaction_store.record_cutover_plan(**arguments)

    assert transaction_store.read_equal().record == validated


def test_formal_file_hashes_are_bound_in_one_mirrored_update(
        transaction_store):
    record = make_record(TxState.CONFIG_REPLACED, sequence=9)
    seed_mirrors(transaction_store, record)
    path = record.planned_files[0].live_path

    updated = transaction_store.record_formal_file_hashes(
        {path: "E" * 64}
    )

    assert updated.sequence == record.sequence + 1
    assert updated.planned_files[0].expected_new_sha256 == "E" * 64
    assert transaction_store.read_equal().record == updated


def test_formal_file_hashes_reject_incomplete_observation(
        transaction_store):
    record = make_record(TxState.CONFIG_REPLACED, sequence=9)
    seed_mirrors(transaction_store, record)

    with pytest.raises(
        InvalidTransitionError,
        match="formal_hash_set_incomplete",
    ):
        transaction_store.record_formal_file_hashes({})

    assert transaction_store.read_equal().record == record


def test_record_shadow_flushes_c_then_e(tmp_path, discovered_record):
    writes = []
    recovery = tmp_path / "c" / "transaction.json"
    primary = tmp_path / "e" / "transaction.json"
    def recording_write(path, value):
        writes.append(path)
        atomic_write_json(path, value)
    store = MirroredTransactionStore(
        primary_path=primary, recovery_path=recovery,
        write_json=recording_write)
    store.create(discovered_record)
    writes.clear()
    updated = store.record_shadow(
        expected=TxState.DISCOVERED,
        shadow_id="{abcdefab-cdef-abcd-efab-cdefabcdefab}",
        source_volume="F:\\")
    assert writes == [recovery, primary]
    assert updated.shadow_id == "{ABCDEFAB-CDEF-ABCD-EFAB-CDEFABCDEFAB}"
    assert store.read_equal().record == updated

def test_record_shadow_primary_failure_blocks_adoption(
        tmp_path, discovered_record):
    recovery = tmp_path / "c" / "transaction.json"
    primary = tmp_path / "e" / "transaction.json"
    fail_primary = False
    def faulting_write(path, value):
        if fail_primary and path == primary:
            raise OSError("synthetic_primary_failure")
        atomic_write_json(path, value)
    store = MirroredTransactionStore(
        primary_path=primary, recovery_path=recovery,
        write_json=faulting_write)
    store.create(discovered_record)
    fail_primary = True
    with pytest.raises(MirrorWriteError):
        store.record_shadow(
            expected=TxState.DISCOVERED,
            shadow_id="{22222222-2222-2222-2222-222222222222}",
            source_volume="F:\\")
    assert store.inspect_conservative().mirrors_diverged is True

def unbound_timeout_record():
    return replace(
        make_record(TxState.RECOVERY_PENDING, sequence=1),
        shadow_id=None, shadow_source_volume=None)

def test_late_bind_created_shadow_for_cleanup_flushes_c_then_e(tmp_path):
    writes = []
    recovery = tmp_path / "c" / "transaction.json"
    primary = tmp_path / "e" / "transaction.json"
    def recording_write(path, value):
        writes.append(path)
        atomic_write_json(path, value)
    store = MirroredTransactionStore(
        primary_path=primary, recovery_path=recovery,
        write_json=recording_write)
    seed_mirrors(store, unbound_timeout_record())
    updated = store.late_bind_created_shadow_for_cleanup(
        shadow_id="{abcdefab-cdef-abcd-efab-cdefabcdefab}",
        source_volume="F:\\",
        expected_source_volume="F:\\",
        journal_run_id="11111111-1111-1111-1111-111111111111",
        journal_state="created")
    assert writes == [recovery, primary]
    assert updated.state is TxState.RECOVERY_PENDING
    assert updated.shadow_id == "{ABCDEFAB-CDEF-ABCD-EFAB-CDEFABCDEFAB}"
    assert store.read_equal().record == updated

@pytest.mark.parametrize("fault", [
    "wrong_state", "wrong_run", "wrong_volume", "adopted",
    "already_bound", "degraded",
])
def test_late_bind_rejects_every_non_created_empty_pending_case(
        transaction_store, fault):
    record = unbound_timeout_record()
    if fault == "wrong_state":
        record = make_record(TxState.DISCOVERED, sequence=0)
    elif fault == "already_bound":
        record = make_record(TxState.RECOVERY_PENDING, sequence=1)
    elif fault == "degraded":
        record = replace(record, mirror_degraded=True)
    seed_mirrors(transaction_store, record)
    with pytest.raises(InvalidTransitionError,
                       match="late_shadow_bind_rejected"):
        transaction_store.late_bind_created_shadow_for_cleanup(
            shadow_id="{22222222-2222-2222-2222-222222222222}",
            source_volume="E:\\" if fault == "wrong_volume" else "F:\\",
            expected_source_volume="F:\\",
            journal_run_id=(
                "99999999-9999-4999-8999-999999999999"
                if fault == "wrong_run"
                else "11111111-1111-1111-1111-111111111111"),
            journal_state="adopted" if fault == "adopted" else "created")

@pytest.mark.parametrize("failed_mirror", ["recovery", "primary"])
def test_late_bind_mirror_failure_never_reports_joint_identity(
        tmp_path, failed_mirror):
    recovery = tmp_path / "c" / "transaction.json"
    primary = tmp_path / "e" / "transaction.json"
    failed_path = recovery if failed_mirror == "recovery" else primary
    def fail_selected(path, value):
        if path == failed_path:
            raise OSError("synthetic_mirror_failure")
        atomic_write_json(path, value)
    store = MirroredTransactionStore(
        primary_path=primary, recovery_path=recovery,
        write_json=fail_selected)
    seed_mirrors(store, unbound_timeout_record())
    with pytest.raises(MirrorWriteError):
        store.late_bind_created_shadow_for_cleanup(
            shadow_id="{22222222-2222-2222-2222-222222222222}",
            source_volume="F:\\",
            expected_source_volume="F:\\",
            journal_run_id="11111111-1111-1111-1111-111111111111",
            journal_state="created")
    if failed_mirror == "recovery":
        assert store.read_equal().record.shadow_id is None
    else:
        assert store.inspect_conservative().mirrors_diverged is True

def test_recovery_only_can_mark_c_mirror_degraded_when_e_is_offline(
        tmp_path):
    recovery = tmp_path / "c" / "transaction.json"
    primary = tmp_path / "e" / "transaction.json"
    store = MirroredTransactionStore(
        primary_path=primary, recovery_path=recovery)
    replacing = make_record(TxState.REPLACING, sequence=6)
    seed_mirrors(store, replacing)
    primary.parent.rename(tmp_path / "e.offline")
    restarted = MirroredTransactionStore(
        primary_path=primary, recovery_path=recovery,
        storage_available=lambda _: False)
    result = restarted.force_conservative_state(TxState.ROLLED_BACK)
    assert result.state is TxState.ROLLED_BACK
    assert result.mirror_degraded is True
    assert restarted._read_one(recovery).record == result
    assert not primary.exists()
    with pytest.raises(InvalidTransitionError,
                       match="terminal_recovery_rejected"):
        restarted.force_conservative_state(TxState.RECOVERY_PENDING)
    online = MirroredTransactionStore(
        primary_path=primary, recovery_path=recovery,
        storage_available=lambda _: True)
    with pytest.raises(InvalidTransitionError,
                       match="prior_run_not_reconciled"):
        online.assert_ready_for_new_run()
    with pytest.raises(InvalidTransitionError,
                       match="old_set_revalidation_required"):
        online.reconcile_degraded_mirror(old_set_revalidated=False)
    reconciled = online.reconcile_degraded_mirror(
        old_set_revalidated=True)
    assert reconciled.mirror_degraded is False
    assert online.read_equal().record == reconciled
    online.assert_ready_for_new_run()

def test_prepared_transition_requires_all_persisted_receipts(
        transaction_store):
    validated = make_record(TxState.VALIDATED, sequence=3)
    seed_mirrors(transaction_store, validated)
    with pytest.raises(InvalidTransitionError,
                       match="cutover_plan_not_recorded"):
        transaction_store.transition(
            TxState.VALIDATED, TxState.PREPARED)
    planned = PlannedFile(
        live_path=r"C:\synthetic\WeFlow-config.json",
        action="replace", existed_before=True,
        expected_old_sha256="A" * 64,
        expected_new_sha256="B" * 64)
    backup = SimpleNamespace(
        run_id=validated.run_id,
        primary_manifest_path=r"E:\run\config-backup\backup-manifest.json",
        recovery_manifest_path=r"C:\recovery\backup-manifest.json",
        canonical_sha256="C" * 64, item_count=1)
    source = SimpleNamespace(
        role=CopyRole.SOURCE, content_sha256="D" * 64,
        total_files=4, total_bytes=100)
    active = SimpleNamespace(
        role=CopyRole.ACTIVE, content_sha256="D" * 64,
        total_files=4, total_bytes=100)
    presentation = SimpleNamespace(
        manifest_sha256="E" * 64,
        manifest=SimpleNamespace(
            media_store_manifest_sha256="F" * 64))
    updated = transaction_store.record_cutover_plan(
        expected=TxState.VALIDATED, planned_files=(planned,),
        backup_receipt=backup, source_receipt=source,
        active_receipt=active, presentation_receipt=presentation)
    assert updated.planned_files == (planned,)
    assert updated.backup_manifest_sha256 == "C" * 64
    assert updated.source_manifest_sha256 == updated.active_manifest_sha256
    assert updated.presentation_manifest_sha256 == "E" * 64
    assert updated.media_store_manifest_sha256 == "F" * 64
    transaction_store.transition(TxState.VALIDATED, TxState.PREPARED)


def test_database_only_cutover_uses_required_receipts_without_media(
        transaction_store):
    validated = make_record(TxState.VALIDATED, sequence=3)
    seed_mirrors(transaction_store, validated)
    arguments = valid_cutover_arguments(validated)
    arguments["presentation_receipt"] = None

    planned = transaction_store.record_cutover_plan(**arguments)

    assert planned.presentation_manifest_sha256 is None
    assert planned.media_store_manifest_sha256 is None
    prepared = transaction_store.transition(
        TxState.VALIDATED,
        TxState.PREPARED,
    )
    replaced = replace(
        prepared,
        sequence=8,
        state=TxState.CONFIG_REPLACED,
        applied_files=tuple(
            item.live_path for item in prepared.planned_files
            if item.action != "delete_if_created"
        ),
    )
    seed_mirrors(transaction_store, replaced)
    accepted = transaction_store.record_ui_acceptance(
        acceptance_sha256="9" * 64,
    )
    current_hashes = {
        item.live_path: item.expected_new_sha256
        for item in accepted.planned_files
    }

    committed = transaction_store.commit_revalidated_accepted(
        current_hashes=current_hashes,
        accepted_revalidated=True,
    )

    assert committed.state is TxState.COMMITTED
    assert committed.presentation_manifest_sha256 is None
    assert committed.media_store_manifest_sha256 is None

@pytest.mark.parametrize("missing", [
    "backup", "backup_primary", "backup_recovery", "source", "active",
    "presentation", "media_store",
])
def test_reader_rejects_each_partial_receipt_set(
        transaction_store, missing):
    record = make_record(TxState.VALIDATED, sequence=3)
    planned = PlannedFile(
        live_path=r"C:\synthetic\WeFlow-config.json",
        action="replace", existed_before=True,
        expected_old_sha256="A" * 64,
        expected_new_sha256="B" * 64)
    values = dict(
        backup_manifest_sha256="C" * 64,
        backup_primary_manifest_path=r"E:\backup-manifest.json",
        backup_recovery_manifest_path=r"C:\backup-manifest.json",
        source_manifest_sha256="D" * 64,
        active_manifest_sha256="D" * 64,
        presentation_manifest_sha256="E" * 64,
        media_store_manifest_sha256="F" * 64)
    if missing == "backup":
        values["backup_manifest_sha256"] = None
    elif missing.startswith("backup_"):
        values[missing + "_manifest_path"] = None
    else:
        values[missing + "_manifest_sha256"] = None
    record = replace(record, planned_files=(planned,), **values)
    seed_mirrors(transaction_store, record)
    with pytest.raises(MirrorDivergenceError,
                       match="invalid_transaction_record"):
        transaction_store.transition(TxState.VALIDATED, TxState.PREPARED)


@pytest.mark.parametrize(
    ("state", "sequence"),
    [
        (TxState.DISCOVERED, 0),
        (TxState.SNAPSHOT_READY, 2),
        (TxState.VALIDATED, 3),
        (TxState.PREPARED, 5),
        (TxState.REPLACING, 6),
        (TxState.CONFIG_REPLACED, 9),
    ],
)
def test_reader_rejects_acceptance_receipt_in_every_early_state(
        transaction_store, state, sequence):
    record = replace(
        make_record(state, sequence=sequence),
        acceptance_sha256="9" * 64,
    )
    seed_mirrors(transaction_store, record)

    with pytest.raises(
        MirrorDivergenceError,
        match="invalid_transaction_record",
    ):
        transaction_store._read_one(transaction_store.recovery_path)


@pytest.mark.parametrize("state", [TxState.ACCEPTED, TxState.COMMITTED])
def test_reader_requires_acceptance_receipt_in_final_states(
        transaction_store, state):
    sequence = 10 if state is TxState.ACCEPTED else 11
    record = replace(
        make_record(state, sequence=sequence),
        acceptance_sha256=None,
    )
    seed_mirrors(transaction_store, record)

    with pytest.raises(
        MirrorDivergenceError,
        match="invalid_transaction_record",
    ):
        transaction_store._read_one(transaction_store.recovery_path)


@pytest.mark.parametrize(
    "state",
    [TxState.RECOVERY_PENDING, TxState.ROLLED_BACK],
)
def test_recovery_states_may_preserve_acceptance_receipt(
        transaction_store, state):
    record = replace(
        make_record(TxState.ACCEPTED, sequence=10),
        state=state,
        sequence=11,
    )
    seed_mirrors(transaction_store, record)

    assert (
        transaction_store.read_equal().record.acceptance_sha256
        == "9" * 64
    )


@pytest.mark.parametrize(
    "state",
    [TxState.RECOVERY_PENDING, TxState.ROLLED_BACK],
)
def test_recovery_states_may_exist_before_ui_acceptance(
        transaction_store, state):
    record = replace(
        make_record(TxState.CONFIG_REPLACED, sequence=9),
        state=state,
        sequence=10,
    )
    seed_mirrors(transaction_store, record)

    assert transaction_store.read_equal().record.acceptance_sha256 is None


def test_recovery_transition_preserves_acceptance_receipt(
        transaction_store):
    accepted = make_record(TxState.ACCEPTED, sequence=10)
    seed_mirrors(transaction_store, accepted)

    pending = transaction_store.force_conservative_state(
        TxState.RECOVERY_PENDING,
    )
    rolled_back = transaction_store.force_conservative_state(
        TxState.ROLLED_BACK,
    )

    assert pending.acceptance_sha256 == "9" * 64
    assert rolled_back.acceptance_sha256 == "9" * 64
    assert transaction_store.read_equal().record == rolled_back


def test_commit_preserves_all_media_and_acceptance_receipts(
        transaction_store):
    accepted = make_record(TxState.ACCEPTED, sequence=10)
    seed_mirrors(transaction_store, accepted)
    planned = accepted.planned_files[0]

    committed = transaction_store.commit_revalidated_accepted(
        current_hashes={
            planned.live_path: planned.expected_new_sha256,
        },
        accepted_revalidated=True,
    )

    assert committed.state is TxState.COMMITTED
    assert committed.presentation_manifest_sha256 == "E" * 64
    assert committed.media_store_manifest_sha256 == "F" * 64
    assert committed.acceptance_sha256 == "9" * 64
    assert transaction_store.read_equal().record == committed


@pytest.mark.parametrize(
    ("field", "bad_value"),
    [
        ("presentationManifestSha256", True),
        ("presentationManifestSha256", "e" * 64),
        ("mediaStoreManifestSha256", True),
        ("mediaStoreManifestSha256", "f" * 64),
        ("acceptanceSha256", True),
        ("acceptanceSha256", "a" * 64),
    ],
)
def test_reader_rejects_malformed_media_and_acceptance_hashes(
        transaction_store, field, bad_value):
    valid = _record_json(
        make_record(TxState.ACCEPTED, sequence=10)
    )
    valid[field] = bad_value
    atomic_write_json(transaction_store.recovery_path, valid)

    with pytest.raises(
        MirrorDivergenceError,
        match="invalid_transaction_record",
    ):
        transaction_store._read_one(transaction_store.recovery_path)


@pytest.mark.parametrize(
    "field",
    [
        "presentationManifestSha256",
        "mediaStoreManifestSha256",
        "acceptanceSha256",
    ],
)
def test_reader_requires_each_new_exact_schema_key(
        transaction_store, field):
    value = _record_json(
        make_record(TxState.ACCEPTED, sequence=10)
    )
    value.pop(field)
    atomic_write_json(transaction_store.recovery_path, value)

    with pytest.raises(
        MirrorDivergenceError,
        match="invalid_transaction_record",
    ):
        transaction_store._read_one(transaction_store.recovery_path)


@pytest.mark.parametrize(
    ("field", "bad_value"),
    [
        ("presentation_manifest_sha256", True),
        ("presentation_manifest_sha256", "e" * 64),
        ("media_store_manifest_sha256", True),
        ("media_store_manifest_sha256", "f" * 64),
        ("acceptance_sha256", True),
        ("acceptance_sha256", "a" * 64),
        ("presentation_manifest_sha256", None),
        ("media_store_manifest_sha256", None),
        ("acceptance_sha256", None),
    ],
)
def test_writer_rejects_malformed_or_partial_new_receipts_before_io(
        transaction_store, field, bad_value):
    record = replace(
        make_record(TxState.ACCEPTED, sequence=10),
        **{field: bad_value},
    )

    with pytest.raises(
        MirrorWriteError,
        match="invalid_transaction_record_write",
    ):
        transaction_store._write_both(record)

    assert not transaction_store.recovery_path.exists()
    assert not transaction_store.primary_path.exists()


def test_read_one_wraps_all_json_and_nested_schema_errors(
        transaction_store, prepared_record):
    valid = _record_json(prepared_record)
    malformed = []
    missing_top = dict(valid)
    missing_top.pop("sequence")
    malformed.append(missing_top)
    extra_top = dict(valid, unexpected=True)
    malformed.append(extra_top)
    malformed.append(dict(valid, schemaVersion=True))
    malformed.append(dict(
        valid, runId="{11111111-1111-1111-1111-111111111111}"))
    malformed.append(dict(valid, sequence=True))
    malformed.append(dict(valid, sequence=-1))
    malformed.append(dict(valid, sequence=2**63))
    malformed.append(dict(valid, sequence=2))
    malformed.append(dict(valid, state="not-a-state"))
    malformed.append(dict(valid, shadowId=None))
    malformed.append(dict(valid, shadowSourceVolume="not-a-volume"))
    malformed.append(dict(valid, mirrorDegraded="false"))
    malformed.append(dict(valid, mirrorDegraded=True))
    malformed.append(dict(valid, backupManifestSha256="short"))
    malformed.append(dict(
        valid, backupPrimaryManifestPath="relative-manifest.json"))
    malformed.append(dict(valid, activeManifestSha256="E" * 64))
    wrong_planned_container = dict(valid, plannedFiles={})
    malformed.append(wrong_planned_container)
    for key, bad_value in (
            ("live_path", "relative.json"),
            ("action", "truncate"),
            ("existed_before", 1),
            ("expected_old_sha256", "short")):
        item = dict(valid["plannedFiles"][0])
        item[key] = bad_value
        malformed.append(dict(valid, plannedFiles=[item]))
    wrong_new_hash = dict(valid["plannedFiles"][0])
    wrong_new_hash["expected_new_sha256"] = None
    malformed.append(dict(valid, plannedFiles=[wrong_new_hash]))
    ads_path = dict(valid["plannedFiles"][0])
    ads_path["live_path"] += ":stream"
    malformed.append(dict(valid, plannedFiles=[ads_path]))
    extra_item_key = dict(valid["plannedFiles"][0], unexpected=True)
    malformed.append(dict(valid, plannedFiles=[extra_item_key]))
    missing_item_key = dict(valid["plannedFiles"][0])
    missing_item_key.pop("action")
    malformed.append(dict(valid, plannedFiles=[missing_item_key]))
    malformed.append(dict(valid, appliedFiles={}))
    malformed.append(dict(
        valid, appliedFiles=[r"C:\synthetic\unplanned.json"]))
    malformed.append(dict(
        valid,
        appliedFiles=[valid["plannedFiles"][0]["live_path"]] * 2))
    for payload in malformed:
        atomic_write_json(transaction_store.recovery_path, payload)
        with pytest.raises(
                MirrorDivergenceError,
                match="invalid_transaction_record"):
            transaction_store._read_one(transaction_store.recovery_path)
    transaction_store.recovery_path.write_bytes(b"{not-json")
    with pytest.raises(MirrorDivergenceError,
                       match="invalid_transaction_record"):
        transaction_store._read_one(transaction_store.recovery_path)
    encoded = json.dumps(valid, separators=(",", ":"))
    transaction_store.recovery_path.write_text(
        encoded[:-1] + ',"sequence":5}', encoding="utf-8")
    with pytest.raises(MirrorDivergenceError,
                       match="invalid_transaction_record"):
        transaction_store._read_one(transaction_store.recovery_path)

def test_inspect_conservative_ignores_malformed_e_and_uses_valid_c(
        transaction_store, prepared_record):
    seed_mirrors(transaction_store, prepared_record)
    malformed = _record_json(prepared_record)
    malformed["plannedFiles"][0].pop("action")
    atomic_write_json(transaction_store.primary_path, malformed)
    view = transaction_store.inspect_conservative()
    assert view.record == prepared_record
    assert view.mirrors_diverged is True
    assert view.requires_full_rollback is True

@pytest.mark.parametrize("difference", ["state", "content"])
@pytest.mark.parametrize("operation", ["inspect", "force"])
def test_conservative_operations_reject_equal_sequence_mirror_divergence(
        transaction_store, prepared_record, difference, operation):
    recovery_record = prepared_record
    if difference == "state":
        primary_record = replace(
            recovery_record, state=TxState.RECOVERY_PENDING)
    else:
        replacement = replace(
            recovery_record.planned_files[0],
            expected_new_sha256="E" * 64)
        primary_record = replace(
            recovery_record, planned_files=(replacement,))
    atomic_write_json(
        transaction_store.recovery_path, _record_json(recovery_record))
    atomic_write_json(
        transaction_store.primary_path, _record_json(primary_record))
    before = {
        path: path.read_bytes()
        for path in (transaction_store.recovery_path,
                     transaction_store.primary_path)
    }
    with pytest.raises(MirrorDivergenceError,
                       match="equal_sequence_mirror_divergence"):
        if operation == "inspect":
            transaction_store.inspect_conservative()
        else:
            transaction_store.force_conservative_state(
                TxState.RECOVERY_PENDING)
    assert {
        path: path.read_bytes()
        for path in (transaction_store.recovery_path,
                     transaction_store.primary_path)
    } == before

def test_mirrored_write_does_not_wrap_keyboard_interrupt(
        tmp_path, discovered_record):
    store = MirroredTransactionStore(
        primary_path=tmp_path / "e" / "transaction.json",
        recovery_path=tmp_path / "c" / "transaction.json",
        write_json=lambda path, value: (_ for _ in ()).throw(
            KeyboardInterrupt("synthetic_interrupt")))
    with pytest.raises(KeyboardInterrupt, match="synthetic_interrupt"):
        store.create(discovered_record)

def test_applied_file_must_follow_planned_order_before_any_write(
        transaction_store):
    record = make_record(TxState.REPLACING, sequence=6)
    second = PlannedFile(
        live_path=r"C:\synthetic\second.json",
        action="replace", existed_before=True,
        expected_old_sha256="E" * 64,
        expected_new_sha256="F" * 64)
    record = replace(
        record, planned_files=record.planned_files + (second,))
    seed_mirrors(transaction_store, record)
    before = transaction_store.read_equal().record
    with pytest.raises(InvalidTransitionError,
                       match="unplanned_applied_file"):
        transaction_store.record_applied_file(second.live_path)
    assert transaction_store.read_equal().record == before

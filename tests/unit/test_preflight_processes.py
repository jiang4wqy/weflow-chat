from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from weflow_chat.preflight import (
    HostContract,
    ProcessIdentity as PreflightProcessIdentity,
    SourceEnumeration,
    require_fixed_host,
    request_normal_weflow_close,
    run_preflight,
)
from weflow_chat.processes import (
    ProcessIdentity,
    relevant_formal_weflow_processes,
)
from weflow_chat.weixin_trust import (
    LocalTrustReceipt,
    STORED_ENVELOPE_REFRESH,
)


def test_host_contract_has_fixed_media_store_and_derived_cache_roots(
        tmp_path: Path) -> None:
    contract = HostContract.for_test_root(tmp_path)

    assert contract.media_store_root == tmp_path / "E" / "MediaStore"
    assert contract.weflow_cache_root == tmp_path / "E" / "DerivedCache"


class FakeHostAdapters:
    def __init__(self, contract: HostContract) -> None:
        contract.db_storage.mkdir(parents=True, exist_ok=True)
        self.source_root = contract.db_storage
        contract.weixin_executable.parent.mkdir(
            parents=True, exist_ok=True
        )
        contract.weixin_executable.write_bytes(b"synthetic-weixin")
        contract.weixin_dll.parent.mkdir(
            parents=True, exist_ok=True
        )
        contract.weixin_dll.write_bytes(b"synthetic-weixin-dll")
        self.entries = (
            ("session.db", 10, 1),
            ("message.db-wal", 5, 2),
        )
        self.free = 2**40
        self.fs = "NTFS"
        self.vss = True
        self.target_exists = False
        self.config_regular = True
        self.config_sha = "A" * 64
        self.db_path_shape = "account_dir_instead_of_parent"
        self.account_matches = 1
        self.my_wxid_matches = True
        self.formal = ()
        self.validators = ()
        self.weixin = ProcessIdentity(
            pid=4242,
            executable=contract.weixin_executable,
            parent_pid=1,
            command_line=r"--secret-profile C:\private",
            architecture="x64",
            authenticode_status="Valid",
            signer_subject=(
                "Tencent Technology (Shenzhen) Company Limited"
            ),
            dll_authenticode_status="Valid",
            dll_signer_subject=(
                "Tencent Technology (Shenzhen) Company Limited"
            ),
            dll_version="4.1.11.24",
            dll_sha256=(
                "03968F3F6DF1C4B9872467E05EC5E84F"
                "7B599466021C2FB47EFD8940F16C9952"
            ),
            dll_path=contract.weixin_dll,
            dll_size=contract.weixin_dll.stat().st_size,
            dll_signer_certificate_sha256="B" * 64,
            isolated_user_data=None,
            creation_time_utc="2026-07-27T10:00:00Z",
        )
        self.session_exists = True
        self.old_upgrade_backup_exists = True
        self.historical_backup_count = 3
        self.newest_historical_backup_timestamp_utc = (
            "2026-07-20T20:08:41+00:00"
        )
        self._enumeration_count = 0
        self._recount_drift = False
        root_info = self.source_root.stat()
        self._root_identity = (
            root_info.st_dev,
            root_info.st_ino,
            root_info.st_ctime_ns,
        )
        self._identity_drift = False

    def enumerate_source(self):
        self._enumeration_count += 1
        if self._recount_drift and self._enumeration_count % 2 == 0:
            entries = (("session.db", 11, 1),)
        else:
            entries = self.entries
        return SourceEnumeration(
            root=self.source_root,
            rootIdentity=(
                (9, 9, 9)
                if self._identity_drift
                and self._enumeration_count == 2
                else self._root_identity
            ),
            entries=entries,
        )

    def inject(self, fault: str) -> None:
        if fault == "config_hash_shape":
            self.config_sha = "not-a-sha256"
        elif fault == "space":
            self.free = 0
        elif fault == "config_type":
            self.config_regular = False
        elif fault == "account_count":
            self.account_matches = 0
        elif fault == "db_path_shape":
            self.db_path_shape = "invalid"
        elif fault == "mywxid":
            self.my_wxid_matches = False
        elif fault == "formal_process":
            self.formal = (21,)
        elif fault == "validator_process":
            self.validators = (22,)
        elif fault == "target_exists":
            self.target_exists = True
        elif fault == "recount":
            self._recount_drift = True
        elif fault == "ntfs":
            self.fs = "ReFS"
        elif fault == "vss":
            self.vss = False
        elif fault == "session":
            self.session_exists = False
        elif fault == "old_backup":
            self.old_upgrade_backup_exists = False
        elif fault == "signature":
            self.weixin = replace(
                self.weixin, authenticode_status="NotSigned"
            )
        elif fault == "dll_hash":
            self.weixin = replace(self.weixin, dll_sha256="0" * 64)


@pytest.fixture
def host_fixture(tmp_path: Path):
    contract = HostContract.for_test_root(tmp_path)
    adapters = FakeHostAdapters(contract)
    return SimpleNamespace(
        contract=contract,
        adapters=adapters,
        actual_file_count=2,
        actual_byte_count=15,
        inject=adapters.inject,
    )


def test_preflight_checks_every_live_gate(host_fixture):
    report = run_preflight(
        host_fixture.contract, host_fixture.adapters
    )

    assert report.ok
    assert report.sourceFileCount == host_fixture.actual_file_count
    assert report.sourceByteCount == host_fixture.actual_byte_count
    assert report.requiredFreeBytes == report.sourceByteCount * 4 + 2**30
    assert report.weixin.pid == 4242
    assert report.weixin.architecture == "x64"
    assert report.weixin.dllVersion == "4.1.11.24"
    assert report.weixin.trustState == "builtin_trusted"
    assert report.weixin.capabilities == (
        "stored-envelope-refresh",
    )
    assert report.targetRunRootExists is False
    assert report.targetAccountMatches == 1
    assert report.formalWeFlowPids == ()
    assert report.validatorPids == ()
    assert report.sessionDbExists is True
    assert report.configSha256 == "A" * 64
    assert report.currentDbPathShape == "account_dir_instead_of_parent"
    assert report.oldUpgradeBackupExists is True
    assert report.historicalBackupCount == 3
    assert report.newestHistoricalBackupTimestampUtc == (
        "2026-07-20T20:08:41+00:00"
    )
    assert host_fixture.adapters._enumeration_count == 2
    rendered = report.to_redacted_json()
    for forbidden in (
        "Tencent Technology",
        "Program Files",
        "Weixin.exe",
        "--",
    ):
        assert forbidden not in rendered


def test_preflight_accepts_prior_committed_active_parent(
        host_fixture):
    host_fixture.adapters.db_path_shape = (
        "managed_active_parent"
    )

    report = run_preflight(
        host_fixture.contract,
        host_fixture.adapters,
    )

    assert report.ok
    assert (
        report.currentDbPathShape
        == "managed_active_parent"
    )
    rendered = json.loads(report.to_redacted_json())
    assert (
        rendered["currentDbPathShape"]
        == "managed_active_parent"
    )


def test_process_identity_has_one_definition():
    assert PreflightProcessIdentity is ProcessIdentity


def test_fixed_host_rejects_any_production_literal_drift(tmp_path):
    test_root = tmp_path / "contract"
    test_root.mkdir()
    contract = HostContract.for_test_root(test_root)

    assert require_fixed_host(contract) is contract
    with pytest.raises(
        RuntimeError, match=r"^host_contract_mismatch$"
    ):
        require_fixed_host(
            replace(contract, snapshots_root=tmp_path / "outside")
        )


def test_invalid_host_is_rejected_before_adapter_access(
    host_fixture,
):
    invalid = replace(
        host_fixture.contract,
        source_account=host_fixture.contract._test_root
        / ".."
        / "outside",
    )

    with pytest.raises(
        RuntimeError, match=r"^host_contract_mismatch$"
    ):
        run_preflight(invalid, host_fixture.adapters)

    assert host_fixture.adapters._enumeration_count == 0


@pytest.mark.parametrize(
    "field",
    ["media_store_root", "weflow_cache_root"],
)
def test_fixed_derived_roots_cannot_escape_test_host(
    host_fixture,
    field,
):
    invalid = replace(
        host_fixture.contract,
        **{
            field: (
                host_fixture.contract._test_root
                / ".."
                / f"outside-{field}"
            )
        },
    )

    with pytest.raises(
        RuntimeError,
        match=r"^host_contract_mismatch$",
    ):
        run_preflight(invalid, host_fixture.adapters)

    assert host_fixture.adapters._enumeration_count == 0


@pytest.mark.parametrize(
    "fault,code",
    [
        ("config_hash_shape", "config_hash_invalid"),
        ("space", "insufficient_e_space"),
        ("config_type", "config_not_regular_file"),
        ("account_count", "target_account_not_unique"),
        ("db_path_shape", "current_db_path_shape_invalid"),
        ("mywxid", "target_account_not_unique"),
        ("formal_process", "formal_weflow_running"),
        ("validator_process", "validator_process_residual"),
        ("target_exists", "run_root_collision"),
        ("recount", "source_recount_changed"),
        ("ntfs", "source_volume_not_ntfs"),
        ("vss", "vss_unsupported"),
        ("session", "session_db_missing"),
        ("signature", "weixin_signature_mismatch"),
    ],
)
def test_preflight_blocks_each_fault(
    host_fixture, fault, code
):
    host_fixture.inject(fault)
    report = run_preflight(
        host_fixture.contract, host_fixture.adapters
    )

    assert not report.ok
    assert code in report.reasonCodes


def test_signed_unknown_dll_is_actionable_trial_without_capabilities(
    host_fixture,
):
    host_fixture.inject("dll_hash")

    report = run_preflight(
        host_fixture.contract, host_fixture.adapters
    )

    assert report.ok
    assert report.reasonCodes == ()
    assert report.weixin.trustState == "trial_required"
    assert report.weixin.capabilities == ()


def test_exact_local_receipt_grants_only_stored_envelope_refresh(
    host_fixture,
):
    host_fixture.inject("dll_hash")
    identity = host_fixture.adapters.weixin
    host_fixture.adapters.local_trust_receipts = (
        LocalTrustReceipt(
            schema_version=1,
            run_id="11111111-1111-4111-8111-111111111111",
            version=identity.dll_version,
            architecture=identity.architecture,
            dll_size=identity.dll_size,
            dll_sha256=identity.dll_sha256,
            signer_certificate_sha256=(
                identity.dll_signer_certificate_sha256
            ),
            capabilities=frozenset({STORED_ENVELOPE_REFRESH}),
            evidence_sha256="F" * 64,
            created_at_utc="2026-08-05T00:00:00Z",
        ),
    )

    report = run_preflight(
        host_fixture.contract, host_fixture.adapters
    )

    assert report.ok
    assert report.weixin.trustState == "local_trusted"
    assert report.weixin.capabilities == (
        "stored-envelope-refresh",
    )


def test_missing_old_upgrade_backup_is_a_warning(host_fixture):
    host_fixture.inject("old_backup")
    report = run_preflight(
        host_fixture.contract, host_fixture.adapters
    )

    assert report.ok
    assert report.warningCodes == ("old_upgrade_backup_missing",)


def test_preflight_accepts_exact_4_1_12_26_builtin_identity(
    host_fixture,
):
    dll = (
        host_fixture.contract.weixin_install_root
        / "4.1.12.26"
        / "Weixin.dll"
    )
    dll.parent.mkdir(parents=True)
    dll.write_bytes(b"new-version")
    host_fixture.adapters.weixin = replace(
        host_fixture.adapters.weixin,
        dll_version="4.1.12.26",
        dll_sha256=(
            "4914A621A810ECBC0A132B6FF8F612658"
            "CFCE323D3989B3E5FE32D4FF343BA46"
        ),
        dll_path=dll,
        dll_size=191_480_360,
        dll_signer_certificate_sha256=(
            "A5260C88F699B19BD6ED100BC08120B4F"
            "D872930EE7538C3D210EB14081A0F45"
        ),
    )

    report = run_preflight(
        host_fixture.contract, host_fixture.adapters
    )

    assert report.ok
    assert report.weixin.dllVersion == "4.1.12.26"
    assert report.weixin.trustState == "builtin_trusted"


def test_source_entries_are_case_insensitively_unique(host_fixture):
    host_fixture.adapters.entries = (
        ("Message.db", 1, 1),
        ("message.db", 1, 1),
    )

    report = run_preflight(
        host_fixture.contract, host_fixture.adapters
    )

    assert not report.ok
    assert "source_enumeration_invalid" in report.reasonCodes


def test_source_root_identity_must_match_across_both_reads(
    host_fixture,
):
    host_fixture.adapters._identity_drift = True

    report = run_preflight(
        host_fixture.contract, host_fixture.adapters
    )

    assert not report.ok
    assert "source_root_identity_changed" in report.reasonCodes


def test_preflight_report_sanitizes_untrusted_adapter_text(
    host_fixture,
):
    secret = r"C:\SECRET --profile"
    host_fixture.adapters.config_sha = secret
    host_fixture.adapters.db_path_shape = secret
    host_fixture.adapters.weixin = replace(
        host_fixture.adapters.weixin,
        architecture=secret,
        dll_version=secret,
        dll_sha256=secret,
    )
    host_fixture.adapters.newest_historical_backup_timestamp_utc = (
        secret
    )

    report = run_preflight(
        host_fixture.contract, host_fixture.adapters
    )
    rendered = report.to_redacted_json()

    assert not report.ok
    assert "SECRET" not in rendered
    assert "profile" not in rendered


def test_process_match_uses_canonical_formal_executable(tmp_path):
    expected = tmp_path / "formal" / "WeFlow.exe"
    expected.parent.mkdir()
    expected.write_bytes(b"formal")
    unrelated = replace(
        FakeHostAdapters(HostContract.for_test_root(tmp_path)).weixin,
        pid=20,
        executable=tmp_path / "Other.exe",
    )
    formal = replace(
        unrelated,
        pid=21,
        executable=expected,
        creation_time_utc="2026-07-27T10:01:00Z",
    )
    source = SimpleNamespace(
        list_processes=lambda: (unrelated, formal)
    )

    matched = relevant_formal_weflow_processes(
        source, expected=expected
    )

    assert tuple(item.pid for item in matched) == (21,)


def test_unreadable_named_formal_process_fails_closed(tmp_path):
    expected = tmp_path / "formal" / "WeFlow.exe"
    expected.parent.mkdir()
    expected.write_bytes(b"formal")
    identity = replace(
        FakeHostAdapters(HostContract.for_test_root(tmp_path)).weixin,
        executable=tmp_path / "missing" / "WeFlow.exe",
    )
    source = SimpleNamespace(list_processes=lambda: (identity,))

    with pytest.raises(
        RuntimeError, match=r"^formal_weflow_identity_unreadable$"
    ):
        relevant_formal_weflow_processes(
            source, expected=expected
        )


def test_process_token_rejects_bool_pid_and_non_utc_timestamp(
    tmp_path,
):
    expected = tmp_path / "WeFlow.exe"
    expected.write_bytes(b"formal")
    base = FakeHostAdapters(
        HostContract.for_test_root(tmp_path / "fixture")
    ).weixin
    source = SimpleNamespace(
        list_processes=lambda: (
            replace(
                base,
                pid=True,
                executable=expected,
                creation_time_utc="not-a-timestamp",
            ),
        )
    )

    with pytest.raises(
        RuntimeError, match=r"^process_identity_token_invalid$"
    ):
        relevant_formal_weflow_processes(
            source, expected=expected
        )


def test_normal_close_is_requested_without_forcing_termination():
    calls = []
    gate = SimpleNamespace(
        request_normal_close_and_wait=lambda timeout: (
            calls.append(timeout) or True
        )
    )

    request_normal_weflow_close(gate, timeout_seconds=12.5)

    assert calls == [12.5]


def test_normal_close_timeout_fails_closed():
    gate = SimpleNamespace(
        request_normal_close_and_wait=lambda _timeout: False
    )

    with pytest.raises(
        TimeoutError, match=r"^formal_weflow_normal_close_timeout$"
    ):
        request_normal_weflow_close(gate)

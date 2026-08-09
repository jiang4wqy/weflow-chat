from dataclasses import fields

from weflow_chat.manifest import (
    FileSetManifest,
    ResidualRisk,
    SnapshotMethod,
)
from weflow_chat.validator.contracts import (
    FingerprintSet,
    ValidationReceipt,
    ValidatorLayout,
)


def test_core_and_validator_contract_fields_are_exact():
    assert tuple(field.name for field in fields(FileSetManifest)) == (
        "role",
        "root",
        "files",
        "total_files",
        "total_bytes",
        "category_counts",
    )
    assert tuple(field.name for field in fields(FingerprintSet)) == (
        "schemaFingerprint",
        "aggregateFingerprint",
        "databaseCoverageFingerprint",
    )
    assert tuple(field.name for field in fields(ValidationReceipt)) == (
        "status",
        "reasonCode",
        "fingerprints",
    )
    assert tuple(field.name for field in fields(ValidatorLayout)) == (
        "run_root",
        "attempt_root",
        "runtime_exe",
        "request_path",
        "result_path",
        "user_data_dir",
        "documents_dir",
        "cache_dir",
    )
    assert SnapshotMethod.VSS_CRASH_CONSISTENT.value == "vss-crash-consistent"
    assert (
        ResidualRisk.NO_CROSS_DATABASE_ATOMICITY_PROOF.value
        == "crash_consistent_no_cross_database_atomicity_proof"
    )

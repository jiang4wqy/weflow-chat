from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class FingerprintSet:
    schemaFingerprint: str
    aggregateFingerprint: str
    databaseCoverageFingerprint: str


@dataclass(frozen=True, slots=True)
class ValidationReceipt:
    status: str
    reasonCode: str | None
    fingerprints: FingerprintSet | None


@dataclass(frozen=True, slots=True)
class ValidatorLayout:
    run_root: Path
    attempt_root: Path
    runtime_exe: Path
    request_path: Path
    result_path: Path
    user_data_dir: Path
    documents_dir: Path
    cache_dir: Path

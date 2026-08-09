from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from types import MappingProxyType
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Callable, Iterable, Mapping
import uuid

from weflow_chat.atomic_io import atomic_write_bytes
from weflow_chat.paths import canonical_existing


STORED_ENVELOPE_REFRESH = "stored-envelope-refresh"
_CAPABILITIES = frozenset({STORED_ENVELOPE_REFRESH})
_HEX64 = re.compile(r"[0-9A-F]{64}")
_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+){3}")
_UTC = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}Z"
)
_TENCENT = "Tencent Technology (Shenzhen) Company Limited"
_TRUST_FILE = "local-weixin-trust.json"
_EVIDENCE_FILE = "local-weixin-trust-evidence.json"
_MAX_TRUST_BYTES = 4096
_MAX_EVIDENCE_BYTES = 16 * 1024
_MAX_SAFE_INTEGER = 2**53 - 1
_MEDIA_COUNT_NAMES = (
    "candidateCount",
    "imageCandidateCount",
    "localFileCount",
    "locallyUnavailableCount",
    "readableImageCount",
    "readableVideoCount",
    "unreadableLocalCount",
    "videoCandidateCount",
)


class TrustState(str, Enum):
    BUILTIN_TRUSTED = "builtin_trusted"
    LOCAL_TRUSTED = "local_trusted"
    TRIAL_REQUIRED = "trial_required"
    REJECTED = "rejected"


@dataclass(frozen=True, slots=True)
class BuiltInWeixinContract:
    version: str
    architecture: str
    dll_sha256: str
    dll_size: int | None
    authenticode_status: str
    signer_subject_contains: str
    signer_certificate_sha256: str | None
    capabilities: frozenset[str]

    def __post_init__(self) -> None:
        if (
            not isinstance(self.version, str)
            or _VERSION.fullmatch(self.version) is None
            or self.architecture != "x64"
            or not isinstance(self.dll_sha256, str)
            or _HEX64.fullmatch(self.dll_sha256) is None
            or (
                self.dll_size is not None
                and (
                    type(self.dll_size) is not int
                    or self.dll_size <= 0
                )
            )
            or self.authenticode_status != "Valid"
            or not isinstance(self.signer_subject_contains, str)
            or not self.signer_subject_contains
            or (
                self.signer_certificate_sha256 is not None
                and (
                    not isinstance(
                        self.signer_certificate_sha256, str
                    )
                    or _HEX64.fullmatch(
                        self.signer_certificate_sha256
                    )
                    is None
                )
            )
            or not isinstance(self.capabilities, frozenset)
            or not self.capabilities
            or STORED_ENVELOPE_REFRESH not in self.capabilities
            or not self.capabilities <= _CAPABILITIES
        ):
            raise ValueError("builtin_weixin_contract_invalid")


@dataclass(frozen=True, slots=True)
class RuntimeWeixinDllIdentity:
    version: str
    architecture: str
    dll_size: int
    dll_sha256: str
    authenticode_status: str
    signer_subject: str
    signer_certificate_sha256: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.version, str)
            or _VERSION.fullmatch(self.version) is None
            or not isinstance(self.architecture, str)
            or type(self.dll_size) is not int
            or self.dll_size <= 0
            or not isinstance(self.dll_sha256, str)
            or _HEX64.fullmatch(self.dll_sha256) is None
            or not isinstance(self.authenticode_status, str)
            or not isinstance(self.signer_subject, str)
            or not isinstance(self.signer_certificate_sha256, str)
            or _HEX64.fullmatch(self.signer_certificate_sha256) is None
        ):
            raise ValueError("runtime_weixin_identity_invalid")


@dataclass(frozen=True, slots=True)
class WeixinTrustDecision:
    state: TrustState
    capabilities: frozenset[str]

    def __post_init__(self) -> None:
        if (
            not isinstance(self.state, TrustState)
            or not isinstance(self.capabilities, frozenset)
            or not self.capabilities <= _CAPABILITIES
            or (
                self.state
                in {TrustState.REJECTED, TrustState.TRIAL_REQUIRED}
                and self.capabilities
            )
        ):
            raise ValueError("weixin_trust_decision_invalid")


@dataclass(frozen=True, slots=True)
class LocalTrustReceipt:
    schema_version: int
    run_id: str
    version: str
    architecture: str
    dll_size: int
    dll_sha256: str
    signer_certificate_sha256: str
    capabilities: frozenset[str]
    evidence_sha256: str
    created_at_utc: str

    def __post_init__(self) -> None:
        try:
            canonical_run_id = str(uuid.UUID(self.run_id))
            created = datetime.strptime(
                self.created_at_utc, "%Y-%m-%dT%H:%M:%SZ"
            ).replace(tzinfo=timezone.utc)
        except (AttributeError, TypeError, ValueError) as error:
            raise ValueError("local_trust_receipt_invalid") from error
        if (
            type(self.schema_version) is not int
            or self.schema_version != 1
            or not isinstance(self.run_id, str)
            or self.run_id != canonical_run_id
            or not isinstance(self.version, str)
            or _VERSION.fullmatch(self.version) is None
            or self.architecture != "x64"
            or type(self.dll_size) is not int
            or not 0 < self.dll_size <= _MAX_SAFE_INTEGER
            or not isinstance(self.dll_sha256, str)
            or _HEX64.fullmatch(self.dll_sha256) is None
            or not isinstance(
                self.signer_certificate_sha256, str
            )
            or _HEX64.fullmatch(
                self.signer_certificate_sha256
            )
            is None
            or self.capabilities
            != frozenset({STORED_ENVELOPE_REFRESH})
            or not isinstance(self.evidence_sha256, str)
            or _HEX64.fullmatch(self.evidence_sha256) is None
            or not isinstance(self.created_at_utc, str)
            or _UTC.fullmatch(self.created_at_utc) is None
            or created.utcoffset() != timezone.utc.utcoffset(created)
        ):
            raise ValueError("local_trust_receipt_invalid")

    def matches(self, identity: RuntimeWeixinDllIdentity) -> bool:
        return (
            isinstance(identity, RuntimeWeixinDllIdentity)
            and self.version == identity.version
            and self.architecture == identity.architecture
            and self.dll_size == identity.dll_size
            and self.dll_sha256 == identity.dll_sha256
            and self.signer_certificate_sha256
            == identity.signer_certificate_sha256
        )


@dataclass(frozen=True, slots=True)
class LocalTrustEvidence:
    schema_version: int
    run_id: str
    version: str
    architecture: str
    dll_size: int
    dll_sha256: str
    signer_certificate_sha256: str
    transaction_sha256: str
    compatibility_sha256: str
    run_manifest_sha256: str
    validation_schema_fingerprint: str
    validation_aggregate_fingerprint: str
    validation_database_coverage_fingerprint: str
    media_openability: tuple[tuple[str, int], ...]
    presentation_manifest_sha256: str
    media_store_manifest_sha256: str
    formal_config_sha256_before: str
    formal_config_sha256_after: str
    production_write_count: int
    final_state: str

    def __post_init__(self) -> None:
        try:
            canonical_run_id = str(uuid.UUID(self.run_id))
            media_names = tuple(
                name for name, _ in self.media_openability
            )
            media = dict(self.media_openability)
        except (
            AttributeError,
            TypeError,
            ValueError,
        ) as error:
            raise ValueError("local_trust_evidence_invalid") from error
        hashes = (
            self.dll_sha256,
            self.signer_certificate_sha256,
            self.transaction_sha256,
            self.compatibility_sha256,
            self.run_manifest_sha256,
            self.validation_schema_fingerprint,
            self.validation_aggregate_fingerprint,
            self.validation_database_coverage_fingerprint,
            self.presentation_manifest_sha256,
            self.media_store_manifest_sha256,
            self.formal_config_sha256_before,
            self.formal_config_sha256_after,
        )
        if (
            type(self.schema_version) is not int
            or self.schema_version != 1
            or not isinstance(self.run_id, str)
            or self.run_id != canonical_run_id
            or not isinstance(self.version, str)
            or _VERSION.fullmatch(self.version) is None
            or self.architecture != "x64"
            or type(self.dll_size) is not int
            or not 0 < self.dll_size <= _MAX_SAFE_INTEGER
            or any(
                not isinstance(value, str)
                or _HEX64.fullmatch(value) is None
                for value in hashes
            )
            or not isinstance(self.media_openability, tuple)
            or media_names != _MEDIA_COUNT_NAMES
            or any(
                not isinstance(item, tuple)
                or len(item) != 2
                or type(item[1]) is not int
                or not 0 <= item[1] <= _MAX_SAFE_INTEGER
                for item in self.media_openability
            )
            or media["candidateCount"]
            != (
                media["imageCandidateCount"]
                + media["videoCandidateCount"]
            )
            or media["candidateCount"]
            != (
                media["locallyUnavailableCount"]
                + media["localFileCount"]
            )
            or media["localFileCount"]
            != (
                media["readableImageCount"]
                + media["readableVideoCount"]
                + media["unreadableLocalCount"]
            )
            or media["unreadableLocalCount"] != 0
            or type(self.production_write_count) is not int
            or self.production_write_count != 0
            or self.final_state != "ROLLED_BACK"
            or self.formal_config_sha256_before
            != self.formal_config_sha256_after
        ):
            raise ValueError("local_trust_evidence_invalid")

    def matches(
        self,
        receipt: LocalTrustReceipt,
    ) -> bool:
        return (
            isinstance(receipt, LocalTrustReceipt)
            and self.run_id == receipt.run_id
            and self.version == receipt.version
            and self.architecture == receipt.architecture
            and self.dll_size == receipt.dll_size
            and self.dll_sha256 == receipt.dll_sha256
            and self.signer_certificate_sha256
            == receipt.signer_certificate_sha256
        )


def build_builtin_registry(
    contracts: Iterable[BuiltInWeixinContract],
) -> Mapping[str, BuiltInWeixinContract]:
    values = tuple(contracts)
    if not values or any(
        not isinstance(item, BuiltInWeixinContract)
        for item in values
    ):
        raise ValueError("builtin_weixin_registry_invalid")
    by_hash = {item.dll_sha256: item for item in values}
    if len(by_hash) != len(values):
        raise ValueError("builtin_weixin_registry_invalid")
    return MappingProxyType(by_hash)


BUILTIN_WEIXIN_CONTRACTS = (
    BuiltInWeixinContract(
        version="4.1.11.24",
        architecture="x64",
        dll_sha256=(
            "03968F3F6DF1C4B9872467E05EC5E84F"
            "7B599466021C2FB47EFD8940F16C9952"
        ),
        dll_size=None,
        authenticode_status="Valid",
        signer_subject_contains=_TENCENT,
        signer_certificate_sha256=None,
        capabilities=frozenset({STORED_ENVELOPE_REFRESH}),
    ),
    BuiltInWeixinContract(
        version="4.1.12.26",
        architecture="x64",
        dll_sha256=(
            "4914A621A810ECBC0A132B6FF8F612658"
            "CFCE323D3989B3E5FE32D4FF343BA46"
        ),
        dll_size=191_480_360,
        authenticode_status="Valid",
        signer_subject_contains=_TENCENT,
        signer_certificate_sha256=(
            "A5260C88F699B19BD6ED100BC08120B4F"
            "D872930EE7538C3D210EB14081A0F45"
        ),
        capabilities=frozenset({STORED_ENVELOPE_REFRESH}),
    ),
)
BUILTIN_WEIXIN_BY_HASH = build_builtin_registry(
    BUILTIN_WEIXIN_CONTRACTS
)


def resolve_builtin_trust(
    identity: RuntimeWeixinDllIdentity,
) -> WeixinTrustDecision:
    if not isinstance(identity, RuntimeWeixinDllIdentity):
        raise TypeError("runtime_weixin_identity_invalid")
    if (
        identity.architecture != "x64"
        or identity.authenticode_status != "Valid"
        or _TENCENT not in identity.signer_subject
    ):
        return WeixinTrustDecision(
            TrustState.REJECTED, frozenset()
        )
    contract = BUILTIN_WEIXIN_BY_HASH.get(
        identity.dll_sha256
    )
    if contract is None:
        return WeixinTrustDecision(
            TrustState.TRIAL_REQUIRED, frozenset()
        )
    if (
        identity.version != contract.version
        or identity.architecture != contract.architecture
        or identity.authenticode_status
        != contract.authenticode_status
        or contract.signer_subject_contains
        not in identity.signer_subject
        or (
            contract.dll_size is not None
            and identity.dll_size != contract.dll_size
        )
        or (
            contract.signer_certificate_sha256 is not None
            and identity.signer_certificate_sha256
            != contract.signer_certificate_sha256
        )
    ):
        return WeixinTrustDecision(
            TrustState.REJECTED, frozenset()
        )
    return WeixinTrustDecision(
        TrustState.BUILTIN_TRUSTED,
        contract.capabilities,
    )


def resolve_weixin_trust(
    identity: RuntimeWeixinDllIdentity,
    *,
    local_receipts: Iterable[LocalTrustReceipt] = (),
) -> WeixinTrustDecision:
    decision = resolve_builtin_trust(identity)
    if decision.state is not TrustState.TRIAL_REQUIRED:
        return decision
    receipts = tuple(local_receipts)
    if any(
        not isinstance(item, LocalTrustReceipt)
        for item in receipts
    ):
        raise TypeError("local_trust_receipt_invalid")
    matched = tuple(
        item for item in receipts if item.matches(identity)
    )
    if not matched:
        return decision
    identities = {
        (
            item.version,
            item.dll_size,
            item.dll_sha256,
            item.signer_certificate_sha256,
            item.capabilities,
        )
        for item in matched
    }
    if len(identities) != 1:
        return WeixinTrustDecision(
            TrustState.REJECTED, frozenset()
        )
    return WeixinTrustDecision(
        TrustState.LOCAL_TRUSTED,
        frozenset({STORED_ENVELOPE_REFRESH}),
    )


def _strict_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("local_trust_receipt_invalid")
        value[key] = item
    return value


def encode_local_trust_receipt(
    receipt: LocalTrustReceipt,
) -> bytes:
    if not isinstance(receipt, LocalTrustReceipt):
        raise TypeError("local_trust_receipt_invalid")
    value = {
        "architecture": receipt.architecture,
        "capabilities": sorted(receipt.capabilities),
        "createdAtUtc": receipt.created_at_utc,
        "dllSha256": receipt.dll_sha256,
        "dllSize": receipt.dll_size,
        "evidenceSha256": receipt.evidence_sha256,
        "runId": receipt.run_id,
        "schemaVersion": receipt.schema_version,
        "signerCertificateSha256": (
            receipt.signer_certificate_sha256
        ),
        "version": receipt.version,
    }
    return json.dumps(
        value, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def decode_local_trust_receipt(payload: bytes) -> LocalTrustReceipt:
    if (
        not isinstance(payload, bytes)
        or not 0 < len(payload) <= _MAX_TRUST_BYTES
    ):
        raise ValueError("local_trust_receipt_invalid")
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_strict_object,
        )
        if (
            not isinstance(value, dict)
            or set(value)
            != {
                "architecture",
                "capabilities",
                "createdAtUtc",
                "dllSha256",
                "dllSize",
                "evidenceSha256",
                "runId",
                "schemaVersion",
                "signerCertificateSha256",
                "version",
            }
            or not isinstance(value["capabilities"], list)
            or any(
                not isinstance(item, str)
                for item in value["capabilities"]
            )
            or value["capabilities"]
            != sorted(set(value["capabilities"]))
        ):
            raise ValueError
        return LocalTrustReceipt(
            schema_version=value["schemaVersion"],
            run_id=value["runId"],
            version=value["version"],
            architecture=value["architecture"],
            dll_size=value["dllSize"],
            dll_sha256=value["dllSha256"],
            signer_certificate_sha256=(
                value["signerCertificateSha256"]
            ),
            capabilities=frozenset(value["capabilities"]),
            evidence_sha256=value["evidenceSha256"],
            created_at_utc=value["createdAtUtc"],
        )
    except (KeyError, TypeError, UnicodeError, ValueError) as error:
        raise ValueError("local_trust_receipt_invalid") from error


def encode_local_trust_evidence(
    evidence: LocalTrustEvidence,
) -> bytes:
    if not isinstance(evidence, LocalTrustEvidence):
        raise TypeError("local_trust_evidence_invalid")
    value = {
        "architecture": evidence.architecture,
        "compatibilitySha256": evidence.compatibility_sha256,
        "dllSha256": evidence.dll_sha256,
        "dllSize": evidence.dll_size,
        "finalState": evidence.final_state,
        "formalConfigSha256After": (
            evidence.formal_config_sha256_after
        ),
        "formalConfigSha256Before": (
            evidence.formal_config_sha256_before
        ),
        "mediaOpenability": dict(evidence.media_openability),
        "mediaStoreManifestSha256": (
            evidence.media_store_manifest_sha256
        ),
        "presentationManifestSha256": (
            evidence.presentation_manifest_sha256
        ),
        "productionWriteCount": evidence.production_write_count,
        "runId": evidence.run_id,
        "runManifestSha256": evidence.run_manifest_sha256,
        "schemaVersion": evidence.schema_version,
        "signerCertificateSha256": (
            evidence.signer_certificate_sha256
        ),
        "transactionSha256": evidence.transaction_sha256,
        "validationFingerprints": {
            "aggregateFingerprint": (
                evidence.validation_aggregate_fingerprint
            ),
            "databaseCoverageFingerprint": (
                evidence.validation_database_coverage_fingerprint
            ),
            "schemaFingerprint": (
                evidence.validation_schema_fingerprint
            ),
        },
        "version": evidence.version,
    }
    return json.dumps(
        value, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def decode_local_trust_evidence(
    payload: bytes,
) -> LocalTrustEvidence:
    if (
        not isinstance(payload, bytes)
        or not 0 < len(payload) <= _MAX_EVIDENCE_BYTES
    ):
        raise ValueError("local_trust_evidence_invalid")
    expected = {
        "architecture",
        "compatibilitySha256",
        "dllSha256",
        "dllSize",
        "finalState",
        "formalConfigSha256After",
        "formalConfigSha256Before",
        "mediaOpenability",
        "mediaStoreManifestSha256",
        "presentationManifestSha256",
        "productionWriteCount",
        "runId",
        "runManifestSha256",
        "schemaVersion",
        "signerCertificateSha256",
        "transactionSha256",
        "validationFingerprints",
        "version",
    }
    fingerprint_names = {
        "aggregateFingerprint",
        "databaseCoverageFingerprint",
        "schemaFingerprint",
    }
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=lambda _value: (
                _ for _ in ()
            ).throw(ValueError("local_trust_evidence_invalid")),
        )
        media = value["mediaOpenability"]
        fingerprints = value["validationFingerprints"]
        if (
            not isinstance(value, dict)
            or set(value) != expected
            or not isinstance(media, dict)
            or tuple(sorted(media)) != _MEDIA_COUNT_NAMES
            or not isinstance(fingerprints, dict)
            or set(fingerprints) != fingerprint_names
        ):
            raise ValueError
        return LocalTrustEvidence(
            schema_version=value["schemaVersion"],
            run_id=value["runId"],
            version=value["version"],
            architecture=value["architecture"],
            dll_size=value["dllSize"],
            dll_sha256=value["dllSha256"],
            signer_certificate_sha256=(
                value["signerCertificateSha256"]
            ),
            transaction_sha256=value["transactionSha256"],
            compatibility_sha256=value["compatibilitySha256"],
            run_manifest_sha256=value["runManifestSha256"],
            validation_schema_fingerprint=(
                fingerprints["schemaFingerprint"]
            ),
            validation_aggregate_fingerprint=(
                fingerprints["aggregateFingerprint"]
            ),
            validation_database_coverage_fingerprint=(
                fingerprints["databaseCoverageFingerprint"]
            ),
            media_openability=tuple(
                (name, media[name]) for name in _MEDIA_COUNT_NAMES
            ),
            presentation_manifest_sha256=(
                value["presentationManifestSha256"]
            ),
            media_store_manifest_sha256=(
                value["mediaStoreManifestSha256"]
            ),
            formal_config_sha256_before=(
                value["formalConfigSha256Before"]
            ),
            formal_config_sha256_after=(
                value["formalConfigSha256After"]
            ),
            production_write_count=value["productionWriteCount"],
            final_state=value["finalState"],
        )
    except (
        KeyError,
        TypeError,
        UnicodeError,
        ValueError,
    ) as error:
        raise ValueError("local_trust_evidence_invalid") from error


def local_trust_evidence_sha256(
    evidence: LocalTrustEvidence,
) -> str:
    return hashlib.sha256(
        encode_local_trust_evidence(evidence)
    ).hexdigest().upper()


def _artifact_path(root: Path, name: str) -> Path:
    if not isinstance(root, Path):
        raise ValueError("local_trust_pair_invalid")
    try:
        canonical = canonical_existing(root)
        metadata = canonical.lstat()
    except (OSError, ValueError) as error:
        raise ValueError("local_trust_pair_invalid") from error
    if (
        canonical != root.absolute()
        or not canonical.is_dir()
        or canonical.is_symlink()
        or getattr(metadata, "st_file_attributes", 0) & 0x400
    ):
        raise ValueError("local_trust_pair_invalid")
    return canonical / name


def _read_trust_file(
    path: Path,
    *,
    verify: Callable[[Path], None],
) -> bytes:
    try:
        metadata = path.lstat()
        identity = (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )
        if (
            not path.is_file()
            or path.is_symlink()
            or getattr(metadata, "st_file_attributes", 0) & 0x400
            or not 0 < metadata.st_size <= _MAX_TRUST_BYTES
        ):
            raise ValueError
        verify(path)
        payload = path.read_bytes()
        after = path.lstat()
        if (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) != identity:
            raise ValueError
        return payload
    except (OSError, ValueError) as error:
        raise ValueError("local_trust_pair_invalid") from error


def read_local_trust_pair(
    *,
    primary_root: Path,
    recovery_root: Path,
    expected_evidence_sha256: str,
    verify: Callable[[Path], None],
) -> LocalTrustReceipt:
    primary_path = _artifact_path(primary_root, _TRUST_FILE)
    recovery_path = _artifact_path(recovery_root, _TRUST_FILE)
    verify(primary_root)
    verify(recovery_root)
    primary_payload = _read_trust_file(
        primary_path, verify=verify
    )
    recovery_payload = _read_trust_file(
        recovery_path, verify=verify
    )
    if primary_payload != recovery_payload:
        raise ValueError("local_trust_pair_invalid")
    try:
        receipt = decode_local_trust_receipt(primary_payload)
    except ValueError as error:
        raise ValueError("local_trust_pair_invalid") from error
    if (
        receipt.evidence_sha256 != expected_evidence_sha256
        or not primary_root.name.endswith("-" + receipt.run_id)
        or recovery_root.name != receipt.run_id
    ):
        raise ValueError("local_trust_pair_invalid")
    return receipt


def write_local_trust_pair(
    *,
    primary_root: Path,
    recovery_root: Path,
    receipt: LocalTrustReceipt,
    restrict: Callable[[Path], None],
    verify: Callable[[Path], None],
) -> LocalTrustReceipt:
    if not isinstance(receipt, LocalTrustReceipt):
        raise TypeError("local_trust_receipt_invalid")
    primary_path = _artifact_path(primary_root, _TRUST_FILE)
    recovery_path = _artifact_path(recovery_root, _TRUST_FILE)
    if (
        os.path.lexists(primary_path)
        or os.path.lexists(recovery_path)
        or not primary_root.name.endswith("-" + receipt.run_id)
        or recovery_root.name != receipt.run_id
    ):
        raise ValueError("local_trust_pair_invalid")
    payload = encode_local_trust_receipt(receipt)
    restrict(recovery_root)
    verify(recovery_root)
    atomic_write_bytes(recovery_path, payload)
    restrict(recovery_path)
    verify(recovery_path)
    restrict(primary_root)
    verify(primary_root)
    atomic_write_bytes(primary_path, payload)
    restrict(primary_path)
    verify(primary_path)
    return read_local_trust_pair(
        primary_root=primary_root,
        recovery_root=recovery_root,
        expected_evidence_sha256=receipt.evidence_sha256,
        verify=verify,
    )


def read_local_trust_evidence_pair(
    *,
    primary_root: Path,
    recovery_root: Path,
    verify: Callable[[Path], None],
) -> LocalTrustEvidence:
    primary_path = _artifact_path(primary_root, _EVIDENCE_FILE)
    recovery_path = _artifact_path(recovery_root, _EVIDENCE_FILE)
    verify(primary_root)
    verify(recovery_root)
    primary_payload = _read_trust_file(
        primary_path, verify=verify
    )
    recovery_payload = _read_trust_file(
        recovery_path, verify=verify
    )
    if primary_payload != recovery_payload:
        raise ValueError("local_trust_evidence_pair_invalid")
    try:
        evidence = decode_local_trust_evidence(primary_payload)
    except ValueError as error:
        raise ValueError(
            "local_trust_evidence_pair_invalid"
        ) from error
    if (
        not primary_root.name.endswith("-" + evidence.run_id)
        or recovery_root.name != evidence.run_id
    ):
        raise ValueError("local_trust_evidence_pair_invalid")
    return evidence


def write_local_trust_evidence_pair(
    *,
    primary_root: Path,
    recovery_root: Path,
    evidence: LocalTrustEvidence,
    restrict: Callable[[Path], None],
    verify: Callable[[Path], None],
) -> LocalTrustEvidence:
    if not isinstance(evidence, LocalTrustEvidence):
        raise TypeError("local_trust_evidence_invalid")
    primary_path = _artifact_path(primary_root, _EVIDENCE_FILE)
    recovery_path = _artifact_path(recovery_root, _EVIDENCE_FILE)
    if (
        os.path.lexists(primary_path)
        or os.path.lexists(recovery_path)
        or not primary_root.name.endswith("-" + evidence.run_id)
        or recovery_root.name != evidence.run_id
    ):
        raise ValueError("local_trust_evidence_pair_invalid")
    payload = encode_local_trust_evidence(evidence)
    restrict(recovery_root)
    verify(recovery_root)
    atomic_write_bytes(recovery_path, payload)
    restrict(recovery_path)
    verify(recovery_path)
    restrict(primary_root)
    verify(primary_root)
    atomic_write_bytes(primary_path, payload)
    restrict(primary_path)
    verify(primary_path)
    reread = read_local_trust_evidence_pair(
        primary_root=primary_root,
        recovery_root=recovery_root,
        verify=verify,
    )
    if reread != evidence:
        raise ValueError("local_trust_evidence_pair_invalid")
    return reread


def read_local_trust_bundle(
    *,
    primary_root: Path,
    recovery_root: Path,
    verify: Callable[[Path], None],
) -> tuple[LocalTrustReceipt, LocalTrustEvidence]:
    evidence = read_local_trust_evidence_pair(
        primary_root=primary_root,
        recovery_root=recovery_root,
        verify=verify,
    )
    evidence_sha256 = local_trust_evidence_sha256(evidence)
    receipt = read_local_trust_pair(
        primary_root=primary_root,
        recovery_root=recovery_root,
        expected_evidence_sha256=evidence_sha256,
        verify=verify,
    )
    if not evidence.matches(receipt):
        raise ValueError("local_trust_bundle_invalid")
    return receipt, evidence


def _stable_sha256(
    path: Path,
    *,
    maximum_bytes: int,
) -> str:
    descriptor = None
    try:
        before = path.lstat()
        if (
            not path.is_file()
            or path.is_symlink()
            or getattr(before, "st_file_attributes", 0) & 0x400
            or not 0 < before.st_size <= maximum_bytes
        ):
            raise ValueError
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        identity = (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
        )
        if identity != (
            before.st_dev,
            before.st_ino,
            before.st_size,
        ):
            raise ValueError
        digest = hashlib.sha256()
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise ValueError
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ValueError
        after = os.fstat(descriptor)
        named = path.lstat()
        if identity != (
            after.st_dev,
            after.st_ino,
            after.st_size,
        ) or identity != (
            named.st_dev,
            named.st_ino,
            named.st_size,
        ) or (
            named.st_mtime_ns,
            named.st_ctime_ns,
        ) != (
            before.st_mtime_ns,
            before.st_ctime_ns,
        ):
            raise ValueError
        return digest.hexdigest().upper()
    except (OSError, ValueError) as error:
        raise ValueError("local_trust_artifact_invalid") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def verify_local_trust_artifacts(
    *,
    primary_root: Path,
    recovery_root: Path,
    account_name: str,
    verify: Callable[[Path], None],
) -> LocalTrustReceipt:
    from weflow_chat.manifest import read_run_manifest
    from weflow_chat.models import TxState
    from weflow_chat.paths import RunLayout
    from weflow_chat.presentation import read_presentation_receipt
    from weflow_chat.transaction import MirroredTransactionStore

    try:
        receipt, evidence = read_local_trust_bundle(
            primary_root=primary_root,
            recovery_root=recovery_root,
            verify=verify,
        )
        layout = RunLayout.from_existing_root(primary_root)
        store = MirroredTransactionStore(
            primary_path=layout.transaction_path,
            recovery_path=recovery_root / "transaction.json",
            storage_available=lambda path: path.exists(),
        )
        transaction = store.read_equal()
        record = transaction.record
        if (
            record.run_id != receipt.run_id
            or record.state is not TxState.ROLLED_BACK
            or record.mirror_degraded
            or record.planned_files
            or record.applied_files
            or transaction.canonical_sha256
            != evidence.transaction_sha256
        ):
            raise ValueError
        compatibility_payload = layout.compatibility_path.read_bytes()
        compatibility = json.loads(
            compatibility_payload.decode("utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=lambda _value: (
                _ for _ in ()
            ).throw(ValueError("local_trust_artifact_invalid")),
        )
        if (
            not isinstance(compatibility, dict)
            or compatibility.get("runId") != receipt.run_id
            or compatibility.get("status") != "compatible"
            or _stable_sha256(
                layout.compatibility_path,
                maximum_bytes=1024 * 1024,
            )
            != evidence.compatibility_sha256
        ):
            raise ValueError
        manifest, _manifest_receipt = read_run_manifest(
            layout,
            expected_run_id=receipt.run_id,
            expected_source_account_name=account_name,
        )
        if (
            manifest.run_id != receipt.run_id
            or _stable_sha256(
                layout.manifest_path,
                maximum_bytes=64 * 1024 * 1024,
            )
            != evidence.run_manifest_sha256
        ):
            raise ValueError
        presentation = read_presentation_receipt(
            primary_root / "presentation-manifest.json",
            expected_presentation_root=(
                primary_root / "presentation"
            ),
            account_name=account_name,
        )
        if (
            presentation.manifest_sha256
            != evidence.presentation_manifest_sha256
            or presentation.manifest.media_store_manifest_sha256
            != evidence.media_store_manifest_sha256
        ):
            raise ValueError
        return receipt
    except (
        OSError,
        TypeError,
        UnicodeError,
        ValueError,
        RuntimeError,
    ) as error:
        raise ValueError("local_trust_artifact_invalid") from error

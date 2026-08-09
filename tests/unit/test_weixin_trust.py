from dataclasses import replace
import json
from pathlib import Path

import pytest

from weflow_chat.weixin_trust import (
    BUILTIN_WEIXIN_CONTRACTS,
    STORED_ENVELOPE_REFRESH,
    BuiltInWeixinContract,
    LocalTrustEvidence,
    LocalTrustReceipt,
    RuntimeWeixinDllIdentity,
    TrustState,
    build_builtin_registry,
    decode_local_trust_evidence,
    decode_local_trust_receipt,
    encode_local_trust_evidence,
    encode_local_trust_receipt,
    local_trust_evidence_sha256,
    read_local_trust_bundle,
    read_local_trust_evidence_pair,
    read_local_trust_pair,
    resolve_builtin_trust,
    resolve_weixin_trust,
    write_local_trust_evidence_pair,
    write_local_trust_pair,
)


_TENCENT = "Tencent Technology (Shenzhen) Company Limited"
_V411_HASH = (
    "03968F3F6DF1C4B9872467E05EC5E84F"
    "7B599466021C2FB47EFD8940F16C9952"
)
_V412_HASH = (
    "4914A621A810ECBC0A132B6FF8F612658"
    "CFCE323D3989B3E5FE32D4FF343BA46"
)
_V412_CERT = (
    "A5260C88F699B19BD6ED100BC08120B4F"
    "D872930EE7538C3D210EB14081A0F45"
)


def _runtime(
    *,
    version: str,
    dll_sha256: str,
    dll_size: int,
    certificate_sha256: str = _V412_CERT,
) -> RuntimeWeixinDllIdentity:
    return RuntimeWeixinDllIdentity(
        version=version,
        architecture="x64",
        dll_size=dll_size,
        dll_sha256=dll_sha256,
        authenticode_status="Valid",
        signer_subject=f"CN={_TENCENT}",
        signer_certificate_sha256=certificate_sha256,
    )


def test_builtin_registry_grants_only_stored_envelope_refresh():
    expected = {
        "4.1.11.24": (_V411_HASH, None),
        "4.1.12.26": (_V412_HASH, 191_480_360),
    }
    assert {
        item.version: (item.dll_sha256, item.dll_size)
        for item in BUILTIN_WEIXIN_CONTRACTS
    } == expected

    for version, (digest, size) in expected.items():
        decision = resolve_builtin_trust(
            _runtime(
                version=version,
                dll_sha256=digest,
                dll_size=size or 1,
            )
        )
        assert decision.state is TrustState.BUILTIN_TRUSTED
        assert decision.capabilities == frozenset(
            {STORED_ENVELOPE_REFRESH}
        )


def test_same_version_different_hash_requires_trial_without_capabilities():
    decision = resolve_builtin_trust(
        _runtime(
            version="4.1.12.26",
            dll_sha256="0" * 64,
            dll_size=191_480_360,
        )
    )
    assert decision.state is TrustState.TRIAL_REQUIRED
    assert decision.capabilities == frozenset()


def test_invalid_signer_is_rejected_before_trial():
    identity = replace(
        _runtime(
            version="4.1.13.1",
            dll_sha256="1" * 64,
            dll_size=1,
        ),
        authenticode_status="NotSigned",
    )
    decision = resolve_builtin_trust(identity)
    assert decision.state is TrustState.REJECTED
    assert decision.capabilities == frozenset()


@pytest.mark.parametrize(
    "changes",
    (
        {"dll_size": True},
        {"dll_sha256": "a" * 64},
        {"version": "4.1.12"},
        {"capabilities": frozenset({"unknown"})},
    ),
)
def test_builtin_contract_rejects_noncanonical_fields(changes):
    values = dict(
        version="4.1.12.26",
        architecture="x64",
        dll_sha256=_V412_HASH,
        dll_size=191_480_360,
        authenticode_status="Valid",
        signer_subject_contains=_TENCENT,
        signer_certificate_sha256=_V412_CERT,
        capabilities=frozenset({STORED_ENVELOPE_REFRESH}),
    )
    values.update(changes)
    with pytest.raises(ValueError, match="builtin_weixin_contract_invalid"):
        BuiltInWeixinContract(**values)


def test_builtin_registry_rejects_duplicate_hashes():
    item = BUILTIN_WEIXIN_CONTRACTS[0]
    with pytest.raises(ValueError, match="builtin_weixin_registry_invalid"):
        build_builtin_registry((item, item))


def _local_receipt() -> LocalTrustReceipt:
    return LocalTrustReceipt(
        schema_version=1,
        run_id="11111111-1111-4111-8111-111111111111",
        version="4.1.13.1",
        architecture="x64",
        dll_size=123,
        dll_sha256="D" * 64,
        signer_certificate_sha256="E" * 64,
        capabilities=frozenset({STORED_ENVELOPE_REFRESH}),
        evidence_sha256="F" * 64,
        created_at_utc="2026-08-05T00:00:00Z",
    )


def _local_evidence() -> LocalTrustEvidence:
    return LocalTrustEvidence(
        schema_version=1,
        run_id="11111111-1111-4111-8111-111111111111",
        version="4.1.13.1",
        architecture="x64",
        dll_size=123,
        dll_sha256="D" * 64,
        signer_certificate_sha256="E" * 64,
        transaction_sha256="1" * 64,
        compatibility_sha256="2" * 64,
        run_manifest_sha256="3" * 64,
        validation_schema_fingerprint="4" * 64,
        validation_aggregate_fingerprint="5" * 64,
        validation_database_coverage_fingerprint="6" * 64,
        media_openability=(
            ("candidateCount", 3),
            ("imageCandidateCount", 2),
            ("localFileCount", 2),
            ("locallyUnavailableCount", 1),
            ("readableImageCount", 1),
            ("readableVideoCount", 1),
            ("unreadableLocalCount", 0),
            ("videoCandidateCount", 1),
        ),
        presentation_manifest_sha256="7" * 64,
        media_store_manifest_sha256="8" * 64,
        formal_config_sha256_before="9" * 64,
        formal_config_sha256_after="9" * 64,
        production_write_count=0,
        final_state="ROLLED_BACK",
    )


def test_local_trust_receipt_roundtrips_canonical_exact_schema():
    receipt = _local_receipt()
    payload = encode_local_trust_receipt(receipt)

    assert decode_local_trust_receipt(payload) == receipt
    assert payload == json.dumps(
        {
            "architecture": "x64",
            "capabilities": ["stored-envelope-refresh"],
            "createdAtUtc": "2026-08-05T00:00:00Z",
            "dllSha256": "D" * 64,
            "dllSize": 123,
            "evidenceSha256": "F" * 64,
            "runId": "11111111-1111-4111-8111-111111111111",
            "schemaVersion": 1,
            "signerCertificateSha256": "E" * 64,
            "version": "4.1.13.1",
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def test_local_trust_evidence_roundtrips_and_hash_is_recomputable():
    evidence = _local_evidence()
    payload = encode_local_trust_evidence(evidence)

    assert decode_local_trust_evidence(payload) == evidence
    assert local_trust_evidence_sha256(evidence) == __import__(
        "hashlib"
    ).sha256(payload).hexdigest().upper()


@pytest.mark.parametrize(
    "field,value",
    (
        ("productionWriteCount", True),
        ("productionWriteCount", 1),
        ("finalState", "COMMITTED"),
        ("formalConfigSha256After", "A" * 64),
    ),
)
def test_local_trust_evidence_rejects_unsafe_terminal_values(
    field, value
):
    encoded = json.loads(
        encode_local_trust_evidence(_local_evidence())
    )
    encoded[field] = value

    with pytest.raises(ValueError, match="local_trust_evidence_invalid"):
        decode_local_trust_evidence(
            json.dumps(encoded).encode("utf-8")
        )


def test_local_trust_evidence_rejects_unreadable_media():
    encoded = json.loads(
        encode_local_trust_evidence(_local_evidence())
    )
    encoded["mediaOpenability"]["unreadableLocalCount"] = 1
    encoded["mediaOpenability"]["localFileCount"] = 3

    with pytest.raises(ValueError, match="local_trust_evidence_invalid"):
        decode_local_trust_evidence(
            json.dumps(encoded).encode("utf-8")
        )


@pytest.mark.parametrize(
    "field,value",
    (
        ("schemaVersion", True),
        ("dllSize", True),
        ("dllSha256", "d" * 64),
        ("capabilities", ["read-only-key-recovery"]),
        ("runId", "{11111111-1111-4111-8111-111111111111}"),
        ("createdAtUtc", "2026-08-05T00:00:00+00:00"),
    ),
)
def test_local_trust_receipt_rejects_noncanonical_values(field, value):
    encoded = json.loads(
        encode_local_trust_receipt(_local_receipt())
    )
    encoded[field] = value
    with pytest.raises(ValueError, match="local_trust_receipt_invalid"):
        decode_local_trust_receipt(
            json.dumps(encoded).encode("utf-8")
        )


def test_local_trust_receipt_rejects_extra_fields():
    encoded = json.loads(
        encode_local_trust_receipt(_local_receipt())
    )
    encoded["extra"] = "forbidden"
    with pytest.raises(ValueError, match="local_trust_receipt_invalid"):
        decode_local_trust_receipt(
            json.dumps(encoded).encode("utf-8")
        )


def _trust_roots(tmp_path: Path, receipt: LocalTrustReceipt):
    primary = tmp_path / ("20260805-000000-" + receipt.run_id)
    recovery = tmp_path / "recovery" / receipt.run_id
    primary.mkdir(parents=True)
    recovery.mkdir(parents=True)
    return primary, recovery


def test_local_trust_pair_writes_recovery_then_primary_and_rereads(tmp_path):
    receipt = _local_receipt()
    primary, recovery = _trust_roots(tmp_path, receipt)
    events = []

    written = write_local_trust_pair(
        primary_root=primary,
        recovery_root=recovery,
        receipt=receipt,
        restrict=lambda path: events.append(("restrict", path)),
        verify=lambda path: events.append(("verify", path)),
    )

    assert written == receipt
    assert events == [
        ("restrict", recovery),
        ("verify", recovery),
        ("restrict", recovery / "local-weixin-trust.json"),
        ("verify", recovery / "local-weixin-trust.json"),
        ("restrict", primary),
        ("verify", primary),
        ("restrict", primary / "local-weixin-trust.json"),
        ("verify", primary / "local-weixin-trust.json"),
        ("verify", primary),
        ("verify", recovery),
        ("verify", primary / "local-weixin-trust.json"),
        ("verify", recovery / "local-weixin-trust.json"),
    ]
    assert read_local_trust_pair(
        primary_root=primary,
        recovery_root=recovery,
        expected_evidence_sha256=receipt.evidence_sha256,
        verify=lambda _path: None,
    ) == receipt


def test_local_trust_pair_rejects_single_copy_and_evidence_drift(tmp_path):
    receipt = _local_receipt()
    primary, recovery = _trust_roots(tmp_path, receipt)
    (recovery / "local-weixin-trust.json").write_bytes(
        encode_local_trust_receipt(receipt)
    )

    with pytest.raises(ValueError, match="local_trust_pair_invalid"):
        read_local_trust_pair(
            primary_root=primary,
            recovery_root=recovery,
            expected_evidence_sha256=receipt.evidence_sha256,
            verify=lambda _path: None,
        )

    (primary / "local-weixin-trust.json").write_bytes(
        encode_local_trust_receipt(receipt)
    )
    with pytest.raises(ValueError, match="local_trust_pair_invalid"):
        read_local_trust_pair(
            primary_root=primary,
            recovery_root=recovery,
            expected_evidence_sha256="0" * 64,
            verify=lambda _path: None,
        )


def test_local_receipt_grants_only_stored_envelope_for_exact_identity():
    receipt = _local_receipt()
    identity = _runtime(
        version=receipt.version,
        dll_sha256=receipt.dll_sha256,
        dll_size=receipt.dll_size,
        certificate_sha256=receipt.signer_certificate_sha256,
    )

    decision = resolve_weixin_trust(
        identity, local_receipts=(receipt,)
    )

    assert decision.state is TrustState.LOCAL_TRUSTED
    assert decision.capabilities == frozenset(
        {STORED_ENVELOPE_REFRESH}
    )


def test_local_trust_bundle_requires_equal_evidence_and_receipt(tmp_path):
    evidence = _local_evidence()
    receipt = replace(
        _local_receipt(),
        evidence_sha256=local_trust_evidence_sha256(evidence),
    )
    primary, recovery = _trust_roots(tmp_path, receipt)
    write_local_trust_evidence_pair(
        primary_root=primary,
        recovery_root=recovery,
        evidence=evidence,
        restrict=lambda _path: None,
        verify=lambda _path: None,
    )
    write_local_trust_pair(
        primary_root=primary,
        recovery_root=recovery,
        receipt=receipt,
        restrict=lambda _path: None,
        verify=lambda _path: None,
    )

    assert read_local_trust_evidence_pair(
        primary_root=primary,
        recovery_root=recovery,
        verify=lambda _path: None,
    ) == evidence
    assert read_local_trust_bundle(
        primary_root=primary,
        recovery_root=recovery,
        verify=lambda _path: None,
    ) == (receipt, evidence)

    changed = json.loads(
        (primary / "local-weixin-trust-evidence.json").read_text(
            encoding="utf-8"
        )
    )
    changed["validationFingerprints"]["schemaFingerprint"] = "A" * 64
    (primary / "local-weixin-trust-evidence.json").write_text(
        json.dumps(changed), encoding="utf-8"
    )
    with pytest.raises(
        ValueError, match="local_trust_evidence_pair_invalid"
    ):
        read_local_trust_bundle(
            primary_root=primary,
            recovery_root=recovery,
            verify=lambda _path: None,
        )

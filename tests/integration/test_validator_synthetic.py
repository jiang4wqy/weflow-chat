import os

import pytest


@pytest.mark.skipif(
    os.environ.get("WEFLOW_RUN_VALIDATOR_SMOKE") != "1"
    or os.environ.get("WEFLOW_RUN_HOST_CONTRACT") != "1",
    reason="requires explicit local copied-Electron smoke",
)
def test_synthetic_validator_gates(validator_runtime, formal_hashes):
    contract = validator_runtime.verify_exact_runtime_contract()
    assert (
        contract.vendor_asar_sha256
        == "F27D53EA61E97365865D999AC7EB03149BDAB670BFEF6851964190CEE5F33E80"
    )
    assert (
        contract.patched_main_sha256
        == "EFA10B99F0293812B5FEFB8014E0AD23DC69ADD7995DB89B1E3C761C8F6F165A"
    )
    assert contract.anchors == {
        "bootAnchorCount": 1,
        "readyAnchorCount": 1,
        "configConstructorCount": 1,
        "wcdbSingletonCount": 1,
    }

    smoke = validator_runtime.run(operation="smoke")
    assert smoke.status == "ok"
    assert vars(smoke.gates) == {
        "userDataIsolated": True,
        "documentsIsolated": True,
        "singleInstanceLockAcquired": True,
        "safeStorageAvailable": True,
        "syntheticEnvelopeRoundtrip": False,
        "nativeProtectionAuthenticated": False,
        "workerSetPathsCalled": False,
    }

    envelope = validator_runtime.run(operation="safe-envelope-roundtrip")
    assert envelope.status == "ok"
    assert vars(envelope.gates) == {
        "userDataIsolated": True,
        "documentsIsolated": True,
        "singleInstanceLockAcquired": True,
        "safeStorageAvailable": True,
        "syntheticEnvelopeRoundtrip": True,
        "nativeProtectionAuthenticated": False,
        "workerSetPathsCalled": False,
    }

    protection = validator_runtime.run_empty_account_test()
    assert protection.status == "compatibility_blocked"
    assert protection.reasonCode == "connection_failed"
    assert not protection.gates.nativeProtectionAuthenticated
    assert protection.validation is None
    assert protection.callsBeforeOpen == ["setPaths", "testConnection"]
    assert protection.gates.workerSetPathsCalled
    formal_hashes.assert_unchanged()


@pytest.mark.skipif(
    os.environ.get("WEFLOW_RUN_VALIDATOR_SMOKE") != "1"
    or os.environ.get("WEFLOW_RUN_HOST_CONTRACT") != "1",
    reason="requires explicit local copied-Electron contract",
)
def test_complete_runtime_manifest_rejects_extra_and_module_drift(
    validator_runtime,
):
    app = (
        validator_runtime.run_layout.root
        / "runtime"
        / "WeFlow"
        / "resources"
        / "app"
    )
    extra = app / "dist-electron" / "unexpected.cjs"
    extra.write_text("module.exports = {};", encoding="utf-8")
    with pytest.raises(RuntimeError, match="patched_app_tree_changed"):
        validator_runtime.verify_exact_runtime_contract()
    extra.unlink()
    module = app / "dist-electron" / "worker-gateway.cjs"
    module.write_bytes(module.read_bytes() + b"\n")
    with pytest.raises(
        RuntimeError, match="patched_(app|runtime)_tree_changed"
    ):
        validator_runtime.verify_exact_runtime_contract()

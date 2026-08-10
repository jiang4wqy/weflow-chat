import inspect
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import weflow_chat.validator.install_copy as install_copy
from weflow_chat.validator.install_copy import (
    _COPIED_MODULE_CONTRACT,
    _REPOSITORY_ROOT,
    _copy_install_verified_for_test,
    copy_install_verified,
    patch_copied_runtime,
)


def test_public_copy_accepts_only_layout_and_bound_source():
    assert tuple(inspect.signature(copy_install_verified).parameters) == (
        "layout",
        "source",
    )


def test_repository_copied_modules_match_current_build_contract():
    import hashlib

    for relative, expected in _COPIED_MODULE_CONTRACT.items():
        raw = (
            _REPOSITORY_ROOT / "validator-node" / "src" / relative.name
        ).read_bytes()
        assert (len(raw), hashlib.sha256(raw).hexdigest().upper()) == expected


def test_task4_final_copied_module_contracts_are_exact():
    import hashlib

    expected = {
        Path("dist-electron/validator-entry.cjs"): (
            17543,
            "2800CF8946B2C8846EBE8F29938C822C8CB96D092D19B8F6303BDE4878720CC3",
        ),
                Path("dist-electron/worker-gateway.cjs"): (
                    27645,
                    "109E9C4D29124947BCC6DF124710FE9D70F28C6543FB81B1D60F63FCE42AFEBE",
        ),
    }
    for relative, contract in expected.items():
        raw = (
            _REPOSITORY_ROOT / "validator-node" / "src" / relative.name
        ).read_bytes()
        assert (len(raw), hashlib.sha256(raw).hexdigest().upper()) == contract
        assert _COPIED_MODULE_CONTRACT[relative] == contract


def test_private_copy_verifies_a_synthetic_tree(tmp_path):
    source = tmp_path / "synthetic-install"
    destination = tmp_path / "run" / "runtime" / "WeFlow"
    (source / "resources").mkdir(parents=True)
    (source / "WeFlow.exe").write_bytes(b"exe")
    (source / "resources" / "app.asar").write_bytes(b"asar")
    contract = {
        Path("WeFlow.exe"): _sha(b"exe"),
        Path("resources/app.asar"): _sha(b"asar"),
    }
    copied = _copy_install_verified_for_test(
        source=source, destination=destination, contract=contract
    )
    assert copied == destination.resolve()


def test_private_copy_rejects_a_changed_source(tmp_path):
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir()
    (source / "WeFlow.exe").write_bytes(b"before")
    contract = {Path("WeFlow.exe"): _sha(b"before")}

    def mutating_copytree(src, dst):
        import shutil

        shutil.copytree(src, dst)
        (src / "WeFlow.exe").write_bytes(b"after")

    with pytest.raises(RuntimeError, match="formal_install_changed"):
        _copy_install_verified_for_test(
            source=source,
            destination=destination,
            contract=contract,
            copytree=mutating_copytree,
        )


def test_patch_allows_slow_windows_asar_extraction(
    monkeypatch,
    tmp_path,
):
    runtime = tmp_path / "runtime" / "WeFlow"
    runtime.mkdir(parents=True)
    observed = {}

    def completed_run(*args, **kwargs):
        observed["timeout"] = kwargs["timeout"]
        return SimpleNamespace(
            stdout=json.dumps(
                {
                    "version": 1,
                    "runtimeHashes": {},
                    "extractedHashes": {},
                    "copiedModuleHashes": {},
                    "anchors": {},
                    "patchedMainSha256": "A" * 64,
                    "vendorAsarSha256": "B" * 64,
                }
            )
        )

    monkeypatch.setattr(
        install_copy.subprocess,
        "run",
        completed_run,
    )

    patch_copied_runtime(
        layout=SimpleNamespace(root=tmp_path),
        runtime_root=runtime,
    )

    assert observed["timeout"] == 1200


def _sha(value):
    import hashlib

    return hashlib.sha256(value).hexdigest().upper()

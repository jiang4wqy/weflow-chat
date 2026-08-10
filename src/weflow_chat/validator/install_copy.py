from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
from typing import Callable, Mapping

from weflow_chat.paths import RunLayout, assert_descendant, canonical_existing


_CONTRACT = {
    Path("WeFlow.exe"):
        "5E9007F1FCE332C4038628FB2EAE0518FC6DCA252041A1563B0AD60292FA6A13",
    Path("resources/app.asar"):
        "F27D53EA61E97365865D999AC7EB03149BDAB670BFEF6851964190CEE5F33E80",
    Path("resources/resources/wcdb/win32/x64/wcdb_api.dll"):
        "5D5DFFE151F6CF7C1122D34FB6C6F5E902685547CFED83891EDF8C23B78907B2",
    Path("resources/resources/wcdb/win32/x64/WCDB.dll"):
        "DE80DC7B9117076F7F77E5AB5D6EE8DC44F8D3829C10549A800AF2E4E219EBF8",
}
_EXTRACTED_CONTRACT = {
    Path("resources/app/dist-electron/config-C9Ue62at.js"):
        "77F636C0E8C39E10C774E80ECC1AEA5503BAA8BB6E853D16108D2D182D9B6045",
    Path("resources/app/dist-electron/wcdbWorker.js"):
        "C53892300A724D60CA5C733316332C47E20E41465B5396F764C0BE265C576890",
}
_BASE_TREE_SHA256 = (
    "3E6B03B4390F68762279B96A9A67FE536D29AF639F6F66312F8A0D354BF79AF4"
)
_PATCHED_MAIN = (
    2532306,
    "51B9B75A1A1E575381692AD36988F97C0690E4BFFC8554443AA1DF3554D835C8",
)
_COPIED_MODULE_CONTRACT = {
    Path("dist-electron/validator-entry.cjs"): (
        17543,
        "2800CF8946B2C8846EBE8F29938C822C8CB96D092D19B8F6303BDE4878720CC3",
    ),
    Path("dist-electron/path-policy.cjs"): (
        2967,
        "3A864F017A36E73743E3045BDB68313DD7C67BC9274B1EBF9C47F800250CFA6F",
    ),
    Path("dist-electron/worker-gateway.cjs"): (
        27645,
        "109E9C4D29124947BCC6DF124710FE9D70F28C6543FB81B1D60F63FCE42AFEBE",
    ),
    Path("dist-electron/avatar-aggregate.cjs"): (
        3489,
        "4515698E4B431F7BF93539D9885C6E3FDE126C53DE71528A86053FE9B3E1E31B",
    ),
    Path("dist-electron/aggregate.cjs"): (
        3444,
        "E4DF825B52B07EF06A02FF49E2D4947F7AA7685C0EAC794528EB9EA9A59288D9",
    ),
    Path("dist-electron/sanitize-result.cjs"): (
        7216,
        "B8590A81C10FDF6C16AE556E56608214958D6A73AE71A3562CC959646172C67C",
    ),
}
_REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
_NODE_ENTRY = (
    _REPOSITORY_ROOT / "validator-node" / "src" / "extract-and-patch.mjs"
)
_PATCH_TIMEOUT_SECONDS = 1200


@dataclass(frozen=True, slots=True)
class PatchReceipt:
    patched_main_sha256: str
    vendor_asar_sha256: str
    anchors: dict[str, int]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def _assert_plain_tree(root: Path) -> None:
    absolute = root.absolute()
    cursor = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        cursor = cursor / part
        if not cursor.exists():
            raise RuntimeError("runtime_path_missing")
        info = cursor.lstat()
        if cursor.is_symlink() or (
            getattr(info, "st_file_attributes", 0)
            & stat.FILE_ATTRIBUTE_REPARSE_POINT
        ):
            raise RuntimeError("runtime_reparse_rejected")
    for current, directories, files in os.walk(root, followlinks=False):
        for name in (*directories, *files):
            target = Path(current, name)
            info = target.lstat()
            if target.is_symlink() or (
                getattr(info, "st_file_attributes", 0)
                & stat.FILE_ATTRIBUTE_REPARSE_POINT
            ):
                raise RuntimeError("runtime_reparse_rejected")


def _capture(root: Path, contract: Mapping[Path, str]) -> dict[str, str]:
    _assert_plain_tree(root)
    return {item.as_posix(): _sha256(root / item) for item in contract}


def _verify(root: Path, contract: Mapping[Path, str]) -> dict[str, str]:
    actual = _capture(root, contract)
    expected = {item.as_posix(): value for item, value in contract.items()}
    if actual != expected:
        raise RuntimeError("compatibility_blocked")
    return actual


def _tree_manifest(root: Path) -> tuple[tuple, ...]:
    _assert_plain_tree(root)
    values = []
    for target in root.rglob("*"):
        relative = target.relative_to(root).as_posix()
        if target.is_dir():
            values.append(("D", relative))
        elif target.is_file():
            values.append(
                ("F", relative, target.stat().st_size, _sha256(target))
            )
        else:
            raise RuntimeError("runtime_non_ordinary_entry")
    return tuple(sorted(values, key=lambda item: item[1]))


def _manifest_bytes(value: tuple[tuple, ...]) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")


def _tree_signature(root: Path) -> tuple[tuple, ...]:
    return _tree_manifest(root)


def _copy_install_verified_for_test(
    *,
    source: Path,
    destination: Path,
    contract: Mapping[Path, str],
    copytree: Callable = shutil.copytree,
    expected_tree_sha256: str | None = None,
    persist_tree_manifest: bool = False,
) -> Path:
    source = canonical_existing(source)
    if destination.exists():
        raise RuntimeError("runtime_destination_exists")
    before = _verify(source, contract)
    before_tree = _tree_signature(source)
    before_tree_sha256 = hashlib.sha256(
        _manifest_bytes(before_tree)
    ).hexdigest().upper()
    if (
        expected_tree_sha256 is not None
        and before_tree_sha256 != expected_tree_sha256
    ):
        raise RuntimeError("formal_install_tree_changed")
    destination.parent.mkdir(parents=True, exist_ok=True)
    copytree(source, destination)
    after = _capture(source, contract)
    after_tree = _tree_signature(source)
    if before != after or before_tree != after_tree:
        raise RuntimeError("formal_install_changed")
    copied = _verify(destination, contract)
    if before != copied or before_tree != _tree_signature(destination):
        raise RuntimeError("runtime_copy_mismatch")
    if persist_tree_manifest:
        target = destination / "validator-base-tree.json"
        with target.open("xb") as stream:
            stream.write(_manifest_bytes(before_tree))
            stream.flush()
            os.fsync(stream.fileno())
        if (
            hashlib.sha256(target.read_bytes()).hexdigest().upper()
            != expected_tree_sha256
        ):
            raise RuntimeError("runtime_base_manifest_mismatch")
    return destination.resolve(strict=True)


def copy_install_verified(*, layout: RunLayout, source: Path) -> Path:
    destination = layout.root / "runtime" / "WeFlow"
    assert_descendant(destination, layout.root)
    return _copy_install_verified_for_test(
        source=source,
        destination=destination,
        contract=_CONTRACT,
        expected_tree_sha256=_BASE_TREE_SHA256,
        persist_tree_manifest=True,
    )


def patch_copied_runtime(
    *, layout: RunLayout, runtime_root: Path
) -> PatchReceipt:
    expected = (layout.root / "runtime" / "WeFlow").resolve(strict=True)
    actual = canonical_existing(runtime_root)
    assert_descendant(actual, layout.root)
    if actual != expected:
        raise RuntimeError("runtime_root_rejected")
    node_entry = canonical_existing(_NODE_ENTRY)
    assert_descendant(node_entry, _REPOSITORY_ROOT)
    completed = subprocess.run(
        ["node", str(node_entry), "--runtime-root", str(actual)],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="strict",
        timeout=_PATCH_TIMEOUT_SECONDS,
    )
    raw = json.loads(completed.stdout)
    if set(raw) != {
        "version",
        "runtimeHashes",
        "extractedHashes",
        "copiedModuleHashes",
        "anchors",
        "patchedMainSha256",
        "vendorAsarSha256",
    }:
        raise RuntimeError("patch_receipt_schema_mismatch")
    return PatchReceipt(
        raw["patchedMainSha256"],
        raw["vendorAsarSha256"],
        dict(raw["anchors"]),
    )


def _asar_tree(archive: Path) -> tuple[tuple, ...]:
    with archive.open("rb") as stream:
        prefix = stream.read(16)
        if len(prefix) != 16:
            raise RuntimeError("asar_header_invalid")
        length = int.from_bytes(prefix[12:16], "little")
        encoded = stream.read(length)
    try:
        header = json.loads(encoded)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError("asar_header_invalid") from error
    values = []

    def visit(node: dict, parts: tuple[str, ...]) -> None:
        children = node.get("files")
        if isinstance(children, dict):
            if parts:
                values.append(("D", PurePosixPath(*parts).as_posix()))
            for name, child in children.items():
                if (
                    not isinstance(name, str)
                    or not name
                    or name in {".", ".."}
                    or "/" in name
                    or "\\" in name
                    or not isinstance(child, dict)
                ):
                    raise RuntimeError("asar_header_invalid")
                visit(child, (*parts, name))
            return
        if "link" in node:
            raise RuntimeError("asar_link_rejected")
        integrity = node.get("integrity")
        size, digest = node.get("size"), integrity and integrity.get("hash")
        if (
            not parts
            or not isinstance(size, int)
            or size < 0
            or not isinstance(digest, str)
            or len(digest) != 64
            or set(digest.upper()) - set("0123456789ABCDEF")
        ):
            raise RuntimeError("asar_header_invalid")
        values.append(
            ("F", PurePosixPath(*parts).as_posix(), size, digest.upper())
        )

    visit(header, ())
    return tuple(sorted(values, key=lambda item: item[1]))


def _verify_complete_patched_tree(runtime: Path, patch_raw: dict) -> None:
    base_path = runtime / "validator-base-tree.json"
    base_bytes = base_path.read_bytes()
    if hashlib.sha256(base_bytes).hexdigest().upper() != _BASE_TREE_SHA256:
        raise RuntimeError("runtime_base_manifest_mismatch")
    base_json = json.loads(base_bytes)
    if (
        not isinstance(base_json, list)
        or _manifest_bytes(tuple(tuple(item) for item in base_json))
        != base_bytes
    ):
        raise RuntimeError("runtime_base_manifest_mismatch")
    base = tuple(tuple(item) for item in base_json)

    vendor = runtime / "resources" / "app.vendor.asar"
    app = runtime / "resources" / "app"
    expected_app = {item[1]: item for item in _asar_tree(vendor)}
    expected_app["dist-electron/main.js"] = (
        "F",
        "dist-electron/main.js",
        *_PATCHED_MAIN,
    )
    for relative, (size, digest) in _COPIED_MODULE_CONTRACT.items():
        name = relative.as_posix()
        expected_app[name] = ("F", name, size, digest)
    patch_path = app / "validator-patch.json"
    patch_bytes = patch_path.read_bytes()
    if patch_bytes != json.dumps(
        patch_raw, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8"):
        raise RuntimeError("patch_manifest_not_canonical")
    expected_app["validator-patch.json"] = (
        "F",
        "validator-patch.json",
        len(patch_bytes),
        hashlib.sha256(patch_bytes).hexdigest().upper(),
    )
    expected_app_tree = tuple(
        sorted(expected_app.values(), key=lambda item: item[1])
    )
    if _tree_manifest(app) != expected_app_tree:
        raise RuntimeError("patched_app_tree_changed")

    expected_runtime = {}
    for item in base:
        if item[1] == "resources/app.asar":
            replacement = list(item)
            replacement[1] = "resources/app.vendor.asar"
            expected_runtime[replacement[1]] = tuple(replacement)
        else:
            expected_runtime[item[1]] = item
    for item in expected_app_tree:
        relative = f"resources/app/{item[1]}"
        expected_runtime[relative] = (item[0], relative, *item[2:])
    expected_runtime["resources/app"] = ("D", "resources/app")
    expected_runtime["validator-base-tree.json"] = (
        "F",
        "validator-base-tree.json",
        len(base_bytes),
        _BASE_TREE_SHA256,
    )
    expected = tuple(
        sorted(expected_runtime.values(), key=lambda item: item[1])
    )
    if _tree_manifest(runtime) != expected:
        raise RuntimeError("patched_runtime_tree_changed")


def verify_copied_runtime_contract(*, layout: RunLayout) -> PatchReceipt:
    runtime = canonical_existing(layout.root / "runtime" / "WeFlow")
    assert_descendant(runtime, layout.root)
    _assert_plain_tree(runtime)
    raw = json.loads(
        (
            runtime
            / "resources"
            / "app"
            / "validator-patch.json"
        ).read_text(encoding="utf-8")
    )
    main_hash = _sha256(
        runtime / "resources" / "app" / "dist-electron" / "main.js"
    )
    expected_keys = {
        "version",
        "runtimeHashes",
        "extractedHashes",
        "copiedModuleHashes",
        "anchors",
        "patchedMainSha256",
        "vendorAsarSha256",
    }
    expected_anchors = {
        "bootAnchorCount": 1,
        "readyAnchorCount": 1,
        "configConstructorCount": 1,
        "wcdbSingletonCount": 1,
    }
    runtime_expected = {
        item.as_posix(): value for item, value in _CONTRACT.items()
    }
    extracted_expected = {
        item.relative_to("resources/app").as_posix(): value
        for item, value in _EXTRACTED_CONTRACT.items()
    }
    module_expected = {
        item.as_posix(): digest
        for item, (_, digest) in _COPIED_MODULE_CONTRACT.items()
    }
    final_contract = {
        (
            item
            if item != Path("resources/app.asar")
            else Path("resources/app.vendor.asar")
        ): value
        for item, value in _CONTRACT.items()
    }
    if (
        set(raw) != expected_keys
        or raw["version"] != 1
        or raw["runtimeHashes"] != runtime_expected
        or raw["extractedHashes"]
        != {
            **extracted_expected,
            "dist-electron/main.js":
                "1ABB5B41D039AA84FD43D734C1213F47815616141A30C99DA92BB183F803AADD",
        }
        or raw["copiedModuleHashes"] != module_expected
        or raw["anchors"] != expected_anchors
        or raw["vendorAsarSha256"]
        != _CONTRACT[Path("resources/app.asar")]
        or raw["patchedMainSha256"] != _PATCHED_MAIN[1]
        or main_hash != _PATCHED_MAIN[1]
        or len(main_hash) != 64
        or main_hash != main_hash.upper()
    ):
        raise RuntimeError("patched_runtime_changed")
    _verify(runtime, final_contract)
    _verify(runtime, _EXTRACTED_CONTRACT)
    _verify_complete_patched_tree(runtime, raw)
    return PatchReceipt(
        main_hash, raw["vendorAsarSha256"], dict(raw["anchors"])
    )

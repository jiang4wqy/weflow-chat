import builtins
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from weflow_chat.config import (
    PreparedChange,
    build_planned_files,
    create_dual_config_backup,
    invalidate_target_sns_cache,
    prepare_stored_key_cutover,
    read_backup_bundle,
    replace_cutover_config,
    replace_top_level_json_string,
)
from weflow_chat.models import PlannedFile
from weflow_chat.paths import PathBoundaryError
from weflow_chat.security import SecurityMetadata
import weflow_chat.security as security_module


@pytest.fixture
def config_profile(tmp_path: Path):
    live = tmp_path / "live"
    live.mkdir()
    config = live / "WeFlow-config.json"
    cache = live / "WeFlow-cache-maps.json"
    config.write_text(json.dumps({
        "dbPath": r"E:\\old", "myWxid": "wxid_test",
        "decryptKey": "safe:SYNTHETIC_NOT_A_REAL_ENVELOPE",
    }), encoding="utf-8")
    cache.write_text(json.dumps({
        "snsPageCacheMap": {
            "sns_page:wxid_test": {"drop": True},
            "sns_page:wxid_other": {"keep": True},
        }
    }), encoding="utf-8")
    return {
        "config": config,
        "cache": cache,
        "missing_analytics": live / "analytics_cache.json",
    }


class FakeSecurityAdapter:
    def __init__(self):
        self.values = {}
        self.restricted = {}
        self.restrict_calls = {}

    def capture(self, path):
        return self.values.setdefault(str(path.resolve()), SecurityMetadata(
            file_attributes=32, owner_sid="S-1-5-21-test",
            group_sid="S-1-5-18", dacl_sddl="D:synthetic"))

    def restrict_backup_tree(self, path):
        root = str(path.resolve())
        self.restrict_calls[root] = self.restrict_calls.get(root, 0) + 1
        self.restricted[root] = {
            str(child.resolve()) for child in path.rglob("*")
            if child.is_file()}

    def verify_restricted_backup_tree(self, path):
        root = str(path.resolve())
        assert root in self.restricted
        assert self.restricted[root] == {
            str(child.resolve()) for child in path.rglob("*")
            if child.is_file()}

    def restore(self, path, value):
        self.values[str(path.resolve())] = value

    def verify(self, path, value):
        assert self.values[str(path.resolve())] == value


@pytest.fixture
def fake_security_adapter():
    return FakeSecurityAdapter()


def make_bundle(config_profile, tmp_path, fake_security_adapter):
    return create_dual_config_backup(
        [config_profile["config"], config_profile["cache"],
         config_profile["missing_analytics"]],
        primary_root=tmp_path / "e-backup",
        recovery_root=tmp_path / "c-backup",
        run_id="11111111-1111-1111-1111-111111111111",
        security_adapter=fake_security_adapter)


def test_config_patch_changes_only_top_level_dbpath(config_profile):
    before = config_profile["config"].read_bytes()
    after = replace_top_level_json_string(
        before, field="dbPath", new_value=r"E:\\run\\active")
    old = json.loads(before)
    new = json.loads(after)
    old["dbPath"] = r"E:\\run\\active"
    assert new == old
    assert b"safe:SYNTHETIC_NOT_A_REAL_ENVELOPE" in after


def test_config_cutover_preserves_all_stored_key_envelopes():
    before = {
        "dbPath": r"F:\old\wxid_test",
        "cachePath": "",
        "myWxid": "wxid_test",
        "decryptKey": "safe:STALE_TOP",
        "wxidConfigs": {
            "wxid_test": {
                "decryptKey": "safe:STALE_CURRENT",
                "preserved": {"value": True},
            },
            "wxid_other": {
                "decryptKey": "safe:OTHER_ACCOUNT",
            },
        },
        "future": [1, "two", False],
    }
    after_bytes = replace_cutover_config(
        json.dumps(before).encode("utf-8"),
        active_parent=Path(r"E:\Snapshots\run\active"),
    )

    after = json.loads(after_bytes)
    expected = json.loads(json.dumps(before))
    expected["dbPath"] = r"E:\Snapshots\run\active"
    assert after == expected
    assert (
        after["wxidConfigs"]["wxid_other"]["decryptKey"]
        == "safe:OTHER_ACCOUNT"
    )


def test_config_cutover_sets_presentation_and_dedicated_media_cache_only():
    before = {
        "dbPath": r"E:\Snapshots\old\active",
        "cachePath": "",
        "myWxid": "wxid_test",
        "decryptKey": "safe:CURRENT_TOP",
        "imageAesKey": "safe:IMAGE_TOP",
        "imageXorKey": "safe:XOR_TOP",
        "wxidConfigs": {
            "wxid_test": {
                "decryptKey": "safe:CURRENT_NESTED",
                "imageAesKey": "safe:IMAGE_NESTED",
                "imageXorKey": "safe:XOR_NESTED",
            },
        },
        "preserved": {"future": True},
    }

    after = json.loads(replace_cutover_config(
        json.dumps(before).encode("utf-8"),
        active_parent=Path(r"X:\synthetic\Snapshots\run\presentation"),
        cache_path=Path(r"X:\synthetic\DerivedCache"),
    ))

    expected = json.loads(json.dumps(before))
    expected["dbPath"] = r"X:\synthetic\Snapshots\run\presentation"
    expected["cachePath"] = r"X:\synthetic\DerivedCache"
    assert after == expected


def test_prepared_cutover_carries_presentation_and_dedicated_cache(
        tmp_path: Path) -> None:
    config = tmp_path / "WeFlow-config.json"
    cache_maps = tmp_path / "WeFlow-cache-maps.json"
    analytics = tmp_path / "analytics_cache.json"
    presentation = tmp_path / "run" / "presentation"
    derived_cache = tmp_path / "derived-cache"
    presentation.mkdir(parents=True)
    derived_cache.mkdir()
    config.write_text(json.dumps({
        "dbPath": str(tmp_path / "old-active"),
        "cachePath": "",
        "myWxid": "wxid_test",
        "decryptKey": "safe:CURRENT",
    }), encoding="utf-8")
    cache_maps.write_text("{}", encoding="utf-8")

    changes = prepare_stored_key_cutover(
        config_path=config,
        cache_path=cache_maps,
        analytics_path=analytics,
        active_parent=presentation,
        weflow_cache_path=derived_cache,
        account_id="wxid_test",
    )

    config_change = next(
        item for item in changes if item.live_path == str(config.resolve())
    )
    updated = json.loads(config_change.payload)
    assert updated["dbPath"] == str(presentation)
    assert updated["cachePath"] == str(derived_cache)


def test_cache_invalidation_is_targeted(config_profile):
    after = invalidate_target_sns_cache(
        config_profile["cache"].read_bytes(), account_id="wxid_test")
    value = json.loads(after)
    assert "sns_page:wxid_test" not in value["snsPageCacheMap"]
    assert "sns_page:wxid_other" in value["snsPageCacheMap"]


def test_dual_backup_preserves_absence_and_plans_it(
        config_profile, tmp_path, fake_security_adapter):
    bundle = make_bundle(config_profile, tmp_path, fake_security_adapter)
    missing = next(item for item in bundle.items
                   if item.live_path.endswith("analytics_cache.json"))
    assert missing.existed_before is False
    assert (Path(bundle.receipt.primary_manifest_path).read_bytes() ==
            Path(bundle.receipt.recovery_manifest_path).read_bytes())
    restored = read_backup_bundle(
        primary_manifest_path=bundle.receipt.primary_manifest_path,
        recovery_manifest_path=bundle.receipt.recovery_manifest_path,
        expected_run_id=bundle.run_id,
        expected_sha256=bundle.receipt.canonical_sha256,
        security_adapter=fake_security_adapter)
    assert restored == bundle
    changes = tuple(PreparedChange(
        live_path=item.live_path, action="replace", payload=b"new",
        expected_old_sha256=item.expected_old_sha256,
        expected_new_sha256="F" * 64)
        for item in restored.items if item.existed_before)
    planned = build_planned_files(changes, restored)
    absent = next(item for item in planned
                  if item.live_path.endswith("analytics_cache.json"))
    assert absent.action == "delete_if_created"
    assert absent.existed_before is False


def test_final_acl_normalization_covers_payloads_and_manifests(
        config_profile, tmp_path, fake_security_adapter):
    bundle = make_bundle(config_profile, tmp_path, fake_security_adapter)
    for root in (Path(bundle.primary_root), Path(bundle.recovery_root)):
        key = str(root.resolve())
        assert fake_security_adapter.restrict_calls[key] == 2
        assert fake_security_adapter.restricted[key] == {
            str(child.resolve()) for child in root.rglob("*")
            if child.is_file()}
        assert str((root / "backup-manifest.json").resolve()) in (
            fake_security_adapter.restricted[key])
        assert len(fake_security_adapter.restricted[key]) == 3


def test_build_planned_files_is_task3_standalone(monkeypatch):
    item = SimpleNamespace(
        live_path=r"C:\\synthetic\\analytics_cache.json",
        existed_before=False, expected_old_sha256=None)
    original_import = builtins.__import__

    def reject_transaction_import(name, *args, **kwargs):
        if name == "weflow_chat.transaction":
            raise AssertionError("task3_imported_task4_transaction")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", reject_transaction_import)
    assert build_planned_files((), SimpleNamespace(items=(item,))) == (
        PlannedFile(live_path=item.live_path, action="delete_if_created",
                    existed_before=False, expected_old_sha256=None,
                    expected_new_sha256=None),)


def test_pre_cutover_verification_requires_recorded_absence(
        config_profile, tmp_path, fake_security_adapter):
    bundle = make_bundle(config_profile, tmp_path, fake_security_adapter)
    config_profile["missing_analytics"].write_bytes(b"appeared-late")
    with pytest.raises(ValueError, match="live_absence_changed_before_cutover"):
        bundle.verify_both_copies_and_old_hashes(fake_security_adapter)


def test_restore_candidate_reparse_is_rejected_before_hash_read(
        config_profile, tmp_path, fake_security_adapter, monkeypatch):
    bundle = make_bundle(config_profile, tmp_path, fake_security_adapter)
    item = next(value for value in bundle.items if value.existed_before)
    rejected = Path(item.recovery_backup_path)
    original_canonical = security_module.canonical_existing
    original_hash = security_module.sha256_file

    def reject_reparse(path):
        if Path(path) == rejected:
            raise PathBoundaryError("reparse_component_rejected")
        return original_canonical(path)

    def forbid_early_hash(path):
        if Path(path) == rejected:
            raise AssertionError("reparse_target_was_read")
        return original_hash(path)

    monkeypatch.setattr(security_module, "canonical_existing", reject_reparse)
    monkeypatch.setattr(security_module, "sha256_file", forbid_early_hash)
    with pytest.raises(PathBoundaryError, match="reparse_component_rejected"):
        item.resolve_verified_restore_copy()


def test_backup_reader_rejects_unknown_schema_fields(
        config_profile, tmp_path, fake_security_adapter):
    bundle = make_bundle(config_profile, tmp_path, fake_security_adapter)
    payload = json.loads(Path(
        bundle.receipt.primary_manifest_path).read_text(encoding="utf-8"))
    payload["unexpected"] = True
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    Path(bundle.receipt.primary_manifest_path).write_text(encoded, encoding="utf-8")
    Path(bundle.receipt.recovery_manifest_path).write_text(encoded, encoding="utf-8")
    with pytest.raises(ValueError, match="invalid_backup_manifest"):
        read_backup_bundle(
            primary_manifest_path=bundle.receipt.primary_manifest_path,
            recovery_manifest_path=bundle.receipt.recovery_manifest_path,
            expected_run_id=bundle.run_id,
            expected_sha256=bundle.receipt.canonical_sha256,
            security_adapter=fake_security_adapter)


@pytest.mark.parametrize("invalid_mirror", ["primary", "recovery"])
@pytest.mark.parametrize("corruption", [
    "unknown_field", "wrong_hash", "wrong_root",
])
def test_backup_reader_recovers_from_one_strictly_invalid_mirror(
        config_profile, tmp_path, fake_security_adapter, invalid_mirror,
        corruption):
    bundle = make_bundle(config_profile, tmp_path, fake_security_adapter)
    source = Path(getattr(
        bundle.receipt, invalid_mirror + "_manifest_path"))
    untrusted = tmp_path / ("untrusted-" + invalid_mirror + ".json")
    payload = json.loads(source.read_text(encoding="utf-8"))
    if corruption == "unknown_field":
        payload["unexpected"] = True
    elif corruption == "wrong_hash":
        payload["items"][0]["expectedOldSha256"] = "0" * 64
    else:
        root_key = invalid_mirror + "Root"
        payload[root_key] = str(tmp_path / ("wrong-" + invalid_mirror))
    untrusted.write_text(json.dumps(
        payload, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    rebuilt = read_backup_bundle(
        primary_manifest_path=(untrusted if invalid_mirror == "primary" else
                               bundle.receipt.primary_manifest_path),
        recovery_manifest_path=(untrusted if invalid_mirror == "recovery" else
                                bundle.receipt.recovery_manifest_path),
        expected_run_id=bundle.run_id,
        expected_sha256=bundle.receipt.canonical_sha256,
        security_adapter=fake_security_adapter)
    assert rebuilt.items == bundle.items
    assert rebuilt.receipt.primary_manifest_path == str(
        Path(bundle.primary_root) / "backup-manifest.json")
    assert rebuilt.receipt.recovery_manifest_path == str(
        Path(bundle.recovery_root) / "backup-manifest.json")
    assert str(untrusted) not in (
        rebuilt.receipt.primary_manifest_path,
        rebuilt.receipt.recovery_manifest_path)


def test_backup_reader_rejects_when_no_strictly_valid_mirror_remains(
        config_profile, tmp_path, fake_security_adapter):
    bundle = make_bundle(config_profile, tmp_path, fake_security_adapter)
    manifests = []
    for mirror in ("primary", "recovery"):
        source = Path(getattr(bundle.receipt, mirror + "_manifest_path"))
        untrusted = tmp_path / ("untrusted-" + mirror + ".json")
        payload = json.loads(source.read_text(encoding="utf-8"))
        payload["unexpected"] = True
        untrusted.write_text(json.dumps(
            payload, sort_keys=True, separators=(",", ":")), encoding="utf-8")
        manifests.append(untrusted)
    with pytest.raises(ValueError, match="invalid_backup_manifest"):
        read_backup_bundle(
            primary_manifest_path=manifests[0],
            recovery_manifest_path=manifests[1],
            expected_run_id=bundle.run_id,
            expected_sha256=bundle.receipt.canonical_sha256,
            security_adapter=fake_security_adapter)


@pytest.mark.parametrize("offline", ["primary", "recovery"])
def test_backup_reader_accepts_either_manifest_and_backup_copy(
        config_profile, tmp_path, fake_security_adapter, offline):
    bundle = make_bundle(config_profile, tmp_path, fake_security_adapter)
    offline_root = Path(getattr(bundle, offline + "_root"))
    offline_root.rename(offline_root.with_name(offline_root.name + ".offline"))
    rebuilt = read_backup_bundle(
        primary_manifest_path=(None if offline == "primary" else
                               bundle.receipt.primary_manifest_path),
        recovery_manifest_path=(None if offline == "recovery" else
                                bundle.receipt.recovery_manifest_path),
        expected_run_id=bundle.run_id,
        expected_sha256=bundle.receipt.canonical_sha256,
        security_adapter=fake_security_adapter)
    rebuilt.verify_at_least_one_backup_copy()
    available_root = Path(getattr(
        rebuilt, ("recovery" if offline == "primary" else "primary") +
        "_root"))
    assert all(item.resolve_verified_restore_copy().parent == available_root
               for item in rebuilt.items if item.existed_before)


def test_backup_reader_ignores_mirror_with_wrong_run_id(
        config_profile, tmp_path, fake_security_adapter):
    bundle = make_bundle(config_profile, tmp_path, fake_security_adapter)
    primary = Path(bundle.receipt.primary_manifest_path)
    payload = json.loads(primary.read_text(encoding="utf-8"))
    payload["runId"] = "33333333-3333-3333-3333-333333333333"
    primary.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")),
                       encoding="utf-8")
    rebuilt = read_backup_bundle(
        primary_manifest_path=bundle.receipt.primary_manifest_path,
        recovery_manifest_path=bundle.receipt.recovery_manifest_path,
        expected_run_id=bundle.run_id,
        expected_sha256=bundle.receipt.canonical_sha256,
        security_adapter=fake_security_adapter)
    assert rebuilt.items == bundle.items


@pytest.mark.parametrize("bad_mirror", ["primary", "recovery"])
def test_backup_reader_rejects_valid_manifest_when_its_own_payload_is_bad(
        config_profile, tmp_path, fake_security_adapter, bad_mirror):
    bundle = make_bundle(config_profile, tmp_path, fake_security_adapter)
    bad_root = Path(getattr(bundle, bad_mirror + "_root"))
    next(path for path in bad_root.iterdir()
         if path.name != "backup-manifest.json").write_bytes(b"tampered")
    other_manifest = Path(getattr(
        bundle.receipt,
        ("recovery" if bad_mirror == "primary" else "primary") +
        "_manifest_path"))
    invalid_other = json.loads(other_manifest.read_text(encoding="utf-8"))
    invalid_other["unexpected"] = True
    other_manifest.write_text(json.dumps(
        invalid_other, sort_keys=True, separators=(",", ":")),
        encoding="utf-8")
    with pytest.raises(ValueError, match="invalid_backup_manifest"):
        read_backup_bundle(
            primary_manifest_path=bundle.receipt.primary_manifest_path,
            recovery_manifest_path=bundle.receipt.recovery_manifest_path,
            expected_run_id=bundle.run_id,
            expected_sha256=bundle.receipt.canonical_sha256,
            security_adapter=fake_security_adapter)


@pytest.mark.parametrize("bad_mirror", ["primary", "recovery"])
def test_backup_reader_uses_only_mirror_with_intact_own_payloads(
        config_profile, tmp_path, fake_security_adapter, bad_mirror):
    bundle = make_bundle(config_profile, tmp_path, fake_security_adapter)
    bad_root = Path(getattr(bundle, bad_mirror + "_root"))
    next(path for path in bad_root.iterdir()
         if path.name != "backup-manifest.json").write_bytes(b"tampered")
    rebuilt = read_backup_bundle(
        primary_manifest_path=bundle.receipt.primary_manifest_path,
        recovery_manifest_path=bundle.receipt.recovery_manifest_path,
        expected_run_id=bundle.run_id,
        expected_sha256=bundle.receipt.canonical_sha256,
        security_adapter=fake_security_adapter)
    rebuilt.verify_at_least_one_backup_copy()
    assert rebuilt.items == bundle.items


def _write_duplicate_key_manifest(path: Path, *, location: str) -> None:
    text = path.read_text(encoding="utf-8")
    if location == "top":
        path.write_text('{"schemaVersion":1,' + text[1:], encoding="utf-8")
        return
    value = json.loads(text)
    encoded_live_path = json.dumps(value["items"][0]["livePath"])
    key = '"livePath":' + encoded_live_path
    path.write_text(text.replace(key, key + "," + key, 1), encoding="utf-8")


@pytest.mark.parametrize("location", ["top", "item"])
@pytest.mark.parametrize("invalid_mirror", ["primary", "recovery"])
def test_backup_reader_ignores_duplicate_key_manifest_when_other_is_valid(
        config_profile, tmp_path, fake_security_adapter, location,
        invalid_mirror):
    bundle = make_bundle(config_profile, tmp_path, fake_security_adapter)
    invalid = Path(getattr(
        bundle.receipt, invalid_mirror + "_manifest_path"))
    _write_duplicate_key_manifest(invalid, location=location)
    rebuilt = read_backup_bundle(
        primary_manifest_path=bundle.receipt.primary_manifest_path,
        recovery_manifest_path=bundle.receipt.recovery_manifest_path,
        expected_run_id=bundle.run_id,
        expected_sha256=bundle.receipt.canonical_sha256,
        security_adapter=fake_security_adapter)
    assert rebuilt.items == bundle.items


@pytest.mark.parametrize("location", ["top", "item"])
def test_backup_reader_rejects_duplicate_key_manifests_when_none_are_valid(
        config_profile, tmp_path, fake_security_adapter, location):
    bundle = make_bundle(config_profile, tmp_path, fake_security_adapter)
    for manifest in (
            Path(bundle.receipt.primary_manifest_path),
            Path(bundle.receipt.recovery_manifest_path)):
        _write_duplicate_key_manifest(manifest, location=location)
    with pytest.raises(ValueError, match="invalid_backup_manifest"):
        read_backup_bundle(
            primary_manifest_path=bundle.receipt.primary_manifest_path,
            recovery_manifest_path=bundle.receipt.recovery_manifest_path,
            expected_run_id=bundle.run_id,
            expected_sha256=bundle.receipt.canonical_sha256,
            security_adapter=fake_security_adapter)

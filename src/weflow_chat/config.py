import hashlib
import json
import os
import uuid
from dataclasses import dataclass
from pathlib import Path

from weflow_chat.atomic_io import atomic_write_bytes, atomic_write_json
from weflow_chat.audit import AuditEvent, AuditStage, AuditStatus, AuditWriter
from weflow_chat.manifest import sha256_file
from weflow_chat.models import PlannedFile
from weflow_chat.paths import canonical_existing, canonical_future
from weflow_chat.security import (
    BackupBundle,
    BackupItem,
    BackupReceipt,
    SecurityAdapter,
    SecurityMetadata,
)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest().upper()


@dataclass(frozen=True, slots=True)
class PreparedChange:
    live_path: str
    action: str
    payload: bytes | None
    expected_old_sha256: str | None
    expected_new_sha256: str | None


def _skip_ws(text: str, offset: int) -> int:
    while offset < len(text) and text[offset] in " \t\r\n":
        offset += 1
    return offset


def _string_end(text: str, start: int) -> int:
    if start >= len(text) or text[start] != '"':
        raise ValueError("json_string_required")
    escaped = False
    for offset in range(start + 1, len(text)):
        char = text[offset]
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == '"':
            return offset + 1
    raise ValueError("unterminated_json_string")


def _top_level_value_span(text: str, field: str) -> tuple[int, int]:
    decoder = json.JSONDecoder()
    offset = _skip_ws(text, 0)
    if offset >= len(text) or text[offset] != "{":
        raise ValueError("root_json_object_required")
    offset += 1
    matches = []
    while True:
        offset = _skip_ws(text, offset)
        if offset < len(text) and text[offset] == "}":
            break
        key_end = _string_end(text, offset)
        key = json.loads(text[offset:key_end])
        offset = _skip_ws(text, key_end)
        if offset >= len(text) or text[offset] != ":":
            raise ValueError("json_colon_required")
        value_start = _skip_ws(text, offset + 1)
        value, value_end = decoder.raw_decode(text, value_start)
        if key == field:
            if not isinstance(value, str):
                raise ValueError("target_json_value_not_string")
            matches.append((value_start, value_end))
        offset = _skip_ws(text, value_end)
        if offset < len(text) and text[offset] == ",":
            offset += 1
            continue
        if offset < len(text) and text[offset] == "}":
            break
        raise ValueError("json_object_separator_required")
    if len(matches) != 1:
        raise ValueError("target_json_field_not_unique")
    return matches[0]


def replace_top_level_json_string(
        payload: bytes, *, field: str, new_value: str) -> bytes:
    text = payload.decode("utf-8")
    start, end = _top_level_value_span(text, field)
    replacement = json.dumps(new_value, ensure_ascii=False)
    changed = (text[:start] + replacement + text[end:]).encode("utf-8")
    before = json.loads(payload)
    after = json.loads(changed)
    expected = dict(before)
    expected[field] = new_value
    if after != expected:
        raise ValueError("config_semantic_diff_rejected")
    return changed


def replace_cutover_config(
    payload: bytes,
    *,
    active_parent: Path,
    cache_path: Path | None = None,
) -> bytes:
    changed = replace_top_level_json_string(
        payload,
        field="dbPath",
        new_value=str(active_parent),
    )
    if cache_path is not None:
        changed = replace_top_level_json_string(
            changed,
            field="cachePath",
            new_value=str(cache_path),
        )
    return changed


def invalidate_target_sns_cache(payload: bytes, *, account_id: str) -> bytes:
    value = json.loads(payload)
    if not isinstance(value, dict):
        raise ValueError("cache_root_not_object")
    maps = value.get("snsPageCacheMap")
    if maps is not None and not isinstance(maps, dict):
        raise ValueError("sns_cache_map_not_object")
    if maps is not None:
        maps.pop("sns_page:" + account_id, None)
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


_BACKUP_KEYS = {"schemaVersion", "runId", "primaryRoot", "recoveryRoot", "items"}
_BACKUP_ITEM_KEYS = {
    "livePath", "existedBefore", "primaryBackupPath", "recoveryBackupPath",
    "expectedOldSha256", "security",
}
_SECURITY_KEYS = {"fileAttributes", "ownerSid", "groupSid", "daclSddl"}


def _backup_item_json(item: BackupItem) -> dict[str, object]:
    security = None if item.security is None else {
        "fileAttributes": item.security.file_attributes,
        "ownerSid": item.security.owner_sid,
        "groupSid": item.security.group_sid,
        "daclSddl": item.security.dacl_sddl,
    }
    return {
        "livePath": item.live_path,
        "existedBefore": item.existed_before,
        "primaryBackupPath": item.primary_backup_path,
        "recoveryBackupPath": item.recovery_backup_path,
        "expectedOldSha256": item.expected_old_sha256,
        "security": security,
    }


def _backup_manifest_json(*, run_id: str, primary_root: Path,
                          recovery_root: Path,
                          items: tuple[BackupItem, ...]) -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "runId": run_id,
        "primaryRoot": str(primary_root),
        "recoveryRoot": str(recovery_root),
        "items": [_backup_item_json(item) for item in items],
    }


def _canonical_json_bytes(value: dict[str, object]) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def _stored_path_equal(left: str, right: Path) -> bool:
    return os.path.normcase(os.path.normpath(left)) == os.path.normcase(
        os.path.normpath(str(right)))


def _reject_duplicate_json_keys(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate_backup_manifest_key")
        value[key] = item
    return value


def _strict_backup_item(value: object, *, primary_root: str,
                        recovery_root: str) -> BackupItem:
    if not isinstance(value, dict) or set(value) != _BACKUP_ITEM_KEYS:
        raise ValueError("invalid_backup_item_schema")
    if not isinstance(value["livePath"], str):
        raise ValueError("invalid_backup_live_path")
    existed = value["existedBefore"]
    if type(existed) is not bool:
        raise ValueError("invalid_backup_existence_flag")
    live = canonical_future(Path(value["livePath"]))
    if str(live) != value["livePath"]:
        raise ValueError("backup_live_path_identity_changed")
    primary_value = value["primaryBackupPath"]
    recovery_value = value["recoveryBackupPath"]
    security_value = value["security"]
    old_hash = value["expectedOldSha256"]
    if existed:
        if (not isinstance(primary_value, str) or
                not isinstance(recovery_value, str) or
                not isinstance(old_hash, str) or
                set(old_hash) - set("0123456789ABCDEF") or
                len(old_hash) != 64 or
                not isinstance(security_value, dict) or
                set(security_value) != _SECURITY_KEYS):
            raise ValueError("invalid_present_backup_item")
        if (not _stored_path_equal(primary_value, Path(primary_root) / live.name) or
                not _stored_path_equal(recovery_value, Path(recovery_root) / live.name) or
                type(security_value["fileAttributes"]) is not int or
                not all(isinstance(security_value[key], str) and security_value[key]
                        for key in ("ownerSid", "groupSid", "daclSddl"))):
            raise ValueError("invalid_backup_path_or_security")
        primary = primary_value
        recovery = recovery_value
        security = SecurityMetadata(
            file_attributes=security_value["fileAttributes"],
            owner_sid=security_value["ownerSid"],
            group_sid=security_value["groupSid"],
            dacl_sddl=security_value["daclSddl"])
    else:
        if any(item is not None for item in (
                primary_value, recovery_value, old_hash, security_value)):
            raise ValueError("invalid_absent_backup_item")
        primary = recovery = security = None
    return BackupItem(str(live), existed, primary, recovery, old_hash, security)


def _verify_mirror_payloads(
        items: tuple[BackupItem, ...], *, mirror: str,
        canonical_root: Path) -> None:
    for item in items:
        expected = canonical_root / Path(item.live_path).name
        if not item.existed_before:
            if os.path.lexists(expected):
                raise ValueError("absent_backup_payload_present")
            continue
        stored = (item.primary_backup_path if mirror == "primary"
                  else item.recovery_backup_path)
        if stored is None:
            raise ValueError("missing_backup_payload_path")
        candidate = canonical_existing(Path(stored))
        if (str(candidate) != stored or candidate != expected or
                sha256_file(candidate) != item.expected_old_sha256):
            raise ValueError("backup_payload_identity_or_hash_mismatch")


def _read_available_manifest(
        supplied: Path | str | None) -> tuple[Path, bytes] | None:
    if supplied is None:
        return None
    try:
        path = canonical_existing(Path(supplied))
        return path, path.read_bytes()
    except OSError:
        return None


def _strict_backup_manifest(
        candidate: tuple[Path, bytes], *, mirror: str, run_id: str,
        expected_sha256: str, security_adapter: SecurityAdapter
        ) -> tuple[dict[str, object], bytes, tuple[BackupItem, ...], str, str]:
    path, payload = candidate
    try:
        value = json.loads(payload, object_pairs_hook=_reject_duplicate_json_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError("invalid_backup_manifest") from error
    if (not isinstance(value, dict) or set(value) != _BACKUP_KEYS or
            value["schemaVersion"] != 1 or value["runId"] != run_id or
            not isinstance(value["items"], list)):
        raise ValueError("invalid_backup_manifest")
    canonical = _canonical_json_bytes(value)
    if _sha256_bytes(canonical) != expected_sha256:
        raise ValueError("invalid_backup_manifest")
    primary_root = value["primaryRoot"]
    recovery_root = value["recoveryRoot"]
    if not isinstance(primary_root, str) or not isinstance(recovery_root, str):
        raise ValueError("invalid_backup_roots")
    root = primary_root if mirror == "primary" else recovery_root
    canonical_root = canonical_existing(Path(root))
    expected_manifest = canonical_root / "backup-manifest.json"
    if not _stored_path_equal(str(path), expected_manifest):
        raise ValueError("backup_manifest_path_mismatch")
    security_adapter.verify_restricted_backup_tree(canonical_root)
    items = tuple(_strict_backup_item(
        item, primary_root=primary_root, recovery_root=recovery_root)
        for item in value["items"])
    if (not items or
            len({item.live_path.casefold() for item in items}) != len(items)):
        raise ValueError("invalid_backup_item_set")
    _verify_mirror_payloads(
        items, mirror=mirror, canonical_root=canonical_root)
    return value, canonical, items, primary_root, recovery_root


def read_backup_bundle(
        *, primary_manifest_path: Path | str | None,
        recovery_manifest_path: Path | str | None,
        expected_run_id: str, expected_sha256: str,
        security_adapter: SecurityAdapter) -> BackupBundle:
    run_id = str(uuid.UUID(expected_run_id))
    if (not isinstance(expected_sha256, str) or len(expected_sha256) != 64 or
            set(expected_sha256) - set("0123456789ABCDEF")):
        raise ValueError("invalid_backup_manifest_hash")
    primary = _read_available_manifest(primary_manifest_path)
    recovery = _read_available_manifest(recovery_manifest_path)
    readable = [item for item in (primary, recovery) if item is not None]
    if not readable:
        raise ValueError("backup_manifest_unavailable")
    validated = []
    for mirror, candidate in (("primary", primary), ("recovery", recovery)):
        if candidate is None:
            continue
        try:
            validated.append(_strict_backup_manifest(
                candidate, mirror=mirror, run_id=run_id,
                expected_sha256=expected_sha256,
                security_adapter=security_adapter))
        except (OSError, ValueError):
            continue
    if not validated:
        raise ValueError("invalid_backup_manifest")
    if len(validated) == 2 and validated[0][1] != validated[1][1]:
        raise ValueError("backup_manifests_diverged")
    _, _, items, primary_root, recovery_root = validated[0]
    receipt = BackupReceipt(
        run_id,
        str(Path(primary_root) / "backup-manifest.json"),
        str(Path(recovery_root) / "backup-manifest.json"),
        expected_sha256,
        len(items))
    bundle = BackupBundle(run_id, items, primary_root, recovery_root, receipt)
    bundle.verify_at_least_one_backup_copy()
    return bundle


def create_dual_config_backup(
        live_paths: tuple[Path, ...] | list[Path], *, primary_root: Path,
        recovery_root: Path, run_id: str, security_adapter: SecurityAdapter,
        audit_path: Path | None = None) -> BackupBundle:
    run_id = str(uuid.UUID(run_id))
    if primary_root.exists() or recovery_root.exists():
        raise ValueError("backup_root_exists")
    primary_root = canonical_future(primary_root)
    recovery_root = canonical_future(recovery_root)
    primary_root.mkdir(parents=True, exist_ok=False)
    recovery_root.mkdir(parents=True, exist_ok=False)
    for root in (primary_root, recovery_root):
        security_adapter.restrict_backup_tree(root)
        security_adapter.verify_restricted_backup_tree(root)
    audit = AuditWriter(audit_path or primary_root.parent / "audit.jsonl")
    audit.append(AuditEvent(
        stage=AuditStage.BACKUP, status=AuditStatus.STARTED,
        normalized_paths=("source/config-backup-primary",
                          "source/config-backup-recovery"),
        file_count=len(live_paths)))
    items = []
    names = set()
    for supplied in live_paths:
        live = canonical_future(supplied)
        folded_name = live.name.casefold()
        if folded_name in names:
            raise ValueError("backup_basename_collision")
        names.add(folded_name)
        if live.exists():
            live = canonical_existing(live)
            metadata = security_adapter.capture(live)
            old_hash = sha256_file(live)
            primary = primary_root / live.name
            recovery = recovery_root / live.name
            payload = live.read_bytes()
            atomic_write_bytes(primary, payload)
            atomic_write_bytes(recovery, payload)
            item = BackupItem(str(live), True, str(primary), str(recovery),
                              old_hash, metadata)
        else:
            item = BackupItem(str(live), False, None, None, None, None)
        items.append(item)
    item_tuple = tuple(items)
    payload = _backup_manifest_json(run_id=run_id, primary_root=primary_root,
                                    recovery_root=recovery_root, items=item_tuple)
    canonical_hash = _sha256_bytes(_canonical_json_bytes(payload))
    primary_manifest = primary_root / "backup-manifest.json"
    recovery_manifest = recovery_root / "backup-manifest.json"
    atomic_write_json(recovery_manifest, payload)
    atomic_write_json(primary_manifest, payload)
    for root in (primary_root, recovery_root):
        security_adapter.restrict_backup_tree(root)
        security_adapter.verify_restricted_backup_tree(root)
    rebuilt = read_backup_bundle(
        primary_manifest_path=primary_manifest,
        recovery_manifest_path=recovery_manifest,
        expected_run_id=run_id, expected_sha256=canonical_hash,
        security_adapter=security_adapter)
    rebuilt.verify_both_copies_and_old_hashes(security_adapter)
    audit.append(AuditEvent(
        stage=AuditStage.BACKUP, status=AuditStatus.OK,
        normalized_paths=("source/backup-manifest-primary",
                          "source/backup-manifest-recovery"),
        file_count=len(item_tuple), sha256_values=(canonical_hash,)))
    return rebuilt


def build_planned_files(
        changes: tuple[PreparedChange, ...], bundle: BackupBundle
        ) -> tuple[PlannedFile, ...]:
    by_path = {item.live_path.casefold(): item for item in bundle.items}
    if len(by_path) != len(bundle.items):
        raise ValueError("duplicate_backup_item")
    if len({change.live_path.casefold() for change in changes}) != len(changes):
        raise ValueError("duplicate_prepared_change")
    planned = []
    for change in changes:
        item = by_path.pop(change.live_path.casefold(), None)
        if (item is None or item.live_path != change.live_path or
                not item.existed_before or
                change.expected_old_sha256 != item.expected_old_sha256 or
                change.action not in {"replace", "delete"}):
            raise ValueError("prepared_change_backup_mismatch")
        planned.append(PlannedFile(
            live_path=item.live_path, action=change.action,
            existed_before=True, expected_old_sha256=change.expected_old_sha256,
            expected_new_sha256=change.expected_new_sha256))
    for item in by_path.values():
        if not item.existed_before:
            planned.append(PlannedFile(
                live_path=item.live_path, action="delete_if_created",
                existed_before=False, expected_old_sha256=None,
                expected_new_sha256=None))
        else:
            raise ValueError("missing_prepared_change")
    return tuple(planned)


def _replace_change(path: Path, payload: bytes) -> PreparedChange:
    canonical = canonical_existing(path)
    return PreparedChange(
        live_path=str(canonical), action="replace", payload=payload,
        expected_old_sha256=sha256_file(canonical),
        expected_new_sha256=_sha256_bytes(payload))


def prepare_stored_key_cutover(
        *, config_path: Path, cache_path: Path, analytics_path: Path,
        active_parent: Path, account_id: str,
        weflow_cache_path: Path | None = None,
        ) -> tuple[PreparedChange, ...]:
    cache = canonical_existing(cache_path)
    config = canonical_existing(config_path)
    changes = [_replace_change(
        cache, invalidate_target_sns_cache(cache.read_bytes(), account_id=account_id))]
    if analytics_path.exists():
        analytics = canonical_existing(analytics_path)
        changes.append(PreparedChange(
            live_path=str(analytics), action="delete", payload=None,
            expected_old_sha256=sha256_file(analytics), expected_new_sha256=None))
    new_config = replace_cutover_config(
        config.read_bytes(),
        active_parent=active_parent,
        cache_path=(
            None
            if weflow_cache_path is None
            else canonical_existing(weflow_cache_path)
        ),
    )
    changes.append(_replace_change(config, new_config))
    return tuple(changes)

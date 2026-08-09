from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import weflow_chat.media_budget as media_budget
from weflow_chat.media_budget import calculate_media_post_staging_budget
from weflow_chat.vss import MediaStagingFile, MediaStagingReceipt


ACCOUNT_NAME = "wxid_test"
GIB = 2**30


def _manifest_sha(files: tuple[MediaStagingFile, ...]) -> str:
    payload = json.dumps(
        [
            {
                "relativePath": item.relative_path,
                "size": item.size,
                "sha256": item.sha256,
            }
            for item in files
        ],
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return sha256(payload).hexdigest().upper()


def _receipt(
    staging_path: Path,
    *files: MediaStagingFile,
) -> MediaStagingReceipt:
    items = tuple(files)
    return MediaStagingReceipt(
        staging_path=staging_path,
        source_account_name=ACCOUNT_NAME,
        files=items,
        file_count=len(items),
        byte_count=sum(item.size for item in items),
        manifest_sha256=_manifest_sha(items),
    )


def test_first_import_uses_the_larger_of_import_and_final_tree_peaks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    staging = tmp_path / "media-staging"
    destination = tmp_path / "media-store"
    staging.mkdir()
    destination.mkdir()
    delta = _receipt(
        staging,
        MediaStagingFile("msg/attach/a.bin", 400_000_000, "A" * 64),
        MediaStagingFile("msg/video/b.bin", 300_000_000, "B" * 64),
    )
    monkeypatch.setattr(
        media_budget.shutil,
        "disk_usage",
        lambda path: SimpleNamespace(free=2_180_000_000),
    )

    result = calculate_media_post_staging_budget(
        prior_inventory=None,
        delta_receipt=delta,
        source_db_bytes=100_000_000,
        validation_db_bytes=100_000_000,
        active_db_bytes=100_000_000,
        presentation_db_bytes=106_258_176,
        existing_destination_volume_root=destination,
    )

    assert result.mergedMediaBytes == 700_000_000
    assert result.deltaBytes == 700_000_000
    assert result.requiredFreeBytes == 2_180_000_000
    assert result.observedFreeBytes == 2_180_000_000


def test_zero_delta_keeps_existing_store_for_first_full_slot_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    staging = tmp_path / "media-staging"
    destination = tmp_path / "media-store"
    staging.mkdir()
    destination.mkdir()
    prior = (
        MediaStagingFile("msg/attach/a.bin", 500, "A" * 64),
        MediaStagingFile("msg/video/disappeared.bin", 250, "B" * 64),
    )
    delta = _receipt(staging)
    expected = GIB + 750 + 70
    monkeypatch.setattr(
        media_budget.shutil,
        "disk_usage",
        lambda path: SimpleNamespace(free=expected),
    )

    result = calculate_media_post_staging_budget(
        prior_inventory=prior,
        delta_receipt=delta,
        source_db_bytes=10,
        validation_db_bytes=10,
        active_db_bytes=20,
        presentation_db_bytes=30,
        existing_destination_volume_root=destination,
    )

    assert result.mergedMediaBytes == 750
    assert result.deltaBytes == 0
    assert result.requiredFreeBytes == expected


def test_post_staging_budget_includes_the_future_source_database_copy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    staging = tmp_path / "media-staging"
    destination = tmp_path / "media-store"
    staging.mkdir()
    destination.mkdir()
    delta = _receipt(staging)
    expected = GIB + 101
    monkeypatch.setattr(
        media_budget.shutil,
        "disk_usage",
        lambda path: SimpleNamespace(free=expected),
    )

    result = calculate_media_post_staging_budget(
        prior_inventory=None,
        delta_receipt=delta,
        source_db_bytes=101,
        validation_db_bytes=0,
        active_db_bytes=0,
        presentation_db_bytes=0,
        existing_destination_volume_root=destination,
    )

    assert result.requiredFreeBytes == expected


@pytest.mark.parametrize(
    ("old_size", "new_size", "expected_required"),
    [
        (100, 150, GIB + 150),
        (100, 40, GIB + 40),
        (100, 100, GIB + 100),
    ],
    ids=["larger", "smaller", "same-size-new-hash"],
)
def test_changed_file_replaces_old_size_and_reserves_atomic_coexistence(
    old_size: int,
    new_size: int,
    expected_required: int,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    staging = tmp_path / "media-staging"
    destination = tmp_path / "media-store"
    staging.mkdir()
    destination.mkdir()
    prior = (
        MediaStagingFile("msg/attach/changed.bin", old_size, "A" * 64),
    )
    delta = _receipt(
        staging,
        MediaStagingFile("msg/attach/changed.bin", new_size, "B" * 64),
    )
    monkeypatch.setattr(
        media_budget.shutil,
        "disk_usage",
        lambda path: SimpleNamespace(free=expected_required),
    )

    result = calculate_media_post_staging_budget(
        prior_inventory=prior,
        delta_receipt=delta,
        source_db_bytes=0,
        validation_db_bytes=0,
        active_db_bytes=0,
        presentation_db_bytes=0,
        existing_destination_volume_root=destination,
    )

    assert result.mergedMediaBytes == new_size
    assert result.deltaBytes == new_size
    assert result.requiredFreeBytes == expected_required


def test_import_peak_uses_the_complete_prepared_delta(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    staging = tmp_path / "media-staging"
    destination = tmp_path / "media-store"
    staging.mkdir()
    destination.mkdir()
    delta = _receipt(
        staging,
        MediaStagingFile("msg/attach/a.bin", 5, "A" * 64),
        MediaStagingFile("msg/attach/b.bin", 11, "B" * 64),
        MediaStagingFile("msg/video/c.bin", 7, "C" * 64),
    )
    expected = GIB + 23
    monkeypatch.setattr(
        media_budget.shutil,
        "disk_usage",
        lambda path: SimpleNamespace(free=expected),
    )

    result = calculate_media_post_staging_budget(
        prior_inventory=None,
        delta_receipt=delta,
        source_db_bytes=0,
        validation_db_bytes=0,
        active_db_bytes=0,
        presentation_db_bytes=0,
        existing_destination_volume_root=destination,
    )

    assert result.requiredFreeBytes == expected


def test_prior_inventory_must_be_an_exact_tuple(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    staging = tmp_path / "media-staging"
    destination = tmp_path / "media-store"
    staging.mkdir()
    destination.mkdir()
    delta = _receipt(staging)
    monkeypatch.setattr(
        media_budget.shutil,
        "disk_usage",
        lambda path: SimpleNamespace(free=10 * GIB),
    )

    with pytest.raises(
        media_budget.MediaBudgetError,
        match=r"^media_budget_input_invalid$",
    ):
        calculate_media_post_staging_budget(
            prior_inventory=[],  # type: ignore[arg-type]
            delta_receipt=delta,
            source_db_bytes=0,
            validation_db_bytes=0,
            active_db_bytes=0,
            presentation_db_bytes=0,
            existing_destination_volume_root=destination,
        )


def test_duplicate_delta_path_is_rejected_before_space_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    staging = tmp_path / "media-staging"
    destination = tmp_path / "media-store"
    staging.mkdir()
    destination.mkdir()
    duplicate = _receipt(
        staging,
        MediaStagingFile("msg/attach/a.bin", 1, "A" * 64),
        MediaStagingFile("msg/attach/a.bin", 1, "A" * 64),
    )
    called = False

    def disk_usage(_path):
        nonlocal called
        called = True
        return SimpleNamespace(free=10 * GIB)

    monkeypatch.setattr(media_budget.shutil, "disk_usage", disk_usage)
    with pytest.raises(
        media_budget.MediaBudgetError,
        match=r"^media_budget_input_invalid$",
    ):
        calculate_media_post_staging_budget(
            prior_inventory=None,
            delta_receipt=duplicate,
            source_db_bytes=0,
            validation_db_bytes=0,
            active_db_bytes=0,
            presentation_db_bytes=0,
            existing_destination_volume_root=destination,
        )
    assert called is False


def test_insufficient_space_fails_closed_at_one_byte_below_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    staging = tmp_path / "media-staging"
    destination = tmp_path / "media-store"
    staging.mkdir()
    destination.mkdir()
    delta = _receipt(
        staging,
        MediaStagingFile("msg/attach/a.bin", 10, "A" * 64),
    )
    required = GIB + 10
    monkeypatch.setattr(
        media_budget.shutil,
        "disk_usage",
        lambda _path: SimpleNamespace(free=required - 1),
    )

    with pytest.raises(
        media_budget.MediaBudgetError,
        match=r"^media_post_staging_space_insufficient$",
    ):
        calculate_media_post_staging_budget(
            prior_inventory=None,
            delta_receipt=delta,
            source_db_bytes=0,
            validation_db_bytes=0,
            active_db_bytes=0,
            presentation_db_bytes=0,
            existing_destination_volume_root=destination,
        )


def test_invalid_free_space_probe_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    staging = tmp_path / "media-staging"
    destination = tmp_path / "media-store"
    staging.mkdir()
    destination.mkdir()
    delta = _receipt(staging)
    monkeypatch.setattr(
        media_budget.shutil,
        "disk_usage",
        lambda _path: SimpleNamespace(free=-1),
    )

    with pytest.raises(
        media_budget.MediaBudgetError,
        match=r"^media_budget_space_probe_invalid$",
    ):
        calculate_media_post_staging_budget(
            prior_inventory=None,
            delta_receipt=delta,
            source_db_bytes=0,
            validation_db_bytes=0,
            active_db_bytes=0,
            presentation_db_bytes=0,
            existing_destination_volume_root=destination,
        )

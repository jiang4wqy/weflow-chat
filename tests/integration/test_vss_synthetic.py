from __future__ import annotations

import os
from pathlib import Path, PureWindowsPath
import uuid

import pytest

from weflow_chat.vss import (
    ShadowState,
    VssHelperClient,
    acquire_vss_staging,
    remove_synthetic_tree,
)


@pytest.mark.skipif(
    os.environ.get("WEFLOW_RUN_VSS_SMOKE") != "1",
    reason="requires explicit local UAC VSS smoke opt-in")
def test_owned_shadow_stages_synthetic_bytes_and_ends_deleted() -> None:
    run_id = str(uuid.uuid4())
    source_account_name = "wxid_test_vss"
    allowed = Path(os.environ["WEFLOW_CHAT_VSS_SOURCE_ROOT"])
    source = allowed / run_id / source_account_name / "db_storage"
    staging_allowed = Path(os.environ["WEFLOW_CHAT_VSS_SNAPSHOTS_ROOT"])
    run_root = staging_allowed / ("synthetic-" + run_id)
    source_volume = source.anchor.upper()
    primary_error: Exception | None = None
    cleanup_errors: list[Exception] = []
    try:
        source.mkdir(parents=True)
        run_root.mkdir(parents=True)
        client = VssHelperClient(source_volume=source_volume)
        (source / "session.db").write_bytes(b"synthetic-session")
        receipt = acquire_vss_staging(
            client=client, run_id=run_id, source_volume=source_volume,
            live_path=source, source_account_name=source_account_name,
            run_root=run_root, snapshots_root=staging_allowed)
        assert receipt.staging_path == run_root / "vss-staging"
        assert receipt.source_account_name == source_account_name
        assert receipt.account_db_relative_path == PureWindowsPath(
            source_account_name, "db_storage")
        assert (
            receipt.staging_path / receipt.account_db_relative_path /
            "session.db"
        ).read_bytes() == b"synthetic-session"
        assert "GLOBALROOT" not in str(receipt.staging_path)
        final = client.inspect_owned(run_id=run_id)
        assert final.state is ShadowState.DELETED
    except Exception as error:
        primary_error = error
    finally:
        synthetic_run_root = source.parents[1]
        if synthetic_run_root.exists():
            try:
                remove_synthetic_tree(synthetic_run_root, allowed_root=allowed)
            except Exception as error:
                cleanup_errors.append(error)
        if run_root.exists():
            try:
                remove_synthetic_tree(
                    run_root, allowed_root=staging_allowed)
            except Exception as error:
                cleanup_errors.append(error)
    if primary_error is not None and cleanup_errors:
        raise ExceptionGroup(
            "vss_smoke_and_cleanup_failed", [primary_error, *cleanup_errors])
    if cleanup_errors:
        raise ExceptionGroup("vss_smoke_cleanup_failed", cleanup_errors)
    if primary_error is not None:
        raise primary_error

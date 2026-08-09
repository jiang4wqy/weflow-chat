from __future__ import annotations

import copy
import json
import os
from pathlib import Path

import pytest

import weflow_chat.validator.result as result_module
from weflow_chat.paths import RunLayout
from weflow_chat.validator.launcher import (
    ValidatorBlockedError,
    _CopiedBackendCore,
    _assert_no_reparse_chain,
    _bind_exit_result_for_test,
    _write_request,
)
from weflow_chat.validator.profile import ConfigCopyReceipt
from weflow_chat.validator.result import (
    ValidationResultError,
    read_validation_result,
)


RUN_ID = "00000000-0000-4000-8000-000000000001"


def _request_payload() -> dict[str, str]:
    return {
        "operation": "validate-snapshot",
        "runId": RUN_ID,
        "area": "validation",
    }


def _blocked_result(valid_result_payload: dict[str, object]) -> dict[str, object]:
    value = copy.deepcopy(valid_result_payload)
    value["status"] = "compatibility_blocked"
    value["reasonCode"] = "connection_failed"
    value["validation"] = None
    value["gates"]["nativeProtectionAuthenticated"] = False
    return value


def test_request_publication_preserves_existing_target_and_removes_random_temp(
    validator_layout,
) -> None:
    sentinel = b"existing request"
    validator_layout.request_path.write_bytes(sentinel)
    observed_temps: list[Path] = []

    def observe_reparse_check(
        root: Path,
        target: Path,
        *,
        require_target: bool = False,
    ) -> None:
        if target.name.endswith(".tmp"):
            observed_temps.append(target)
        _assert_no_reparse_chain(root, target, require_target=require_target)

    with pytest.raises(ValidatorBlockedError, match=r"^request_target_exists$"):
        _write_request(
            validator_layout,
            _request_payload(),
            reparse_check=observe_reparse_check,
        )

    assert validator_layout.request_path.read_bytes() == sentinel
    assert observed_temps
    assert all(path.name.startswith(".request.") for path in observed_temps)
    assert list(validator_layout.request_path.parent.glob(".request.*.tmp")) == []
    assert not (validator_layout.request_path.parent / "request.tmp").exists()


def test_request_publication_fails_closed_when_temp_changes_before_link(
    validator_layout,
) -> None:
    changed = False

    def replace_temp_before_link(
        root: Path,
        target: Path,
        *,
        require_target: bool = False,
    ) -> None:
        nonlocal changed
        _assert_no_reparse_chain(root, target, require_target=require_target)
        if target == validator_layout.request_path and not require_target and not changed:
            temps = list(target.parent.glob(".request.*.tmp"))
            if temps:
                temps[0].write_bytes(b'{"operation":"smoke"}')
                changed = True

    with pytest.raises(
        ValidatorBlockedError,
        match=r"^request_temporary_changed$",
    ):
        _write_request(
            validator_layout,
            _request_payload(),
            reparse_check=replace_temp_before_link,
        )

    assert changed
    assert not validator_layout.request_path.exists()
    assert list(validator_layout.request_path.parent.glob(".request.*.tmp")) == []


def test_request_publication_never_deletes_a_competing_temp(
    validator_layout,
) -> None:
    sentinel = b"competitor temporary"
    competing_temp = None

    def occupy_temp_name(
        root: Path,
        target: Path,
        *,
        require_target: bool = False,
    ) -> None:
        nonlocal competing_temp
        _assert_no_reparse_chain(root, target, require_target=require_target)
        if target.name.startswith(".request.") and not require_target:
            target.write_bytes(sentinel)
            competing_temp = target

    with pytest.raises(
        ValidatorBlockedError,
        match=r"^request_target_exists$",
    ):
        _write_request(
            validator_layout,
            _request_payload(),
            reparse_check=occupy_temp_name,
        )

    assert competing_temp is not None
    assert competing_temp.read_bytes() == sentinel
    assert not validator_layout.request_path.exists()


def test_result_reader_rejects_symlink(
    validator_layout,
    valid_result_payload,
) -> None:
    outside = validator_layout.result_path.parent / "outside.json"
    outside.write_text(
        json.dumps(valid_result_payload, separators=(",", ":")),
        encoding="utf-8",
    )
    try:
        validator_layout.result_path.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    with pytest.raises(ValidationResultError, match=r"^result_path_invalid$"):
        read_validation_result(
            validator_layout.result_path,
            expected_run_id=RUN_ID,
            expected_operation="validate-snapshot",
        )


def test_result_reader_detects_identity_change_between_lstat_and_open(
    monkeypatch,
    validator_layout,
    valid_result_payload,
) -> None:
    original = json.dumps(valid_result_payload, separators=(",", ":"))
    validator_layout.result_path.write_text(original, encoding="utf-8")

    replacement_payload = copy.deepcopy(valid_result_payload)
    replacement_payload["reasonCode"] = "connection_failed"
    replacement = validator_layout.result_path.parent / "replacement.json"
    replacement.write_text(
        json.dumps(replacement_payload, separators=(",", ":")),
        encoding="utf-8",
    )

    real_open = os.open
    swapped = False

    def swapping_open(path, flags, mode=0o777):
        nonlocal swapped
        if Path(path) == validator_layout.result_path and not swapped:
            os.replace(replacement, validator_layout.result_path)
            swapped = True
        return real_open(path, flags, mode)

    monkeypatch.setattr(result_module.os, "open", swapping_open)

    with pytest.raises(ValidationResultError, match=r"^result_path_changed$"):
        read_validation_result(
            validator_layout.result_path,
            expected_run_id=RUN_ID,
            expected_operation="validate-snapshot",
        )

    assert swapped


@pytest.mark.parametrize(
    ("exit_code", "result_kind", "accepted"),
    [
        (0, "ok", True),
        (70, "blocked", True),
        (0, "blocked", False),
        (70, "ok", False),
    ],
)
def test_exit_code_is_bound_to_result_status(
    exit_code,
    result_kind,
    accepted,
    valid_result_payload,
) -> None:
    value = (
        copy.deepcopy(valid_result_payload)
        if result_kind == "ok"
        else _blocked_result(valid_result_payload)
    )

    if accepted:
        assert _bind_exit_result_for_test(exit_code, value) is value
    else:
        with pytest.raises(
            ValidatorBlockedError,
            match=r"^validator_exit_result_mismatch$",
        ):
            _bind_exit_result_for_test(exit_code, value)


def test_exit_code_binding_rejects_unknown_status() -> None:
    with pytest.raises(
        ValidatorBlockedError,
        match=r"^validator_exit_result_mismatch$",
    ):
        _bind_exit_result_for_test(70, {"status": "other"})


def test_backend_uses_launched_result_without_second_path_read(
    validator_layout,
    valid_result_payload,
) -> None:
    result_reads: list[object] = []
    core = _CopiedBackendCore(
        layout_builder=lambda _layout, _area, _run_id: validator_layout,
        profile_builder=lambda **_kwargs: ConfigCopyReceipt(
            source_sha256="A" * 64,
            destination_sha256="B" * 64,
            changed_fields=("dbPath", "cachePath"),
            effective_db_path=str(validator_layout.run_root / "validation"),
            effective_cache_path=str(validator_layout.cache_dir),
            source_path_absent=True,
        ),
        launcher=lambda *_args, **_kwargs: copy.deepcopy(valid_result_payload),
        result_reader=lambda *_args, **_kwargs: result_reads.append(object()),
    )

    receipt = core.validate(
        area="validation",
        layout=RunLayout.from_existing_root(validator_layout.run_root),
        run_id=RUN_ID,
    )

    assert receipt.status == "ok"
    assert result_reads == []

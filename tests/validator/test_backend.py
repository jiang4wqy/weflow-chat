import inspect
from hashlib import sha256
import os

import pytest

import weflow_chat.validator.launcher as launcher_module
from weflow_chat.paths import RunLayout
from weflow_chat.validator.contracts import ValidationReceipt
from weflow_chat.validator.launcher import (
    CopiedWeFlowValidatorBackend,
    _CopiedBackendCore,
    _build_validator_layout_for_test,
    ValidatorBlockedError,
)
from weflow_chat.validator.profile import ConfigCopyReceipt
from weflow_chat.weixin_trust import (
    STORED_ENVELOPE_REFRESH,
)


RUN_ID = "00000000-0000-4000-8000-000000000001"
OTHER_RUN_ID = "00000000-0000-4000-8000-000000000002"


def backend_host(tmp_path):
    formal_config = tmp_path / "WeFlow-config.json"
    formal_weflow = tmp_path / "WeFlow.exe"
    snapshots_root = tmp_path / "Snapshots"
    formal_config.write_text("{}", encoding="utf-8")
    formal_weflow.write_bytes(b"synthetic-runtime")
    snapshots_root.mkdir()
    return {
        "formal_config": formal_config,
        "formal_weflow": formal_weflow,
        "snapshots_root": snapshots_root,
    }


def profile_receipt(validator_layout):
    return ConfigCopyReceipt(
        source_sha256="A" * 64,
        destination_sha256="B" * 64,
        changed_fields=("dbPath", "cachePath"),
        effective_db_path=str(validator_layout.run_root / "validation"),
        effective_cache_path=str(validator_layout.cache_dir),
        source_path_absent=True,
    )


def avatar_aggregate():
    return {
        "version": 1,
        "candidateContactCount": 2,
        "avatarUrlCount": 1,
        "headImageBufferCount": 1,
        "finalAvatarCount": 2,
        "missingAvatarCount": 0,
        "reasonCounts": {
            "urlOnly": 1,
            "headImageBufferOnly": 1,
            "urlAndHeadImageBuffer": 0,
            "noSupportedSource": 0,
        },
    }


def media_openability():
    return {
        "version": 1,
        "candidateCount": 3,
        "imageCandidateCount": 2,
        "videoCandidateCount": 1,
        "locallyUnavailableCount": 1,
        "localFileCount": 2,
        "readableImageCount": 1,
        "readableVideoCount": 1,
        "unreadableLocalCount": 0,
    }


def avatar_profile_receipt(validator_layout, presentation):
    payload = b'{"profile":"avatar-test"}'
    config_path = (
        validator_layout.user_data_dir / "WeFlow-config.json"
    )
    config_path.write_bytes(payload)
    return ConfigCopyReceipt(
        source_sha256="A" * 64,
        destination_sha256=sha256(payload).hexdigest().upper(),
        changed_fields=("dbPath", "cachePath"),
        effective_db_path=str(presentation),
        effective_cache_path=str(validator_layout.cache_dir),
        source_path_absent=True,
    )


def mark_stored_envelope_validated(core, run_layout):
    core._stored_envelope_scope = launcher_module._run_scope(
        run_layout, RUN_ID
    )


def test_production_backend_requires_bound_host_paths(tmp_path):
    assert tuple(
        inspect.signature(CopiedWeFlowValidatorBackend).parameters
    ) == (
        "formal_config",
        "formal_weflow",
        "snapshots_root",
        "capabilities",
    )
    with pytest.raises(TypeError):
        CopiedWeFlowValidatorBackend()
    with pytest.raises(TypeError):
        CopiedWeFlowValidatorBackend(process_source=object())
    with pytest.raises(ValueError, match="validator_capabilities_invalid"):
        CopiedWeFlowValidatorBackend(
            **backend_host(tmp_path), capabilities={"forbidden"}
        )


def test_avatar_aggregate_requires_successful_validation(tmp_path):
    backend = CopiedWeFlowValidatorBackend(
        **backend_host(tmp_path)
    )
    root = tmp_path / "run"
    root.mkdir()

    with pytest.raises(
        ValidatorBlockedError,
        match="^stored_envelope_validation_required$",
    ):
        backend.avatar_aggregate(
            area="presentation",
            layout=RunLayout.from_existing_root(root),
            run_id=RUN_ID,
        )


def test_media_openability_requires_successful_validation(
    tmp_path,
):
    backend = CopiedWeFlowValidatorBackend(
        **backend_host(tmp_path)
    )
    root = tmp_path / "run"
    root.mkdir()

    with pytest.raises(
        ValidatorBlockedError,
        match="^stored_envelope_validation_required$",
    ):
        backend.media_openability(
            area="presentation",
            layout=RunLayout.from_existing_root(root),
            run_id=RUN_ID,
        )


def test_stored_envelope_validation_enables_followup_without_process_recovery(
    tmp_path
):
    assert not hasattr(
        launcher_module, "_recover_envelope_for_validation"
    )

    class Core:
        request_audit = []
        attempt_audit = ()

        def validate(self, **_values):
            return ValidationReceipt("ok", None, None)

        def avatar_aggregate(self, **_values):
            return avatar_aggregate()

        def media_openability(self, **_values):
            return media_openability()

    backend = CopiedWeFlowValidatorBackend(
        **backend_host(tmp_path),
        capabilities=frozenset({STORED_ENVELOPE_REFRESH})
    )
    backend._core = Core()
    root = tmp_path / "run"
    root.mkdir()
    layout = RunLayout.from_existing_root(root)

    receipt = backend.validate(
        area="validation",
        layout=layout,
        run_id=RUN_ID,
    )

    assert receipt.status == "ok"
    assert backend.avatar_aggregate(
        area="validation",
        layout=layout,
        run_id=RUN_ID,
    ) == avatar_aggregate()
    assert backend.media_openability(
        area="presentation",
        layout=layout,
        run_id=RUN_ID,
    ) == media_openability()


@pytest.mark.parametrize(
    "capabilities",
    (
        frozenset(),
        frozenset({STORED_ENVELOPE_REFRESH}),
    ),
)
def test_connection_failure_has_no_process_fallback(
    tmp_path, capabilities
):
    assert not hasattr(
        launcher_module, "_recover_envelope_for_validation"
    )

    class Core:
        request_audit = []
        attempt_audit = ()

        def validate(self, **_kwargs):
            return ValidationReceipt(
                "compatibility_blocked", "connection_failed", None
            )

    backend = CopiedWeFlowValidatorBackend(
        **backend_host(tmp_path),
        capabilities=capabilities
    )
    backend._core = Core()
    root = tmp_path / "run"
    root.mkdir()

    receipt = backend.validate(
        area="validation",
        layout=RunLayout.from_existing_root(root),
        run_id=RUN_ID,
    )

    assert receipt.reasonCode == "connection_failed"


def test_attempt_layout_is_fresh_for_repeated_area(tmp_path):
    root = tmp_path / "run"
    root.mkdir()
    layout = RunLayout.from_existing_root(root)
    made = []

    def secure(path):
        path.mkdir(parents=True, exist_ok=True)

    for attempt_id in (
        "00000000-0000-4000-8000-000000000010",
        "00000000-0000-4000-8000-000000000011",
    ):
        made.append(
            _build_validator_layout_for_test(
                layout=layout,
                area="validation",
                run_id=RUN_ID,
                attempt_id=attempt_id,
                secure=secure,
            )
        )
    assert made[0].attempt_root != made[1].attempt_root


def test_presentation_attempt_layout_uses_exact_validator_ancestry(tmp_path):
    root = tmp_path / "run"
    root.mkdir()
    layout = RunLayout.from_existing_root(root)

    attempt = _build_validator_layout_for_test(
        layout=layout,
        area="presentation",
        run_id=RUN_ID,
        attempt_id="00000000-0000-4000-8000-000000000012",
        secure=lambda path: path.mkdir(parents=True, exist_ok=True),
    )

    assert attempt.attempt_root == (
        layout.root
        / "validator"
        / "presentation"
        / "00000000-0000-4000-8000-000000000012"
    )


def test_root_reparse_replacement_blocks_before_secure(tmp_path):
    root = tmp_path / "run"
    root.mkdir()
    layout = RunLayout.from_existing_root(root)
    secured = []

    def replaced_root(root, target, *, require_target=False):
        raise ValidatorBlockedError("validator_reparse_rejected")

    with pytest.raises(
        ValidatorBlockedError, match="validator_reparse_rejected"
    ):
        _build_validator_layout_for_test(
            layout=layout,
            area="validation",
            run_id=RUN_ID,
            attempt_id="00000000-0000-4000-8000-000000000010",
            secure=lambda path: secured.append(path),
            reparse_check=replaced_root,
        )
    assert secured == []


def test_private_core_serializes_only_operation_run_and_area(
    validator_layout, valid_result_payload
):
    seen = []
    core = _CopiedBackendCore(
        layout_builder=lambda layout, area, run_id: validator_layout,
        profile_builder=lambda **kwargs: profile_receipt(validator_layout),
        launcher=lambda layout, request_payload: seen.append(request_payload),
        result_reader=lambda *args, **kwargs: valid_result_payload,
    )
    root = validator_layout.run_root
    core.validate(
        area="validation",
        layout=RunLayout.from_existing_root(root),
        run_id=RUN_ID,
    )
    assert seen == [
        {"operation": "validate-snapshot", "runId": RUN_ID, "area": "validation"}
    ]
    assert set(seen[0]) == {"operation", "runId", "area"}
    assert core.attempt_audit == (
        {
            "area": "validation",
            "attemptRoot": str(validator_layout.attempt_root),
            "configPath": str(
                validator_layout.user_data_dir / "WeFlow-config.json"
            ),
            "effectiveDbPath": str(
                validator_layout.run_root / "validation"
            ),
            "effectiveCachePath": str(validator_layout.cache_dir),
            "sourcePathAbsent": True,
            "changedFields": ("dbPath", "cachePath"),
            "sourceSha256": "A" * 64,
            "destinationSha256": "B" * 64,
        },
    )


def test_private_core_binds_presentation_profile_to_presentation_root(
    validator_layout, valid_result_payload
):
    presentation = validator_layout.run_root / "presentation"
    receipt = ConfigCopyReceipt(
        source_sha256="A" * 64,
        destination_sha256="B" * 64,
        changed_fields=("dbPath", "cachePath"),
        effective_db_path=str(presentation),
        effective_cache_path=str(validator_layout.cache_dir),
        source_path_absent=True,
    )
    seen = []
    core = _CopiedBackendCore(
        layout_builder=lambda layout, area, run_id: validator_layout,
        profile_builder=lambda **kwargs: receipt,
        launcher=lambda layout, request_payload: seen.append(request_payload),
        result_reader=lambda *args, **kwargs: valid_result_payload,
    )

    result = core.validate(
        area="presentation",
        layout=RunLayout.from_existing_root(validator_layout.run_root),
        run_id=RUN_ID,
    )

    assert result.status == "ok"
    assert seen == [
        {
            "operation": "validate-snapshot",
            "runId": RUN_ID,
            "area": "presentation",
        }
    ]
    assert core.attempt_audit[0]["effectiveDbPath"] == str(presentation)


def test_private_core_runs_avatar_aggregate_with_stored_envelope(
    validator_layout,
):
    presentation = validator_layout.run_root / "presentation"
    presentation.mkdir()
    receipt = avatar_profile_receipt(
        validator_layout,
        presentation,
    )
    profile_calls = []
    launch_calls = []
    core = _CopiedBackendCore(
        layout_builder=lambda layout, area, run_id: validator_layout,
        profile_builder=lambda **kwargs: (
            profile_calls.append(kwargs)
            or receipt
        ),
        avatar_launcher=lambda layout, request_payload: (
            launch_calls.append((layout, request_payload))
            or avatar_aggregate()
        ),
    )
    run_layout = RunLayout.from_existing_root(
        validator_layout.run_root
    )
    mark_stored_envelope_validated(core, run_layout)

    result = core.avatar_aggregate(
        area="presentation",
        layout=run_layout,
        run_id=RUN_ID,
    )

    assert result == avatar_aggregate()
    assert profile_calls == [
        {
            "run_layout": RunLayout.from_existing_root(
                validator_layout.run_root
            ),
            "validator_layout": validator_layout,
            "area": "presentation",
        }
    ]
    assert launch_calls == [
        (
            validator_layout,
            {
                "operation": "avatar-aggregate",
                "runId": RUN_ID,
                "area": "presentation",
            },
        )
    ]
    assert core.attempt_audit == ()


def test_avatar_startup_stall_retries_once_with_a_fresh_profile(
    validator_layout,
):
    run_layout = RunLayout.from_existing_root(
        validator_layout.run_root
    )
    presentation = validator_layout.run_root / "presentation"
    presentation.mkdir()
    attempts = [
        _build_validator_layout_for_test(
            layout=run_layout,
            area="presentation",
            run_id=RUN_ID,
            attempt_id=attempt_id,
            secure=lambda path: path.mkdir(parents=True),
        )
        for attempt_id in (
            "00000000-0000-4000-8000-000000000097",
            "00000000-0000-4000-8000-000000000098",
        )
    ]
    built_profiles = []
    launches = []

    def build_profile(**values):
        built_profiles.append(values["validator_layout"])
        return avatar_profile_receipt(
            values["validator_layout"], presentation
        )

    def launch(layout, request_payload):
        launches.append((layout, request_payload))
        if len(launches) == 1:
            raise ValidatorBlockedError("validator_timeout")
        return avatar_aggregate()

    core = _CopiedBackendCore(
        layout_builder=lambda *_args: attempts.pop(0),
        profile_builder=build_profile,
        avatar_launcher=launch,
    )
    mark_stored_envelope_validated(core, run_layout)

    result = core.avatar_aggregate(
        area="presentation",
        layout=run_layout,
        run_id=RUN_ID,
    )

    assert result == avatar_aggregate()
    assert len(launches) == 2
    assert launches[0][0].attempt_root != launches[1][0].attempt_root
    assert built_profiles == [launches[0][0], launches[1][0]]


@pytest.mark.parametrize("progress", ["result", "stage"])
def test_avatar_timeout_with_observed_progress_is_not_retried(
    validator_layout,
    progress,
):
    run_layout = RunLayout.from_existing_root(
        validator_layout.run_root
    )
    presentation = validator_layout.run_root / "presentation"
    presentation.mkdir()
    attempt = _build_validator_layout_for_test(
        layout=run_layout,
        area="presentation",
        run_id=RUN_ID,
        attempt_id="00000000-0000-4000-8000-000000000094",
        secure=lambda path: path.mkdir(parents=True),
    )
    launches = []

    def launch(layout, request_payload):
        launches.append((layout, request_payload))
        path = (
            layout.result_path
            if progress == "result"
            else layout.user_data_dir / "validator-stage.log"
        )
        path.write_text("observed", encoding="utf-8")
        raise ValidatorBlockedError("validator_timeout")

    core = _CopiedBackendCore(
        layout_builder=lambda *_args: attempt,
        profile_builder=lambda **values: avatar_profile_receipt(
            values["validator_layout"], presentation
        ),
        avatar_launcher=launch,
    )
    mark_stored_envelope_validated(core, run_layout)

    with pytest.raises(ValidatorBlockedError, match="^validator_timeout$"):
        core.avatar_aggregate(
            area="presentation",
            layout=run_layout,
            run_id=RUN_ID,
        )

    assert len(launches) == 1


def test_avatar_startup_stall_is_retried_at_most_once(
    validator_layout,
):
    run_layout = RunLayout.from_existing_root(
        validator_layout.run_root
    )
    presentation = validator_layout.run_root / "presentation"
    presentation.mkdir()
    attempts = [
        _build_validator_layout_for_test(
            layout=run_layout,
            area="presentation",
            run_id=RUN_ID,
            attempt_id=attempt_id,
            secure=lambda path: path.mkdir(parents=True),
        )
        for attempt_id in (
            "00000000-0000-4000-8000-000000000092",
            "00000000-0000-4000-8000-000000000093",
        )
    ]
    launches = []

    def launch(layout, request_payload):
        launches.append((layout, request_payload))
        raise ValidatorBlockedError("validator_timeout")

    core = _CopiedBackendCore(
        layout_builder=lambda *_args: attempts.pop(0),
        profile_builder=lambda **values: avatar_profile_receipt(
            values["validator_layout"], presentation
        ),
        avatar_launcher=launch,
    )
    mark_stored_envelope_validated(core, run_layout)

    with pytest.raises(ValidatorBlockedError, match="^validator_timeout$"):
        core.avatar_aggregate(
            area="presentation",
            layout=run_layout,
            run_id=RUN_ID,
        )

    assert len(launches) == 2


def test_private_core_runs_media_openability_with_fixed_request(
    validator_layout,
):
    presentation = validator_layout.run_root / "presentation"
    presentation.mkdir()
    (presentation / "wxid_test").mkdir()
    receipt = avatar_profile_receipt(validator_layout, presentation)
    launches = []
    presentation_reads = []
    formal_reads = []

    def read_presentation(*args, **kwargs):
        presentation_reads.append((args, kwargs))
        return ("stable-presentation",)

    def bind_formal_profile():
        formal_reads.append(True)
        return ("stable-formal-profile",)

    core = _CopiedBackendCore(
        layout_builder=lambda layout, area, run_id: validator_layout,
        profile_builder=lambda **kwargs: receipt,
        launcher=lambda layout, request_payload: (
            launches.append((layout, request_payload))
            or {
                "status": "ok",
                "reasonCode": None,
                "validation": media_openability(),
            }
        ),
        presentation_reader=read_presentation,
        formal_profile_binding=bind_formal_profile,
    )
    run_layout = RunLayout.from_existing_root(
        validator_layout.run_root
    )
    mark_stored_envelope_validated(core, run_layout)

    result = core.media_openability(
        area="presentation",
        layout=run_layout,
        run_id=RUN_ID,
    )

    assert result == media_openability()
    assert launches == [
        (
            validator_layout,
            {
                "operation": "media-openability",
                "runId": RUN_ID,
                "area": "presentation",
            },
        )
    ]
    assert core.request_audit == [launches[0][1]]
    assert core.attempt_audit == ()
    assert len(presentation_reads) == 2
    assert all(
        args == (validator_layout.run_root / "presentation-manifest.json",)
        and kwargs
        == {
            "expected_presentation_root": presentation,
            "account_name": "wxid_test",
        }
        for args, kwargs in presentation_reads
    )
    assert formal_reads == [True, True]


def test_media_startup_stall_retries_once_with_a_fresh_profile(
    validator_layout,
):
    run_layout = RunLayout.from_existing_root(
        validator_layout.run_root
    )
    presentation = validator_layout.run_root / "presentation"
    presentation.mkdir()
    (presentation / "wxid_test").mkdir()
    attempts = [
        _build_validator_layout_for_test(
            layout=run_layout,
            area="presentation",
            run_id=RUN_ID,
            attempt_id=attempt_id,
            secure=lambda path: path.mkdir(parents=True),
        )
        for attempt_id in (
            "00000000-0000-4000-8000-000000000095",
            "00000000-0000-4000-8000-000000000096",
        )
    ]
    built_profiles = []
    launches = []

    def build_profile(**values):
        built_profiles.append(values["validator_layout"])
        return avatar_profile_receipt(
            values["validator_layout"], presentation
        )

    def launch(layout, request_payload):
        launches.append((layout, request_payload))
        if len(launches) == 1:
            raise ValidatorBlockedError("validator_timeout")
        return {
            "status": "ok",
            "reasonCode": None,
            "validation": media_openability(),
        }

    core = _CopiedBackendCore(
        layout_builder=lambda *_args: attempts.pop(0),
        profile_builder=build_profile,
        launcher=launch,
        presentation_reader=lambda *args, **kwargs: (
            "stable-presentation",
        ),
        formal_profile_binding=lambda: ("stable-formal-profile",),
    )
    mark_stored_envelope_validated(core, run_layout)

    result = core.media_openability(
        area="presentation",
        layout=run_layout,
        run_id=RUN_ID,
    )

    assert result == media_openability()
    assert len(launches) == 2
    assert launches[0][0].attempt_root != launches[1][0].attempt_root
    assert built_profiles == [launches[0][0], launches[1][0]]


def test_private_core_reuses_validated_stored_envelope_for_media(
    validator_layout, valid_result_payload
):
    validation = validator_layout.run_root / "validation"
    validation.mkdir()
    presentation = validator_layout.run_root / "presentation"
    presentation.mkdir()
    (presentation / "wxid_test").mkdir()
    validation_receipt = profile_receipt(validator_layout)
    media_receipt = avatar_profile_receipt(
        validator_layout,
        presentation,
    )
    plain_profile_calls = []

    def build_plain_profile(**values):
        plain_profile_calls.append(values)
        if values["area"] == "validation":
            return validation_receipt
        return media_receipt

    def launch(_layout, request_payload):
        if request_payload["operation"] == "validate-snapshot":
            return valid_result_payload
        return {
            "status": "ok",
            "reasonCode": None,
            "validation": media_openability(),
        }

    core = _CopiedBackendCore(
        layout_builder=lambda layout, area, run_id: validator_layout,
        profile_builder=build_plain_profile,
        launcher=launch,
        presentation_reader=lambda *args, **kwargs: ("stable-presentation",),
        formal_profile_binding=lambda: ("stable-formal-profile",),
    )
    run_layout = RunLayout.from_existing_root(
        validator_layout.run_root
    )

    receipt = core.validate(
        area="validation",
        layout=run_layout,
        run_id=RUN_ID,
    )
    result = core.media_openability(
        area="presentation",
        layout=run_layout,
        run_id=RUN_ID,
    )

    assert receipt.status == "ok"
    assert result == media_openability()
    assert [call["area"] for call in plain_profile_calls] == [
        "validation",
        "presentation",
    ]


def test_media_result_failure_still_completes_final_integrity_checks(
    validator_layout,
):
    presentation = validator_layout.run_root / "presentation"
    presentation.mkdir()
    (presentation / "wxid_test").mkdir()
    receipt = avatar_profile_receipt(validator_layout, presentation)
    presentation_reads = []
    formal_reads = []

    def read_presentation(*_args, **_kwargs):
        presentation_reads.append(True)
        return ("stable-presentation",)

    def bind_formal_profile():
        formal_reads.append(True)
        return ("stable-formal-profile",)

    def reject_result(*_args, **_kwargs):
        raise launcher_module.ValidationResultError(
            "media_openability_unreadable"
        )

    core = _CopiedBackendCore(
        layout_builder=lambda layout, area, run_id: validator_layout,
        profile_builder=lambda **kwargs: receipt,
        launcher=lambda *args, **kwargs: None,
        result_reader=reject_result,
        presentation_reader=read_presentation,
        formal_profile_binding=bind_formal_profile,
    )
    run_layout = RunLayout.from_existing_root(
        validator_layout.run_root
    )
    mark_stored_envelope_validated(core, run_layout)

    with pytest.raises(
        ValidatorBlockedError,
        match="^media_openability_invalid$",
    ):
        core.media_openability(
            area="presentation",
            layout=run_layout,
            run_id=RUN_ID,
        )

    assert presentation_reads == [True, True]
    assert formal_reads == [True, True]


def test_private_core_rejects_nonaggregate_avatar_output(
    validator_layout,
):
    presentation = validator_layout.run_root / "presentation"
    presentation.mkdir()
    receipt = avatar_profile_receipt(
        validator_layout,
        presentation,
    )
    core = _CopiedBackendCore(
        layout_builder=lambda layout, area, run_id: validator_layout,
        profile_builder=lambda **kwargs: receipt,
        avatar_launcher=lambda *args, **kwargs: {
            **avatar_aggregate(),
            "username": "must-not-escape",
        },
    )
    run_layout = RunLayout.from_existing_root(
        validator_layout.run_root
    )
    mark_stored_envelope_validated(core, run_layout)

    with pytest.raises(
        ValidatorBlockedError,
        match="^avatar_aggregate_invalid$",
    ):
        core.avatar_aggregate(
            area="presentation",
            layout=run_layout,
            run_id=RUN_ID,
        )


def test_private_core_rejects_database_root_replaced_during_avatar_launch(
    validator_layout,
):
    presentation = validator_layout.run_root / "presentation"
    presentation.mkdir()
    receipt = avatar_profile_receipt(
        validator_layout,
        presentation,
    )

    def replace_database_root(*_args, **_kwargs):
        displaced = validator_layout.run_root / "displaced-presentation"
        presentation.rename(displaced)
        presentation.mkdir()
        return avatar_aggregate()

    core = _CopiedBackendCore(
        layout_builder=lambda layout, area, run_id: validator_layout,
        profile_builder=lambda **kwargs: receipt,
        avatar_launcher=replace_database_root,
    )
    run_layout = RunLayout.from_existing_root(
        validator_layout.run_root
    )
    mark_stored_envelope_validated(core, run_layout)

    with pytest.raises(
        ValidatorBlockedError,
        match="^avatar_data_binding_changed$",
    ):
        core.avatar_aggregate(
            area="presentation",
            layout=run_layout,
            run_id=RUN_ID,
        )


def test_private_core_rejects_profile_replaced_during_avatar_launch(
    validator_layout,
):
    presentation = validator_layout.run_root / "presentation"
    presentation.mkdir()
    receipt = avatar_profile_receipt(
        validator_layout,
        presentation,
    )
    config = (
        validator_layout.user_data_dir / "WeFlow-config.json"
    )

    def replace_profile(*_args, **_kwargs):
        config.unlink()
        config.write_bytes(b'{"profile":"replaced"}')
        return avatar_aggregate()

    core = _CopiedBackendCore(
        layout_builder=lambda layout, area, run_id: validator_layout,
        profile_builder=lambda **kwargs: receipt,
        avatar_launcher=replace_profile,
    )
    run_layout = RunLayout.from_existing_root(
        validator_layout.run_root
    )
    mark_stored_envelope_validated(core, run_layout)

    with pytest.raises(
        ValidatorBlockedError,
        match="^avatar_data_binding_changed$",
    ):
        core.avatar_aggregate(
            area="presentation",
            layout=run_layout,
            run_id=RUN_ID,
        )


@pytest.mark.skipif(
    os.name != "nt",
    reason="deny-write sharing is a Windows production contract",
)
def test_private_core_blocks_transient_profile_write_during_avatar_launch(
    validator_layout,
):
    presentation = validator_layout.run_root / "presentation"
    presentation.mkdir()
    receipt = avatar_profile_receipt(
        validator_layout,
        presentation,
    )
    config = (
        validator_layout.user_data_dir / "WeFlow-config.json"
    )
    untrusted_observed = []

    def transient_profile_write(*_args, **_kwargs):
        original = config.read_bytes()
        with config.open("r+b") as stream:
            stream.write(b"X" * len(original))
            stream.flush()
            untrusted_observed.append(config.read_bytes())
            stream.seek(0)
            stream.write(original)
            stream.flush()
        return avatar_aggregate()

    core = _CopiedBackendCore(
        layout_builder=lambda layout, area, run_id: validator_layout,
        profile_builder=lambda **kwargs: receipt,
        avatar_launcher=transient_profile_write,
    )
    run_layout = RunLayout.from_existing_root(
        validator_layout.run_root
    )
    mark_stored_envelope_validated(core, run_layout)

    with pytest.raises(
        ValidatorBlockedError,
        match="^avatar_data_binding_changed$",
    ):
        core.avatar_aggregate(
            area="presentation",
            layout=run_layout,
            run_id=RUN_ID,
        )
    assert untrusted_observed == []


def test_private_core_rejects_database_root_replaced_before_pin(
    validator_layout,
):
    presentation = validator_layout.run_root / "presentation"
    presentation.mkdir()
    receipt = avatar_profile_receipt(
        validator_layout,
        presentation,
    )
    replaced = False

    def replace_before_pin(path):
        nonlocal replaced
        if path == presentation and not replaced:
            replaced = True
            displaced = (
                validator_layout.run_root
                / "displaced-before-pin"
            )
            presentation.rename(displaced)
            presentation.mkdir()
        return launcher_module._pin_directory(path)

    core = _CopiedBackendCore(
        layout_builder=lambda layout, area, run_id: validator_layout,
        profile_builder=lambda **kwargs: receipt,
        avatar_launcher=lambda *args, **kwargs: avatar_aggregate(),
        pin_directory=replace_before_pin,
    )
    run_layout = RunLayout.from_existing_root(
        validator_layout.run_root
    )
    mark_stored_envelope_validated(core, run_layout)

    with pytest.raises(
        ValidatorBlockedError,
        match="^avatar_data_binding_changed$",
    ):
        core.avatar_aggregate(
            area="presentation",
            layout=run_layout,
            run_id=RUN_ID,
        )


def test_private_core_accepts_fixed_sanitized_cache_fields(
    validator_layout, valid_result_payload
):
    sanitized = (
        "contactsAvatarCacheMap",
        "contactsListCacheMap",
        "exportSessionMutualFriendsCacheMap",
        "exportSnsUserPostCountsCacheMap",
    )
    receipt = profile_receipt(validator_layout)
    receipt = ConfigCopyReceipt(
        source_sha256=receipt.source_sha256,
        destination_sha256=receipt.destination_sha256,
        changed_fields=(
            "dbPath",
            "cachePath",
            *sanitized,
        ),
        effective_db_path=receipt.effective_db_path,
        effective_cache_path=receipt.effective_cache_path,
        source_path_absent=True,
    )
    core = _CopiedBackendCore(
        layout_builder=lambda layout, area, run_id: validator_layout,
        profile_builder=lambda **kwargs: receipt,
        launcher=lambda *args, **kwargs: None,
        result_reader=lambda *args, **kwargs: valid_result_payload,
    )

    core.validate(
        area="validation",
        layout=RunLayout.from_existing_root(validator_layout.run_root),
        run_id=RUN_ID,
    )

    assert core.attempt_audit[0]["changedFields"] == (
        "dbPath",
        "cachePath",
        *sanitized,
    )


def test_private_core_constructor_is_stored_envelope_only():
    assert tuple(inspect.signature(_CopiedBackendCore).parameters) == (
        "layout_builder",
        "profile_builder",
        "launcher",
        "avatar_launcher",
        "result_reader",
        "presentation_reader",
        "formal_profile_binding",
        "pin_directory",
        "pin_file",
    )


def test_private_core_refuses_unverified_ok_gates(
    validator_layout, valid_result_payload
):
    payload = dict(valid_result_payload)
    payload["gates"] = {
        name: False for name in valid_result_payload["gates"]
    }
    core = _CopiedBackendCore(
        layout_builder=lambda layout, area, run_id: validator_layout,
        profile_builder=lambda **kwargs: profile_receipt(validator_layout),
        launcher=lambda *args, **kwargs: None,
        result_reader=lambda *args, **kwargs: payload,
    )
    with pytest.raises(ValidatorBlockedError, match="validator_gate_failed"):
        core.validate(
            area="validation",
            layout=RunLayout.from_existing_root(validator_layout.run_root),
            run_id=RUN_ID,
        )

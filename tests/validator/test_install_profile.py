import base64
import copy
from dataclasses import replace
import inspect
import json
import os

import pytest

from weflow_chat.paths import RunLayout
from weflow_chat.validator.profile import (
    ConfigCopyReceipt,
    ProfileCompatibilityError,
    _build_envelope_profile_for_test,
    _move_file_no_replace,
    _publish_json_for_test,
    _require_role_account_layout,
    build_envelope_profile,
    build_synthetic_profile,
)


def make_run_layout(validator_layout):
    for role in ("validation", "active"):
        (
            validator_layout.run_root / role / "wxid_test" / "db_storage"
        ).mkdir(parents=True, exist_ok=True)
    return RunLayout.from_existing_root(validator_layout.run_root)


def test_real_profile_copies_every_field_and_changes_only_paths(
    synthetic_full_config, validator_layout
):
    run_layout = make_run_layout(validator_layout)
    result = _build_envelope_profile_for_test(
        source_config_path=synthetic_full_config.path,
        run_layout=run_layout,
        validator_layout=validator_layout,
        area="validation",
        secure=lambda path: None,
    )
    config_path = validator_layout.user_data_dir / "WeFlow-config.json"
    value = json.loads(config_path.read_bytes())
    expected = copy.deepcopy(synthetic_full_config.value)
    expected["dbPath"] = str(run_layout.validation)
    expected["cachePath"] = str(validator_layout.cache_dir)
    assert value == expected
    assert (
        run_layout.validation / value["myWxid"] / "db_storage"
    ).is_dir()
    assert result.changed_fields == ("dbPath", "cachePath")
    assert result.effective_db_path == str(run_layout.validation)
    assert result.effective_cache_path == str(validator_layout.cache_dir)
    assert result.source_path_absent is True


def test_presentation_profile_uses_exact_presentation_account_tree(
    synthetic_full_config, validator_layout
):
    run_layout = RunLayout.from_existing_root(validator_layout.run_root)
    account_root = (
        run_layout.root / "presentation" / "wxid_test"
    )
    (account_root / "db_storage").mkdir(parents=True)
    (account_root / "msg" / "attach").mkdir(parents=True)
    (account_root / "msg" / "video").mkdir()

    result = _build_envelope_profile_for_test(
        source_config_path=synthetic_full_config.path,
        run_layout=run_layout,
        validator_layout=validator_layout,
        area="presentation",
        secure=lambda path: None,
    )

    copied = json.loads(
        (
            validator_layout.user_data_dir / "WeFlow-config.json"
        ).read_bytes()
    )
    presentation = run_layout.root / "presentation"
    assert copied["dbPath"] == str(presentation)
    assert result.effective_db_path == str(presentation)


@pytest.mark.parametrize("scope", ["role", "account", "msg"])
def test_presentation_profile_rejects_every_unexpected_entry(
    synthetic_full_config, validator_layout, scope
):
    run_layout = RunLayout.from_existing_root(validator_layout.run_root)
    presentation = run_layout.root / "presentation"
    account = presentation / "wxid_test"
    msg = account / "msg"
    (account / "db_storage").mkdir(parents=True)
    (msg / "attach").mkdir(parents=True)
    (msg / "video").mkdir()
    {"role": presentation, "account": account, "msg": msg}[
        scope
    ].joinpath("unexpected").write_bytes(b"sentinel")

    with pytest.raises(
        ProfileCompatibilityError, match="role_account_layout_mismatch"
    ):
        _build_envelope_profile_for_test(
            source_config_path=synthetic_full_config.path,
            run_layout=run_layout,
            validator_layout=validator_layout,
            area="presentation",
            secure=lambda path: None,
        )

    assert not (
        validator_layout.user_data_dir / "WeFlow-config.json"
    ).exists()


def test_presentation_profile_rejects_non_directory_media_root(
    synthetic_full_config, validator_layout
):
    run_layout = RunLayout.from_existing_root(validator_layout.run_root)
    account = run_layout.root / "presentation" / "wxid_test"
    (account / "db_storage").mkdir(parents=True)
    msg = account / "msg"
    msg.mkdir()
    (msg / "attach").write_bytes(b"not-a-directory")
    (msg / "video").mkdir()

    with pytest.raises(
        ProfileCompatibilityError, match="role_account_layout_mismatch"
    ):
        _build_envelope_profile_for_test(
            source_config_path=synthetic_full_config.path,
            run_layout=run_layout,
            validator_layout=validator_layout,
            area="presentation",
            secure=lambda path: None,
        )


def test_validation_profile_keeps_db_storage_only_contract(
    synthetic_full_config, validator_layout
):
    run_layout = make_run_layout(validator_layout)
    (
        run_layout.validation / "wxid_test" / "msg"
    ).mkdir()

    with pytest.raises(
        ProfileCompatibilityError, match="role_account_layout_mismatch"
    ):
        _build_envelope_profile_for_test(
            source_config_path=synthetic_full_config.path,
            run_layout=run_layout,
            validator_layout=validator_layout,
            area="validation",
            secure=lambda path: None,
        )


def test_synthetic_presentation_profile_creates_only_supported_tree(
    validator_layout
):
    attempt = (
        validator_layout.run_root
        / "validator"
        / "presentation"
        / "00000000-0000-4000-8000-000000000100"
    )
    presentation_layout = replace(
        validator_layout,
        attempt_root=attempt,
        request_path=attempt / "request" / "request.json",
        result_path=attempt / "result" / "result.json",
        user_data_dir=attempt / "profile",
        documents_dir=attempt / "documents",
        cache_dir=attempt / "cache",
    )

    receipt = build_synthetic_profile(
        layout=presentation_layout,
        area="presentation",
        source_account_name="wxid_test",
    )

    presentation = validator_layout.run_root / "presentation"
    assert receipt.effective_db_path == str(presentation)
    assert {
        item.name for item in presentation.iterdir()
    } == {"wxid_test"}
    account = presentation / "wxid_test"
    assert {item.name for item in account.iterdir()} == {
        "db_storage",
        "msg",
    }
    assert {item.name for item in (account / "msg").iterdir()} == {
        "attach",
        "video",
    }


def test_private_profile_builder_accepts_only_stored_config_input():
    assert tuple(
        inspect.signature(_build_envelope_profile_for_test).parameters
    ) == (
        "source_config_path",
        "source_local_state_path",
        "run_layout",
        "validator_layout",
        "area",
        "secure",
        "before_write",
        "reparse_check",
        "publish_json",
    )


def test_real_profile_copies_chromium_safe_storage_state(
    synthetic_full_config, validator_layout, tmp_path
):
    run_layout = make_run_layout(validator_layout)
    local_state = tmp_path / "Local State"
    state = {
        "os_crypt": {
            "encrypted_key": base64.b64encode(
                b"DPAPI" + (b"\x01" * 32)
            ).decode("ascii")
        },
        "preserved": {"value": True},
    }
    source_bytes = json.dumps(state).encode("utf-8")
    local_state.write_bytes(source_bytes)

    _build_envelope_profile_for_test(
        source_config_path=synthetic_full_config.path,
        source_local_state_path=local_state,
        run_layout=run_layout,
        validator_layout=validator_layout,
        area="validation",
        secure=lambda path: None,
    )

    copied = json.loads(
        (
            validator_layout.user_data_dir / "Local State"
        ).read_bytes()
    )
    assert copied == state
    assert local_state.read_bytes() == source_bytes


def test_real_profile_replaces_official_empty_cache_path(
    synthetic_full_config, validator_layout, tmp_path
):
    run_layout = make_run_layout(validator_layout)
    original = copy.deepcopy(synthetic_full_config.value)
    original["cachePath"] = ""
    source = tmp_path / "empty-cache-path.json"
    source.write_text(json.dumps(original), encoding="utf-8")

    result = _build_envelope_profile_for_test(
        source_config_path=source,
        run_layout=run_layout,
        validator_layout=validator_layout,
        area="validation",
        secure=lambda path: None,
    )

    copied = json.loads(
        (
            validator_layout.user_data_dir / "WeFlow-config.json"
        ).read_bytes()
    )
    assert json.loads(source.read_bytes())["cachePath"] == ""
    assert copied["cachePath"] == str(validator_layout.cache_dir)
    assert result.effective_cache_path == str(validator_layout.cache_dir)


def test_real_profile_drops_only_source_path_keyed_cache_entries(
    synthetic_full_config, validator_layout, tmp_path
):
    run_layout = make_run_layout(validator_layout)
    original = copy.deepcopy(synthetic_full_config.value)
    source_key = original["dbPath"] + "::wxid_test"
    unrelated_key = r"F:\unrelated-account::wxid_other"
    cache_fields = (
        "contactsAvatarCacheMap",
        "contactsListCacheMap",
        "exportSessionMutualFriendsCacheMap",
        "exportSnsUserPostCountsCacheMap",
    )
    for field in cache_fields:
        original[field] = {
            source_key: {"source": True},
            unrelated_key: {"other": True},
        }
    source = tmp_path / "path-keyed-caches.json"
    source.write_text(json.dumps(original), encoding="utf-8")

    result = _build_envelope_profile_for_test(
        source_config_path=source,
        run_layout=run_layout,
        validator_layout=validator_layout,
        area="validation",
        secure=lambda path: None,
    )

    copied = json.loads(
        (
            validator_layout.user_data_dir / "WeFlow-config.json"
        ).read_bytes()
    )
    persisted_source = json.loads(source.read_bytes())
    for field in cache_fields:
        assert persisted_source[field] == original[field]
        assert copied[field] == {
            unrelated_key: {"other": True}
        }
    assert result.changed_fields == (
        "dbPath",
        "cachePath",
        *cache_fields,
    )


@pytest.mark.parametrize("leak_kind", ["run_source", "original_db"])
def test_profile_rejects_nested_source_path_without_disclosing_value(
    synthetic_full_config, validator_layout, tmp_path, leak_kind
):
    run_layout = make_run_layout(validator_layout)
    value = copy.deepcopy(synthetic_full_config.value)
    if leak_kind == "run_source":
        leaked_path = str(
            run_layout.source / "wxid_test" / "db_storage"
        )
    else:
        leaked_path = value["dbPath"] + r"\wxid_test\db_storage"
    leaked_path = leaked_path.upper().replace("\\", "/")
    value["unknownFutureField"]["nested"] = {
        "path": f"db:{leaked_path};"
    }
    source = tmp_path / "nested-source-path.json"
    source.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(
        ProfileCompatibilityError,
        match="^profile_source_path_leak$",
    ) as captured:
        _build_envelope_profile_for_test(
            source_config_path=source,
            run_layout=run_layout,
            validator_layout=validator_layout,
            area="validation",
            secure=lambda path: None,
        )

    assert leaked_path.casefold() not in str(captured.value).casefold()
    assert not (
        validator_layout.user_data_dir / "WeFlow-config.json"
    ).exists()


def test_profile_allows_non_path_prefix_matches(
    synthetic_full_config, validator_layout, tmp_path
):
    run_layout = make_run_layout(validator_layout)
    value = copy.deepcopy(synthetic_full_config.value)
    value["unknownFutureField"]["nested"] = [
        str(run_layout.source).upper() + "-archive",
        value["dbPath"].lower() + "-archive",
    ]
    source = tmp_path / "non-path-prefixes.json"
    source.write_text(json.dumps(value), encoding="utf-8")

    result = _build_envelope_profile_for_test(
        source_config_path=source,
        run_layout=run_layout,
        validator_layout=validator_layout,
        area="validation",
        secure=lambda path: None,
    )

    assert result.source_path_absent is True


def build_mutated_profile(
    fixture, mutation, tmp_path, validator_layout
):
    value = copy.deepcopy(fixture.value)
    mutations = {
        "missing_top_level": lambda: value.pop("decryptKey"),
        "plaintext_top_level": lambda: value.__setitem__(
            "decryptKey", "plaintext"
        ),
        "missing_nested": lambda: value["wxidConfigs"]["wxid_test"].pop(
            "decryptKey"
        ),
        "plaintext_nested": lambda: value["wxidConfigs"][
            "wxid_test"
        ].__setitem__("decryptKey", "plaintext"),
        "plaintext_image_top": lambda: value.__setitem__(
            "imageAesKey", "plaintext"
        ),
        "plaintext_image_nested": lambda: value["wxidConfigs"][
            "wxid_test"
        ].__setitem__("imageXorKey", "plaintext"),
        "plaintext_other_account": lambda: value["wxidConfigs"][
            "wxid_other"
        ].__setitem__("decryptKey", "plaintext"),
    }
    mutations[mutation]()
    source = tmp_path / f"{mutation}.json"
    source.write_text(json.dumps(value), encoding="utf-8")
    return _build_envelope_profile_for_test(
        source_config_path=source,
        run_layout=make_run_layout(validator_layout),
        validator_layout=validator_layout,
        area="validation",
        secure=lambda path: None,
    )


def test_profile_preserves_all_envelopes_verbatim_and_receipt_is_safe(
    synthetic_full_config, validator_layout
):
    result = _build_envelope_profile_for_test(
        source_config_path=synthetic_full_config.path,
        run_layout=make_run_layout(validator_layout),
        validator_layout=validator_layout,
        area="active",
        secure=lambda path: None,
    )
    value = json.loads(
        (
            validator_layout.user_data_dir / "WeFlow-config.json"
        ).read_bytes()
    )
    before = synthetic_full_config.value
    assert value["decryptKey"] == before["decryptKey"]
    assert value["wxidConfigs"] == before["wxidConfigs"]
    assert isinstance(result, ConfigCopyReceipt)
    assert "safe:" not in repr(result)
    assert set(vars(result)) if hasattr(result, "__dict__") else True


def test_profile_rejects_missing_or_non_safe_envelopes(
    synthetic_full_config, tmp_path, validator_layout
):
    for mutation in (
        "missing_top_level",
        "plaintext_top_level",
        "missing_nested",
        "plaintext_nested",
        "plaintext_image_top",
        "plaintext_image_nested",
        "plaintext_other_account",
    ):
        with pytest.raises(
            ProfileCompatibilityError, match="safe_envelope_contract"
        ):
            build_mutated_profile(
                synthetic_full_config, mutation, tmp_path, validator_layout
            )


def test_profile_rejects_account_not_directly_under_selected_role(
    synthetic_full_config, validator_layout, tmp_path
):
    run_layout = make_run_layout(validator_layout)
    value = copy.deepcopy(synthetic_full_config.value)
    value["myWxid"] = "wxid_other"
    source = tmp_path / "wrong-account.json"
    source.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(
        ProfileCompatibilityError, match="role_account_layout_mismatch"
    ):
        _build_envelope_profile_for_test(
            source_config_path=source,
            run_layout=run_layout,
            validator_layout=validator_layout,
            area="validation",
            secure=lambda path: None,
        )


@pytest.mark.parametrize(
    "source_account_name",
    ["wxid_", "wxid_bad-name", "wxid_" + "a" * 129],
)
def test_profile_rejects_account_names_outside_core_contract(
    tmp_path, source_account_name
):
    role_root = tmp_path / "validation"
    role_root.mkdir()
    with pytest.raises(
        ProfileCompatibilityError, match="source_account_name_invalid"
    ):
        _require_role_account_layout(role_root, source_account_name)


def test_public_real_builder_requires_bound_config_source():
    assert tuple(inspect.signature(build_envelope_profile).parameters) == (
        "source_config_path",
        "run_layout",
        "validator_layout",
        "area",
    )


def test_acl_is_applied_before_config_write(
    synthetic_full_config, validator_layout
):
    events = []

    def secure(path):
        events.append(("secure", path))

    _build_envelope_profile_for_test(
        source_config_path=synthetic_full_config.path,
        run_layout=make_run_layout(validator_layout),
        validator_layout=validator_layout,
        area="validation",
        secure=secure,
        before_write=lambda: events.append(("write", None)),
    )
    write_index = events.index(("write", None))
    assert (
        events.index(("secure", validator_layout.attempt_root))
        < write_index
    )
    assert (
        events.index(("secure", validator_layout.user_data_dir))
        < write_index
    )


def test_reparse_preflight_blocks_before_acl_or_config_write(
    synthetic_full_config, validator_layout
):
    events = []
    run_layout = make_run_layout(validator_layout)

    def reparse_check(root, target, *, require_target=True):
        if (
            target == validator_layout.attempt_root
            and not require_target
        ):
            raise ProfileCompatibilityError("profile_reparse_rejected")

    with pytest.raises(
        ProfileCompatibilityError, match="profile_reparse_rejected"
    ):
        _build_envelope_profile_for_test(
            source_config_path=synthetic_full_config.path,
            run_layout=run_layout,
            validator_layout=validator_layout,
            area="validation",
            secure=lambda path: events.append(("secure", path)),
            before_write=lambda: events.append(("write", None)),
            reparse_check=reparse_check,
        )
    assert events == []


def test_reparse_swap_after_callback_blocks_before_atomic_write(
    synthetic_full_config, validator_layout
):
    events = []
    swapped = False
    run_layout = make_run_layout(validator_layout)
    destination = (
        validator_layout.user_data_dir / "WeFlow-config.json"
    )

    def before_write():
        nonlocal swapped
        swapped = True
        events.append(("callback", None))

    def reparse_check(root, target, *, require_target=True):
        if swapped and target in {destination.parent, destination}:
            raise ProfileCompatibilityError("profile_reparse_rejected")

    with pytest.raises(
        ProfileCompatibilityError, match="profile_reparse_rejected"
    ):
        _build_envelope_profile_for_test(
            source_config_path=synthetic_full_config.path,
            run_layout=run_layout,
            validator_layout=validator_layout,
            area="validation",
            secure=lambda path: None,
            before_write=before_write,
            reparse_check=reparse_check,
        )
    assert events == [("callback", None)]


@pytest.mark.parametrize(
    ("payload", "reason"),
    [
        (
            b'{"dbPath":"x","dbPath":"y","cachePath":"c",'
            b'"myWxid":"wxid_test","decryptKey":"safe:x",'
            b'"wxidConfigs":{"wxid_test":{"decryptKey":"safe:y"}}}',
            "config_duplicate_key",
        ),
        (b"[]", "config_schema_mismatch"),
        (
            b'{"dbPath":1,"cachePath":"c","myWxid":"wxid_test",'
            b'"decryptKey":"safe:x","wxidConfigs":'
            b'{"wxid_test":{"decryptKey":"safe:y"}}}',
            "config_schema_mismatch",
        ),
    ],
)
def test_profile_strict_json_and_schema_fail_closed(
    payload, reason, tmp_path, validator_layout
):
    source = tmp_path / "strict.json"
    source.write_bytes(payload)
    with pytest.raises(ProfileCompatibilityError, match=reason):
        _build_envelope_profile_for_test(
            source_config_path=source,
            run_layout=make_run_layout(validator_layout),
            validator_layout=validator_layout,
            area="validation",
            secure=lambda path: None,
        )
    assert not (
        validator_layout.user_data_dir / "WeFlow-config.json"
    ).exists()


def test_source_hash_is_unchanged_before_and_after_publication(
    synthetic_full_config, validator_layout
):
    before = synthetic_full_config.path.read_bytes()
    receipt = _build_envelope_profile_for_test(
        source_config_path=synthetic_full_config.path,
        run_layout=make_run_layout(validator_layout),
        validator_layout=validator_layout,
        area="validation",
        secure=lambda path: None,
    )
    after = synthetic_full_config.path.read_bytes()
    import hashlib

    assert before == after
    assert receipt.source_sha256 == hashlib.sha256(before).hexdigest().upper()


def test_source_change_during_prepublication_callback_fails_closed(
    synthetic_full_config, validator_layout
):
    destination = (
        validator_layout.user_data_dir / "WeFlow-config.json"
    )

    def mutate_source():
        synthetic_full_config.path.write_text("{}", encoding="utf-8")

    with pytest.raises(
        ProfileCompatibilityError, match="source_config_changed"
    ):
        _build_envelope_profile_for_test(
            source_config_path=synthetic_full_config.path,
            run_layout=make_run_layout(validator_layout),
            validator_layout=validator_layout,
            area="validation",
            secure=lambda path: None,
            before_write=mutate_source,
        )
    assert not destination.exists()


def test_existing_or_locked_destination_fails_without_overwrite(
    synthetic_full_config, validator_layout
):
    destination = (
        validator_layout.user_data_dir / "WeFlow-config.json"
    )
    destination.write_bytes(b"locked-sentinel")
    with pytest.raises(
        ProfileCompatibilityError, match="profile_destination_exists"
    ):
        _build_envelope_profile_for_test(
            source_config_path=synthetic_full_config.path,
            run_layout=make_run_layout(validator_layout),
            validator_layout=validator_layout,
            area="validation",
            secure=lambda path: None,
        )
    assert destination.read_bytes() == b"locked-sentinel"


class StableDirectoryPin:
    def __enter__(self):
        return self

    def verify(self):
        return None

    def __exit__(self, *_args):
        return False


def test_target_created_after_final_check_is_never_overwritten(tmp_path):
    destination = tmp_path / "profile" / "WeFlow-config.json"
    destination.parent.mkdir()

    def competing_move(source, target):
        target.write_bytes(b"competitor")
        _move_file_no_replace(source, target)

    with pytest.raises(
        ProfileCompatibilityError, match="profile_destination_exists"
    ):
        _publish_json_for_test(
            destination,
            {"synthetic": True},
            pin_directory=lambda _path: StableDirectoryPin(),
            move_file=competing_move,
        )
    assert destination.read_bytes() == b"competitor"


def test_parent_swap_after_callback_blocks_publication(tmp_path):
    destination = tmp_path / "profile" / "WeFlow-config.json"
    destination.parent.mkdir()
    outside = tmp_path / "outside-sentinel"
    outside.write_bytes(b"unchanged")
    moves = []
    swapped = False

    class SwapAwarePin(StableDirectoryPin):
        def verify(self):
            if swapped:
                raise ProfileCompatibilityError(
                    "profile_parent_identity_changed"
                )

    def simulate_parent_swap():
        nonlocal swapped
        swapped = True

    with pytest.raises(
        ProfileCompatibilityError,
        match="profile_parent_identity_changed",
    ):
        _publish_json_for_test(
            destination,
            {"synthetic": True},
            before_publish=simulate_parent_swap,
            pin_directory=lambda _path: SwapAwarePin(),
            move_file=lambda source, target: moves.append(
                (source, target)
            ),
        )
    assert not destination.exists()
    assert outside.read_bytes() == b"unchanged"
    assert moves == []


@pytest.mark.skipif(os.name != "nt", reason="Windows handle binding")
def test_open_temp_handle_blocks_same_account_replacement(tmp_path):
    destination = tmp_path / "profile" / "WeFlow-config.json"
    destination.parent.mkdir()
    attacker = tmp_path / "attacker.json"
    attacker.write_bytes(b'{"attacker":true}')
    attempted = []

    def try_to_replace_open_temp(temporary):
        attempted.append(temporary)
        with pytest.raises(OSError):
            os.replace(attacker, temporary)

    encoded, reread = _publish_json_for_test(
        destination,
        {"synthetic": "trusted"},
        after_temp_open=try_to_replace_open_temp,
    )
    assert attempted
    assert reread == encoded
    assert json.loads(destination.read_bytes()) == {
        "synthetic": "trusted"
    }
    assert attacker.read_bytes() == b'{"attacker":true}'


@pytest.mark.skipif(os.name != "nt", reason="Windows handle binding")
def test_bound_rename_never_replaces_final_window_competitor(tmp_path):
    destination = tmp_path / "profile" / "WeFlow-config.json"
    destination.parent.mkdir()

    def create_competitor():
        destination.write_bytes(b"competitor")

    with pytest.raises(
        ProfileCompatibilityError, match="profile_destination_exists"
    ):
        _publish_json_for_test(
            destination,
            {"synthetic": "trusted"},
            before_rename=create_competitor,
        )
    assert destination.read_bytes() == b"competitor"
    assert list(destination.parent.glob(".config-*.tmp")) == []

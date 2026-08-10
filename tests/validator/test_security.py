from dataclasses import replace
import os

import pytest

from weflow_chat.validator.security import (
    AclAce,
    AclReceipt,
    _CONTAINER_AND_OBJECT_INHERIT,
    _FULL_CONTROL,
    _ensure_private_directory_for_test,
    _pin_directory,
    ensure_private_directory,
)


class FakeAcl:
    def __init__(self, receipt):
        self.receipt = receipt
        self.applied = []

    def current_user_sid(self):
        return "S-1-5-21-test"

    def apply(self, path):
        self.applied.append(path)
        return self.receipt

    def read(self, path):
        return self.receipt


def exact_receipt():
    return AclReceipt(
        owner="S-1-5-21-test",
        protected=True,
        aces=(
            AclAce(
                "S-1-5-21-test",
                "Allow",
                _FULL_CONTROL,
                _CONTAINER_AND_OBJECT_INHERIT,
                0,
                False,
            ),
            AclAce(
                "S-1-5-18",
                "Allow",
                _FULL_CONTROL,
                _CONTAINER_AND_OBJECT_INHERIT,
                0,
                False,
            ),
        ),
    )


def test_acl_requires_owner_protection_and_exact_two_ace_tuples(tmp_path):
    receipt = exact_receipt()
    assert (
        _ensure_private_directory_for_test(
            tmp_path / "profile", FakeAcl(receipt)
        )
        == receipt
    )


def test_post_create_reparse_check_runs_before_acl_apply(tmp_path):
    adapter = FakeAcl(exact_receipt())
    checks = []

    def replaced_by_reparse(path, *, require_target):
        checks.append(require_target)
        if require_target:
            raise PermissionError("validator_reparse_rejected")

    with pytest.raises(PermissionError, match="validator_reparse_rejected"):
        _ensure_private_directory_for_test(
            tmp_path / "profile",
            adapter,
            reparse_check=replaced_by_reparse,
        )
    assert checks == [False, True]
    assert adapter.applied == []


def test_swap_after_path_check_is_rejected_before_acl_write(tmp_path):
    adapter = FakeAcl(exact_receipt())
    checks = []

    def check(_path, *, require_target):
        checks.append(require_target)

    class SwappedPin:
        def __enter__(self):
            raise PermissionError("validator_directory_identity_changed")

        def __exit__(self, *_args):
            return False

    with pytest.raises(
        PermissionError, match="validator_directory_identity_changed"
    ):
        _ensure_private_directory_for_test(
            tmp_path / "profile",
            adapter,
            reparse_check=check,
            pin_directory=lambda _path: SwappedPin(),
        )
    assert checks == [False, True]
    assert adapter.applied == []


@pytest.mark.skipif(os.name != "nt", reason="Windows handle sharing")
def test_directory_pin_blocks_rename_until_handle_is_closed(tmp_path):
    original = tmp_path / "profile"
    renamed = tmp_path / "renamed"
    original.mkdir()
    with _pin_directory(original) as pinned:
        pinned.verify()
        with pytest.raises(OSError):
            original.rename(renamed)
    original.rename(renamed)
    assert renamed.is_dir()


@pytest.mark.parametrize(
    "fault",
    [
        "owner",
        "protected",
        "extra",
        "duplicate",
        "sid",
        "type",
        "rights",
        "inheritance",
        "propagation",
        "inherited",
    ],
)
def test_acl_rejects_every_tuple_drift(tmp_path, fault):
    receipt = exact_receipt()
    user, system = receipt.aces
    if fault == "owner":
        receipt = replace(receipt, owner="S-1-5-32-544")
    elif fault == "protected":
        receipt = replace(receipt, protected=False)
    elif fault == "extra":
        receipt = replace(
            receipt,
            aces=receipt.aces + (replace(user, sid="S-1-5-32-544"),),
        )
    elif fault == "duplicate":
        receipt = replace(receipt, aces=(user, user, system))
    elif fault == "sid":
        user = replace(user, sid="S-1-5-32-544")
    elif fault == "type":
        user = replace(user, access_type="Deny")
    elif fault == "rights":
        user = replace(user, rights=1)
    elif fault == "inheritance":
        user = replace(user, inheritance_flags=0)
    elif fault == "propagation":
        user = replace(user, propagation_flags=2)
    elif fault == "inherited":
        user = replace(user, inherited=True)
    if fault in {
        "sid",
        "type",
        "rights",
        "inheritance",
        "propagation",
        "inherited",
    }:
        receipt = replace(receipt, aces=(user, system))
    with pytest.raises(
        PermissionError, match="validator_acl_contract_mismatch"
    ):
        _ensure_private_directory_for_test(
            tmp_path / "profile", FakeAcl(receipt)
        )


@pytest.mark.skipif(
    os.name != "nt" or os.environ.get("GITHUB_ACTIONS") == "true",
    reason="requires supported desktop Windows ACL semantics",
)
def test_real_acl_is_protected_and_full_control(tmp_path):
    receipt = ensure_private_directory(tmp_path / "profile")
    assert receipt.protected
    assert len(receipt.aces) == 2
    current = next(
        ace.sid for ace in receipt.aces if ace.sid != "S-1-5-18"
    )
    assert receipt.owner == current
    assert {ace.sid for ace in receipt.aces} == {current, "S-1-5-18"}
    assert all(
        ace.access_type == "Allow"
        and ace.rights == _FULL_CONTROL
        and ace.inheritance_flags == _CONTAINER_AND_OBJECT_INHERIT
        and ace.propagation_flags == 0
        and not ace.inherited
        for ace in receipt.aces
    )

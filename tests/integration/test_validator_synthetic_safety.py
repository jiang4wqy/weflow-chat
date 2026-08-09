import os
from pathlib import Path

import pytest

import conftest as gates


class _Pin:
    def __init__(self, path: Path, *, enter_error=None):
        self.path = path
        self.enter_error = enter_error
        self.closed = False
        self.verifications = 0

    def __enter__(self):
        if self.enter_error is not None:
            raise self.enter_error
        return self

    def verify(self):
        self.verifications += 1

    def __exit__(self, *_args):
        self.closed = True
        return False


def test_owned_run_requires_an_existing_snapshots_root(tmp_path):
    missing = tmp_path / "missing"
    with pytest.raises(
        AssertionError, match="synthetic_snapshots_root_rejected"
    ):
        gates._create_owned_run_root(
            snapshots_root=missing,
            name="synthetic-test",
            pin_directory=lambda path: _Pin(path),
            secure=lambda path, pin: None,
        )
    assert not missing.exists()


def test_owned_run_never_adopts_an_existing_random_name(tmp_path):
    snapshots = tmp_path / "Snapshots"
    snapshots.mkdir()
    existing = snapshots / "synthetic-collision"
    existing.mkdir()
    sentinel = existing / "sentinel"
    sentinel.write_bytes(b"owned elsewhere")

    with pytest.raises(FileExistsError):
        gates._create_owned_run_root(
            snapshots_root=snapshots,
            name=existing.name,
            pin_directory=lambda path: _Pin(path),
            secure=lambda path, pin: None,
        )

    assert sentinel.read_bytes() == b"owned elsewhere"


def test_pin_failure_removes_only_the_empty_created_root(tmp_path):
    snapshots = tmp_path / "Snapshots"
    snapshots.mkdir()
    target = snapshots / "synthetic-pin-failure"

    with pytest.raises(RuntimeError, match="pin_failed"):
        gates._create_owned_run_root(
            snapshots_root=snapshots,
            name=target.name,
            pin_directory=lambda path: _Pin(
                path, enter_error=RuntimeError("pin_failed")
            ),
            secure=lambda path, pin: None,
        )

    assert not target.exists()


def test_secure_failure_preserves_nonempty_owned_root(tmp_path):
    snapshots = tmp_path / "Snapshots"
    snapshots.mkdir()
    target = snapshots / "synthetic-secure-failure"

    def fail_after_marker(path, pin):
        (path / "marker").write_bytes(b"preserve")
        raise RuntimeError("secure_failed")

    with pytest.raises(RuntimeError, match="secure_failed"):
        gates._create_owned_run_root(
            snapshots_root=snapshots,
            name=target.name,
            pin_directory=lambda path: _Pin(path),
            secure=fail_after_marker,
        )

    assert (target / "marker").read_bytes() == b"preserve"


@pytest.mark.skipif(os.name != "nt", reason="Windows handle contract")
def test_empty_pinned_root_is_deleted_through_its_handle(tmp_path):
    from weflow_chat.validator.security import _pin_directory

    target = tmp_path / "owned"
    target.mkdir()
    pin_context = _pin_directory(target)
    pin = pin_context.__enter__()
    try:
        assert gates._delete_empty_pinned_root(target, pin) is True
    finally:
        pin_context.__exit__(None, None, None)

    assert not target.exists()

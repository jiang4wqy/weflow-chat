from pathlib import Path

import pytest


def _synthetic_tree(root: Path, *, include_wal: bool) -> Path:
    root.mkdir()
    (root / "session.db").write_bytes(b"synthetic-db")
    if include_wal:
        (root / "session.db-wal").write_bytes(b"synthetic-wal")
    (root / "session.db-shm").write_bytes(b"synthetic-shm")
    (root / "message_0.db").write_bytes(b"synthetic-message")
    return root


@pytest.fixture
def synthetic_db_storage(tmp_path: Path) -> Path:
    return _synthetic_tree(tmp_path / "db-with-wal", include_wal=True)


@pytest.fixture
def synthetic_db_storage_without_wal(tmp_path: Path) -> Path:
    return _synthetic_tree(tmp_path / "db-without-wal", include_wal=False)

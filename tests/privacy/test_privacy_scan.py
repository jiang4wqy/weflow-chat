from __future__ import annotations

from pathlib import Path

from tools.privacy_scan import scan_payload


def reasons(path: str, payload: bytes) -> set[str]:
    return {
        item.reason
        for item in scan_payload(
            scope="test",
            path=path,
            payload=payload,
        )
    }


def test_accepts_synthetic_source() -> None:
    payload = (
        'account = "wxid_test_account"\n'
        'root = known_folders.local_app_data / "WeFlowChat"\n'
    ).encode()
    assert reasons("src/weflow_chat/settings.py", payload) == set()


def test_rejects_absolute_user_path() -> None:
    payload = (
        b'root = r"C:'
        + b'\\Users\\private-user\\AppData"\n'
    )
    assert "absolute_windows_user_path" in reasons(
        "src/weflow_chat/settings.py", payload
    )


def test_rejects_account_identifier() -> None:
    payload = b'account = "wxid_' + b'privateaccount123"\n'
    assert "account_identifier" in reasons(
        "tests/fixtures/account.txt", payload
    )


def test_rejects_sensitive_file_name() -> None:
    assert "sensitive_filename" in reasons(
        "fixtures/WeFlow-config.json", b"{}"
    )


def test_rejects_database_file() -> None:
    assert "sensitive_file_suffix" in reasons(
        "fixtures/session.db", b"synthetic"
    )


def test_rejects_memory_scanning_only_in_runtime() -> None:
    payload = b"kernel32.ReadProcessMemory(handle)\n"
    assert "process_memory_api" in reasons(
        "src/weflow_chat/unsafe.py", payload
    )
    assert "process_memory_api" not in reasons(
        "docs/security-example.md", payload
    )


def test_rejects_private_key_material() -> None:
    payload = b"-----BEGIN " + b"PRIVATE KEY-----\n"
    assert "private_key_material" in reasons(
        "notes.txt", payload
    )


def test_accepts_utf8_documentation() -> None:
    assert reasons(
        "README.md", "仅处理用户有权访问的数据。".encode("utf-8")
    ) == set()


def test_rejects_non_utf8_tracked_file() -> None:
    assert reasons(
        "fixtures/value.bin", bytes((0xFF, 0xFE, 0x00))
    ) == {"non_utf8_tracked_file"}

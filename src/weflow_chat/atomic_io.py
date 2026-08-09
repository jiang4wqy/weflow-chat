import json
import os
import tempfile
import ctypes
from pathlib import Path


_MOVEFILE_REPLACE_EXISTING = 0x1
_MOVEFILE_WRITE_THROUGH = 0x8


def replace_write_through(source: Path, destination: Path) -> None:
    if os.name == "nt":
        move = ctypes.WinDLL("kernel32", use_last_error=True).MoveFileExW
        move.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p,
                         ctypes.c_uint32]
        move.restype = ctypes.c_int
        if not move(str(source), str(destination),
                    _MOVEFILE_REPLACE_EXISTING |
                    _MOVEFILE_WRITE_THROUGH):
            raise ctypes.WinError(ctypes.get_last_error())
        return
    os.replace(source, destination)
    directory_fd = os.open(destination.parent, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def atomic_write_bytes(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary_name = tempfile.mkstemp(
        prefix="." + path.name + ".", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(handle, "wb", closefd=True) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        replace_write_through(temporary, path)
        if path.read_bytes() != payload:
            raise OSError("atomic_reread_mismatch")
    except BaseException:
        if temporary.exists():
            temporary.unlink()
        raise


def atomic_write_json(path: Path, value: dict[str, object]) -> None:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True,
                         separators=(",", ":")).encode("utf-8")
    atomic_write_bytes(path, payload)

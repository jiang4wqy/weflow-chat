import json
import locale
import os
from pathlib import Path
import subprocess


_SCRIPT = (
    "Get-CimInstance Win32_Process | "
    "Select-Object ProcessId,Name,ExecutablePath | "
    "ConvertTo-Json -Compress"
)


def _is_formal_weflow_running_for_test(
    records, *, formal_weflow: Path
) -> bool:
    expected = os.path.normcase(str(formal_weflow))
    for record in records:
        if isinstance(record, (str, Path)):
            name, value = Path(record).name, str(record)
        elif isinstance(record, dict):
            name, value = record.get("Name"), record.get("ExecutablePath")
        else:
            raise RuntimeError("process_inventory_invalid")
        if (
            isinstance(name, str)
            and name.casefold() == "weflow.exe"
            and not value
        ):
            raise RuntimeError("formal_process_path_unknown")
        if isinstance(name, str) and name.casefold() == "weflow.exe":
            return True
        if value and os.path.normcase(str(Path(value))) == expected:
            return True
    return False


def formal_weflow_is_running(*, formal_weflow: Path) -> bool:
    completed = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            _SCRIPT,
        ],
        check=True,
        capture_output=True,
        text=True,
        encoding=locale.getencoding(),
        errors="replace",
        timeout=30,
    )
    raw = json.loads(completed.stdout or "[]")
    records = raw if isinstance(raw, list) else [raw]
    if not all(isinstance(record, dict) for record in records):
        raise RuntimeError("process_inventory_invalid")
    return _is_formal_weflow_running_for_test(
        records, formal_weflow=formal_weflow
    )

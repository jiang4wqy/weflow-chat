import os
from pathlib import Path
import subprocess


ROOT = Path(__file__).parents[2]
WRAPPER = ROOT / "scripts" / "Run-WeFlowRefresh.cmd"


def test_wrapper_is_fixed_utf8_no_argument_python_entry():
    text = WRAPPER.read_text(
        encoding="utf-8"
    )
    folded = text.casefold()
    assert "%~dp0" in text
    assert "%~1" in text
    assert "%*" not in text
    assert "chcp 65001" in folded
    assert 'set "pythonutf8=1"' in folded
    assert 'set "pythonpath=%repo_root%\\src"' in folded
    assert (
        '"c:\\windows\\py.exe" -3.12 -b -m '
        "weflow_chat.desktop_refresh"
    ) in folded
    assert "\npy " not in folded
    assert "pause" in folded
    assert "exit /b %exit_code%" in folded
    assert "Task finished with exit code %EXIT_CODE%." in text
    assert "No data processing is still running." in text
    assert "Press any key to close this window." in text
    for forbidden in (
        "powershell",
        "invoke-webrequest",
        "curl",
        "wget",
        "weixin.exe",
        "weflow.exe",
        "vss-helper",
        "del ",
        "erase ",
        "rmdir ",
    ):
        assert forbidden not in folded


def test_wrapper_template_forwards_fixed_command_and_exit_code(
    tmp_path,
):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    probe = tmp_path / "probe.txt"
    fake_python = fake_bin / "py.cmd"
    fake_python.write_text(
        "@echo off\r\n"
        "> \"%WRAPPER_PROBE%\" echo args=%*\r\n"
        ">> \"%WRAPPER_PROBE%\" "
        "echo pythonpath=%PYTHONPATH%\r\n"
        ">> \"%WRAPPER_PROBE%\" "
        "echo pythonutf8=%PYTHONUTF8%\r\n"
        "exit /b 7\r\n",
        encoding="utf-8",
    )
    environment = os.environ.copy()
    environment["PATH"] = (
        str(fake_bin)
        + os.pathsep
        + environment["PATH"]
    )
    environment["WRAPPER_PROBE"] = str(probe)
    test_wrapper = tmp_path / "scripts" / WRAPPER.name
    test_wrapper.parent.mkdir()
    test_wrapper.write_text(
        WRAPPER.read_text(encoding="utf-8").replace(
            r'"C:\Windows\py.exe"',
            f'"{fake_python}"',
        ),
        encoding="utf-8",
    )

    completed = subprocess.run(
        [
            "cmd.exe",
            "/d",
            "/c",
            str(test_wrapper),
        ],
        input="\n",
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
        timeout=10,
        env=environment,
    )
    assert completed.returncode == 7
    recorded = probe.read_text(
        encoding="utf-8"
    ).casefold()
    assert (
        "args=-3.12 -b -m "
        "weflow_chat.desktop_refresh"
    ) in recorded
    assert (
        f"pythonpath={tmp_path / 'src'}"
    ).casefold() in recorded
    assert "pythonutf8=1" in recorded

    probe.unlink()
    rejected = subprocess.run(
        [
            "cmd.exe",
            "/d",
            "/c",
            str(test_wrapper),
            "SENSITIVE-ARGUMENT",
        ],
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
        timeout=10,
        env=environment,
    )
    assert rejected.returncode == 2
    assert not probe.exists()
    assert "SENSITIVE-" not in (
        rejected.stdout + rejected.stderr
    )


def test_real_wrapper_rejects_arguments_before_any_path_shadow(
    tmp_path,
):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    probe = tmp_path / "path-shadow-called.txt"
    (fake_bin / "py.cmd").write_text(
        "@echo off\r\n"
        '> "%WRAPPER_PROBE%" echo called\r\n'
        "exit /b 99\r\n",
        encoding="ascii",
    )
    environment = os.environ.copy()
    environment["PATH"] = (
        str(fake_bin)
        + os.pathsep
        + environment["PATH"]
    )
    environment["WRAPPER_PROBE"] = str(probe)

    rejected = subprocess.run(
        [
            "cmd.exe",
            "/d",
            "/c",
            str(WRAPPER),
            "SENSITIVE-ARGUMENT",
        ],
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
        timeout=10,
        env=environment,
    )
    assert rejected.returncode == 2
    assert not probe.exists()
    assert "SENSITIVE-" not in (
        rejected.stdout + rejected.stderr
    )


def test_real_wrapper_rejects_quoted_cmd_metacharacters(
    tmp_path,
):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    probe = tmp_path / "path-shadow-called.txt"
    (fake_bin / "py.cmd").write_text(
        "@echo off\r\n"
        '> "%WRAPPER_PROBE%" echo called\r\n'
        "exit /b 99\r\n",
        encoding="ascii",
    )
    environment = os.environ.copy()
    environment["PATH"] = (
        str(fake_bin)
        + os.pathsep
        + environment["PATH"]
    )
    environment["WRAPPER_PROBE"] = str(probe)

    for argument in (
        "A & echo SENSITIVE-SHELL-SENTINEL",
        "A | echo SENSITIVE-SHELL-SENTINEL",
        "A ) ( echo SENSITIVE-SHELL-SENTINEL",
        'A " B SENSITIVE-SHELL-SENTINEL',
    ):
        rejected = subprocess.run(
            [
                "cmd.exe",
                "/d",
                "/s",
                "/c",
                str(WRAPPER),
                argument,
            ],
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            check=False,
            timeout=10,
            env=environment,
        )
        assert rejected.returncode == 2
        assert not probe.exists()
        assert "SENSITIVE-" not in (
            rejected.stdout + rejected.stderr
        )

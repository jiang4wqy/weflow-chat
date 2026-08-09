from pathlib import Path

from tools.runtime_boundary_scan import scan_runtime


def test_runtime_boundary_accepts_stored_envelope_only(tmp_path: Path):
    source = tmp_path / "src" / "weflow_chat" / "entry.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        'CAPABILITY = "stored-envelope-refresh"\n', encoding="utf-8"
    )

    assert scan_runtime(tmp_path) == ()


def test_runtime_boundary_rejects_forbidden_source(tmp_path: Path):
    source = tmp_path / "src" / "weflow_chat" / "entry.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        "def unsafe():\n    return 'OpenProcess'\n", encoding="utf-8"
    )

    assert scan_runtime(tmp_path) == ("forbidden_runtime_source",)

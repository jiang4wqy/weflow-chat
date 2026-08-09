from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys
from types import CodeType


_FORBIDDEN = re.compile(
    r"(?i)(?:ReadProcessMemory|\bOpenProcess\b|\bkey_recovery\b|"
    r"\bsafe_storage\b|"
    r"read-only-key-recovery|recovered_envelope|"
    r"set_decrypt_key_envelope)"
)
_ROOTS = (
    "src",
    "scripts",
    "validator-node/src",
    "vss-helper",
)
_SUFFIXES = {".py", ".cjs", ".mjs", ".ps1", ".psm1", ".cmd"}


def _code_contains_forbidden(code: CodeType) -> bool:
    if any(_FORBIDDEN.search(name) for name in code.co_names):
        return True
    for value in code.co_consts:
        if isinstance(value, str) and _FORBIDDEN.search(value):
            return True
        if isinstance(value, CodeType) and _code_contains_forbidden(value):
            return True
    return False


def scan_runtime(repo: Path) -> tuple[str, ...]:
    root = repo.resolve(strict=True)
    findings = []
    for relative_root in _ROOTS:
        directory = root / relative_root
        if not directory.is_dir():
            continue
        for path in sorted(directory.rglob("*")):
            if not path.is_file() or path.suffix.casefold() not in _SUFFIXES:
                continue
            try:
                source = path.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                findings.append("runtime_source_unreadable")
                continue
            if _FORBIDDEN.search(source):
                findings.append("forbidden_runtime_source")
                continue
            if path.suffix.casefold() == ".py":
                try:
                    code = compile(source, str(path), "exec")
                except (SyntaxError, ValueError):
                    findings.append("runtime_compile_failed")
                    continue
                if _code_contains_forbidden(code):
                    findings.append("forbidden_runtime_bytecode")
    return tuple(sorted(set(findings)))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="runtime-boundary-scan")
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        findings = scan_runtime(arguments.repo)
    except OSError:
        print("runtime_boundary_scan_error", file=sys.stderr)
        return 2
    for finding in findings:
        print(finding)
    if findings:
        print("runtime_boundary_scan_blocked", file=sys.stderr)
        return 1
    print("runtime_boundary_scan_ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

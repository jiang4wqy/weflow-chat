from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys


_SENSITIVE_BASENAMES = {
    "local state",
    "weflow-config.json",
    "weflow-cache-maps.json",
    "analytics_cache.json",
    "transaction.json",
    "compatibility.json",
    "media-manifest.json",
    "settings.json",
}
_SENSITIVE_SUFFIXES = (
    ".db",
    ".db-shm",
    ".db-wal",
    ".key",
    ".log",
    ".p12",
    ".pem",
    ".pfx",
    ".sqlite",
    ".sqlite3",
)
_SKIP_BINARY_SUFFIXES = {
    ".ico",
    ".jpg",
    ".jpeg",
    ".png",
    ".zip",
}
_MAX_TEXT_BYTES = 8 * 1024 * 1024

_CONTENT_RULES = (
    (
        "absolute_windows_user_path",
        re.compile(r"(?i)(?<![A-Za-z0-9_])[A-Z]:[\\/]+Users[\\/]+[^\\/\r\n]+"),
    ),
    (
        "absolute_unix_user_path",
        re.compile(r"(?i)(?<![A-Za-z0-9_])/(?:Users|home)/[^/\s]+"),
    ),
    (
        "fixed_private_data_root",
        re.compile(
            r"(?i)(?<![A-Za-z0-9_])[A-Z]:[\\/]+"
            r"(?:UserData|AppData|xwechat_files)(?:[\\/]|$)"
        ),
    ),
    (
        "account_identifier",
        re.compile(
            r"(?i)(?<![A-Za-z0-9_])wxid_"
            r"(?!(?:test|example|synthetic)(?:_|\b))"
            r"[A-Za-z0-9_]{8,}"
        ),
    ),
    (
        "github_token",
        re.compile(r"(?<![A-Za-z0-9_])gh[pousr]_[A-Za-z0-9]{20,}"),
    ),
    (
        "aws_access_key",
        re.compile(r"(?<![A-Z0-9])AKIA[A-Z0-9]{16}(?![A-Z0-9])"),
    ),
    (
        "private_key_material",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ),
)

_RUNTIME_PREFIXES = (
    "src/",
    "scripts/",
    "validator-node/src/",
    "vss-helper/",
)
_FORBIDDEN_RUNTIME_RULES = (
    ("process_memory_api", re.compile(r"\b(?:ReadProcessMemory|OpenProcess)\b")),
    (
        "key_recovery_capability",
        re.compile(
            r"\b(?:key_recovery|recover_unique_key_from_windows_process|"
            r"diagnose_internal_key_patterns)\b"
        ),
    ),
)


@dataclass(frozen=True, slots=True)
class Finding:
    scope: str
    path: str
    reason: str
    line: int | None = None

    def render(self) -> str:
        location = self.path
        if self.line is not None:
            location = f"{location}:{self.line}"
        return f"{self.scope}:{location}:{self.reason}"


def _git(repo: Path, *arguments: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(repo), *arguments],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise RuntimeError("git_scan_failed")
    return result.stdout


def _nul_names(payload: bytes) -> tuple[str, ...]:
    return tuple(
        item.decode("utf-8", errors="strict").replace("\\", "/")
        for item in payload.split(b"\0")
        if item
    )


def _path_finding(scope: str, path: str) -> Finding | None:
    pure = PurePosixPath(path)
    lowered = pure.name.casefold()
    if lowered in _SENSITIVE_BASENAMES:
        return Finding(scope, path, "sensitive_filename")
    if any(lowered.endswith(suffix) for suffix in _SENSITIVE_SUFFIXES):
        return Finding(scope, path, "sensitive_file_suffix")
    if any(part.casefold() in {"snapshots", "mediastore", "derivedcache"}
           for part in pure.parts):
        return Finding(scope, path, "sensitive_directory")
    return None


def _content_findings(
    *, scope: str, path: str, payload: bytes
) -> tuple[Finding, ...]:
    if len(payload) > _MAX_TEXT_BYTES:
        return (Finding(scope, path, "tracked_file_too_large"),)
    if PurePosixPath(path).suffix.casefold() in _SKIP_BINARY_SUFFIXES:
        return ()
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return (Finding(scope, path, "non_utf8_tracked_file"),)
    rules = list(_CONTENT_RULES)
    if path.replace("\\", "/").startswith(_RUNTIME_PREFIXES):
        rules.extend(_FORBIDDEN_RUNTIME_RULES)
    findings: list[Finding] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        for reason, pattern in rules:
            if pattern.search(line):
                findings.append(
                    Finding(scope, path, reason, line_number)
                )
    return tuple(findings)


def scan_payload(
    *, scope: str, path: str, payload: bytes
) -> tuple[Finding, ...]:
    path_issue = _path_finding(scope, path)
    findings = () if path_issue is None else (path_issue,)
    return findings + _content_findings(
        scope=scope,
        path=path,
        payload=payload,
    )


def scan_worktree(repo: Path) -> tuple[Finding, ...]:
    names = _nul_names(
        _git(
            repo,
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        )
    )
    findings: list[Finding] = []
    for name in names:
        path = repo / Path(name)
        if not path.is_file():
            continue
        findings.extend(
            scan_payload(
                scope="worktree",
                path=name,
                payload=path.read_bytes(),
            )
        )
    return tuple(findings)


def scan_history(repo: Path) -> tuple[Finding, ...]:
    commits = tuple(
        line for line in _git(repo, "rev-list", "--all").decode().splitlines()
        if line
    )
    findings: list[Finding] = []
    for commit in commits:
        names = _nul_names(
            _git(repo, "ls-tree", "-r", "-z", "--name-only", commit)
        )
        for name in names:
            payload = _git(repo, "show", f"{commit}:{name}")
            findings.extend(
                scan_payload(
                    scope=f"commit:{commit[:12]}",
                    path=name,
                    payload=payload,
                )
            )
    return tuple(findings)


def scan_repository(
    repo: Path, *, include_history: bool = True
) -> tuple[Finding, ...]:
    canonical = repo.resolve(strict=True)
    if not (canonical / ".git").exists():
        raise RuntimeError("git_repository_required")
    findings = list(scan_worktree(canonical))
    if include_history:
        findings.extend(scan_history(canonical))
    unique = {item.render(): item for item in findings}
    return tuple(unique[key] for key in sorted(unique))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="privacy-scan")
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--no-history", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        findings = scan_repository(
            arguments.repo,
            include_history=not arguments.no_history,
        )
    except (OSError, RuntimeError, UnicodeError):
        print("privacy_scan_error", file=sys.stderr)
        return 2
    for finding in findings:
        print(finding.render())
    if findings:
        print(f"privacy_scan_blocked:{len(findings)}", file=sys.stderr)
        return 1
    print("privacy_scan_ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

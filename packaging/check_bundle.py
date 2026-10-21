"""Build-time assertion: the PyInstaller output contains the assets it needs
and none of the operator files that must never ship (config.yaml, S3/env
secrets, SQLite databases, logs, backups, state, .git, archive/, test/).

    python packaging/check_bundle.py dist/logscope            # onedir
    python packaging/check_bundle.py --onefile dist/logscope  # onefile archive

Exits 1 and lists the offending paths on failure.
"""

from __future__ import annotations

import argparse
import fnmatch
import sys
from pathlib import Path, PurePosixPath

REQUIRED = (
    "webapp/ui/index.html",
    "webapp/ui/app.js",
    "webapp/ui/styles.css",
    "config.example.yaml",
    "botocore/data/endpoints.json",
    "webapp/api/signatures.yaml",
    # Rust bindings behind the stored AI key encryption (cryptography.fernet).
    "cryptography/hazmat/bindings/_rust.abi3.so",
)
# Matched against each file's base name.
FORBIDDEN_NAMES = (
    "config.yaml",
    "*secret*.yaml",
    "*secret*.yml",
    "*.env",
    "*.sqlite",
    "*.sqlite-*",
    "*.sqlite3",
    "*.pem.key",
    "id_rsa*",
)
# Never allowed as a top-level directory of the bundle data.
FORBIDDEN_TOP_DIRS = {"logs", "backups", ".state", "archive", "test", "tests", "deploy", "scripts", "local-vector",
                      "production-vector"}
# Never allowed anywhere in a path.
FORBIDDEN_ANY_DIRS = {".git", ".state", ".venv", "venv", ".pytest_cache"}


def _onedir_entries(root: Path) -> list[str]:
    internal = root / "_internal"
    base = internal if internal.is_dir() else root
    return [p.relative_to(base).as_posix() for p in base.rglob("*") if p.is_file() or p.is_symlink()]


def _onefile_entries(binary: Path) -> list[str]:
    from PyInstaller.archive.readers import CArchiveReader

    return [name.replace("\\", "/") for name in CArchiveReader(str(binary)).toc]


def check(entries: list[str]) -> list[str]:
    problems: list[str] = []
    present = set(entries)
    for required in REQUIRED:
        if required not in present:
            problems.append(f"missing required file: {required}")
    for entry in entries:
        path = PurePosixPath(entry)
        parts = path.parts
        if any(fnmatch.fnmatch(path.name, pattern) for pattern in FORBIDDEN_NAMES):
            problems.append(f"forbidden file: {entry}")
        elif parts and len(parts) > 1 and parts[0] in FORBIDDEN_TOP_DIRS:
            problems.append(f"forbidden directory: {entry}")
        elif FORBIDDEN_ANY_DIRS.intersection(parts[:-1]):
            problems.append(f"forbidden directory: {entry}")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("path", type=Path)
    parser.add_argument("--onefile", action="store_true")
    args = parser.parse_args(argv)
    entries = _onefile_entries(args.path) if args.onefile else _onedir_entries(args.path)
    problems = check(entries)
    for problem in problems:
        print(f"check_bundle: {problem}", file=sys.stderr)
    if problems:
        return 1
    print(f"check_bundle: {args.path}: {len(entries)} entries, no forbidden files, required assets present")
    return 0


if __name__ == "__main__":
    sys.exit(main())

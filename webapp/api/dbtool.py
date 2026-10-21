"""Backup, verification, restore and compaction for the web app's SQLite cache.

This is the web app database (cached log records, ingest bookkeeping and the
anomaly triage state), not the Vector file-sink backup CronJob. Records can be
re-read from S3 within the bucket's retention; anomaly status and AI summaries
exist only here.

    python -m webapp.api.dbtool backup  DEST        # online; app may keep running
    python -m webapp.api.dbtool verify  PATH
    python -m webapp.api.dbtool restore SRC --app-stopped
    python -m webapp.api.dbtool compact --app-stopped

The same commands are available as `logscope db ...` (binary and image).

--db defaults to $LOGSCOPE_WEBAPP_DB_PATH (set to /data/logscope.sqlite by the
Helm chart). With --state, backup / verify / restore work on the durable state
database (saved views) instead: --db then defaults to
$LOGSCOPE_WEBAPP_STATE_DB_PATH, else $XDG_DATA_HOME/logscope/state.sqlite, and
copies are created with mode 0600. Nothing is ever deleted or overwritten:
backup refuses an existing destination, and restore keeps the replaced database as
<db>.pre-restore-<UTC timestamp> (plus its -wal/-shm files, if present). Restore
copies and verifies the backup beside the database before swapping it in, so a
failure (e.g. a full disk) leaves the current database untouched. Each command
first checks that the volume has room for what it writes.
"""

from __future__ import annotations

import argparse
import os
import shutil
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

from .state import REQUIRED_TABLES as _STATE_REQUIRED_TABLES
from .state import default_state_db_path, env_state_db_path
from .storage import SQLITE_BUSY_TIMEOUT_SECS

_REQUIRED_TABLES = ("records", "ingested_objects", "app_state")
_COUNTED_TABLES = ("records", "ingested_objects", "anomalies")
_STATE_COUNTED_TABLES = ("saved_views", "ai_usage")
_SIDE_SUFFIXES = ("-wal", "-shm")
# Headroom kept free on the volume beyond what a command needs.
_SPACE_MARGIN_BYTES = 64 * 1024 * 1024


def _connect(path: Path, *, readonly: bool = False) -> sqlite3.Connection:
    if readonly:
        return sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=SQLITE_BUSY_TIMEOUT_SECS)
    return sqlite3.connect(path, timeout=SQLITE_BUSY_TIMEOUT_SECS)


def verify(path: Path, *, state: bool = False) -> dict:
    """Integrity check plus row counts. Raises ValueError if unusable.
    state=True checks for the state database's tables instead of the cache's."""
    required = _STATE_REQUIRED_TABLES if state else _REQUIRED_TABLES
    counted = _STATE_COUNTED_TABLES if state else _COUNTED_TABLES
    kind = "Logscope state database" if state else "Logscope database"
    if not path.is_file():
        raise ValueError(f"{path} does not exist")
    conn = _connect(path, readonly=True)
    try:
        result = [str(row[0]) for row in conn.execute("PRAGMA integrity_check").fetchall()]
        if result != ["ok"]:
            raise ValueError(f"{path} failed integrity_check: {'; '.join(result[:5])}")
        tables = {str(row[0]) for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        missing = [name for name in required if name not in tables]
        if missing:
            raise ValueError(f"{path} is not a {kind} (missing tables: {', '.join(missing)})")
        counts = {
            name: int(conn.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0])  # names from the fixed lists
            for name in counted
            if name in tables
        }
        if state:
            counts["schema_version"] = int(conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0] or 0)
    finally:
        conn.close()
    return {"path": str(path), "integrity": "ok", "counts": counts}


def _used_bytes(db: Path) -> int:
    """Bytes of live pages (what a copy of the database will occupy)."""
    conn = _connect(db, readonly=True)
    try:
        page = int(conn.execute("PRAGMA page_size").fetchone()[0])
        pages = int(conn.execute("PRAGMA page_count").fetchone()[0])
        free = int(conn.execute("PRAGMA freelist_count").fetchone()[0])
    finally:
        conn.close()
    return (pages - free) * page


def _require_space(directory: Path, needed: int, what: str) -> None:
    free = shutil.disk_usage(directory).free
    if free < needed + _SPACE_MARGIN_BYTES:
        raise ValueError(
            f"not enough free space in {directory} for {what}: need about "
            f"{(needed + _SPACE_MARGIN_BYTES) // 2**20} MiB, {free // 2**20} MiB free"
        )


def _fsync_path(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _create_private(path: Path) -> None:
    """Create the empty file path with mode 0600 (the state database's mode),
    so the copy written into it is never readable by others."""
    os.close(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))


def _copy_database(src: Path, dest: Path) -> None:
    """Consistent copy of src into the new file dest, as a self-contained
    rollback-journal database, flushed to disk. Removes dest on failure."""
    source = _connect(src)
    try:
        out = sqlite3.connect(dest)
        try:
            source.backup(out)  # one step: a single consistent snapshot
            # A copy of a WAL database is itself in WAL mode; switch it to a
            # rollback journal so the copy is one self-contained file.
            out.execute("PRAGMA journal_mode = DELETE")
        finally:
            out.close()
        _fsync_path(dest)
    except BaseException:
        dest.unlink(missing_ok=True)
        raise
    finally:
        source.close()


def _publish_new(staged: Path, dest: Path) -> None:
    """Move staged to dest only if dest does not exist (a hard link fails
    instead of replacing, unlike rename), so nothing is ever overwritten."""
    try:
        os.link(staged, dest)
    except FileExistsError:
        raise ValueError(f"{dest} already exists; choose a new file name") from None
    staged.unlink()
    _fsync_path(dest.parent)


def backup(db: Path, dest: Path, *, state: bool = False) -> dict:
    """Consistent online copy via SQLite's backup API (safe while the app is
    writing, including in WAL mode). Never overwrites an existing file."""
    if not db.is_file():
        raise ValueError(f"database {db} does not exist")
    if dest.exists():
        raise ValueError(f"{dest} already exists; choose a new file name")
    if not dest.parent.is_dir():
        raise ValueError(f"directory {dest.parent} does not exist")
    partial = dest.with_name(dest.name + ".partial")
    if partial.exists():
        raise ValueError(f"{partial} exists (an earlier backup was interrupted); remove it first")
    _require_space(dest.parent, _used_bytes(db), "the backup")
    if state:
        _create_private(partial)
    try:
        _copy_database(db, partial)
    except BaseException:
        partial.unlink(missing_ok=True)  # also the pre-created file
        raise
    try:
        _publish_new(partial, dest)
    except BaseException:
        partial.unlink(missing_ok=True)
        raise
    return verify(dest, state=state)


def _assert_not_in_use(db: Path) -> None:
    """Best effort: fail if another connection is writing. A running app that
    is only reading is not detected, which is why --app-stopped is required."""
    conn = sqlite3.connect(db, timeout=1)
    try:
        conn.execute("BEGIN EXCLUSIVE")
        conn.rollback()
    except sqlite3.OperationalError as exc:
        raise ValueError(f"{db} is in use ({exc}); stop the web app first") from None
    finally:
        conn.close()


def _keep_name(db: Path) -> str:
    """A <db>.pre-restore-<stamp> base name that no existing file uses (with
    any -wal/-shm suffix), so an earlier kept copy is never replaced."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    for n in range(1000):
        base = f"{db}.pre-restore-{stamp}" + (f"-{n}" if n else "")
        if not any(Path(base + suffix).exists() for suffix in ("", *_SIDE_SUFFIXES)):
            return base
    raise ValueError(f"too many {db}.pre-restore-{stamp}* files; move some away first")


def restore(db: Path, src: Path, *, state: bool = False) -> dict:
    """Replace db with a verified copy of src. The copy is built and checked
    next to db first; only then is the current database moved aside (kept as
    <db>.pre-restore-<timestamp>[-wal|-shm]) and the copy moved in. A failure
    before that point leaves the current database in place."""
    verify(src, state=state)
    if db.exists() and src.resolve() == db.resolve():
        raise ValueError("source and destination are the same file")
    if not db.parent.is_dir():
        raise ValueError(f"directory {db.parent} does not exist")
    staged = Path(f"{db}.restore-partial")
    if staged.exists():
        raise ValueError(f"{staged} exists (an earlier restore was interrupted); remove it first")
    if db.exists():
        _assert_not_in_use(db)
    _require_space(db.parent, _used_bytes(src), "the restored copy")
    if state:
        _create_private(staged)
    try:
        _copy_database(src, staged)
    except BaseException:
        staged.unlink(missing_ok=True)  # also the pre-created file
        raise
    try:
        verify(staged, state=state)
        kept: list[str] = []
        if db.exists():
            conn = sqlite3.connect(db)
            try:
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")  # fold any WAL into the main file
            finally:
                conn.close()
            base = _keep_name(db)
            for suffix in ("", *_SIDE_SUFFIXES):
                current = Path(f"{db}{suffix}")
                if current.exists():
                    target = Path(base + suffix)
                    os.link(current, target)  # fails rather than replacing an existing file
                    kept.append(str(target))
            # The WAL was just checkpointed and truncated. Its old -wal/-shm
            # must not sit beside the restored file (SQLite would apply them).
            for suffix in _SIDE_SUFFIXES:
                Path(f"{db}{suffix}").unlink(missing_ok=True)
        # Atomic: db is always either the old file (still reachable under its
        # kept name) or the verified copy, never missing.
        os.replace(staged, db)
        _fsync_path(db.parent)
    except BaseException:
        staged.unlink(missing_ok=True)
        raise
    report = verify(db, state=state)
    report["previous_database_kept_as"] = kept
    return report


def compact(db: Path) -> dict:
    """Rebuild the file without free pages and switch it to incremental
    auto-vacuum, so later pruning returns space to the filesystem. Needs free
    disk space of about the database size while it runs."""
    if not db.is_file():
        raise ValueError(f"database {db} does not exist")
    _assert_not_in_use(db)
    before = db.stat().st_size
    # VACUUM writes a temporary copy, and in WAL mode the rewritten pages go
    # through the WAL as well: allow for two copies of the live data.
    _require_space(db.parent, 2 * _used_bytes(db), "compaction")
    conn = sqlite3.connect(db)
    try:
        conn.execute("PRAGMA auto_vacuum = INCREMENTAL")
        conn.execute("VACUUM")
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        conn.close()
    return {"path": str(db), "bytes_before": before, "bytes_after": db.stat().st_size, **verify(db)}


def _default_db(state: bool = False) -> Path | None:
    if state:
        return env_state_db_path() or default_state_db_path()
    value = os.environ.get("LOGSCOPE_WEBAPP_DB_PATH", "").strip()
    return Path(value) if value else None


def main(argv: list[str] | None = None, prog: str = "python -m webapp.api.dbtool") -> int:
    parser = argparse.ArgumentParser(prog=prog, description=__doc__.split("\n\n")[0])
    parser.add_argument("--db", type=Path, default=None,
                        help="database file (default: $LOGSCOPE_WEBAPP_DB_PATH; with --state, "
                             "$LOGSCOPE_WEBAPP_STATE_DB_PATH or $XDG_DATA_HOME/logscope/state.sqlite)")
    state_help = "the durable state database (saved views) instead of the log cache"
    sub = parser.add_subparsers(dest="command", required=True)
    p_backup = sub.add_parser("backup", help="consistent online copy to a new file")
    p_backup.add_argument("dest", type=Path)
    p_backup.add_argument("--state", action="store_true", help=state_help)
    p_verify = sub.add_parser("verify", help="integrity check and row counts")
    p_verify.add_argument("path", type=Path)
    p_verify.add_argument("--state", action="store_true", help=state_help)
    p_restore = sub.add_parser("restore", help="replace the database with a backup (app must be stopped)")
    p_restore.add_argument("src", type=Path)
    p_restore.add_argument("--state", action="store_true", help=state_help)
    p_restore.add_argument("--app-stopped", action="store_true", required=True,
                           help="confirm the web app is not running")
    p_compact = sub.add_parser("compact", help="VACUUM and enable incremental auto-vacuum (app must be stopped; "
                                               "needs free space of about twice the live data)")
    p_compact.add_argument("--app-stopped", action="store_true", required=True,
                           help="confirm the web app is not running")
    args = parser.parse_args(argv)

    state = bool(getattr(args, "state", False))
    db = args.db or _default_db(state)
    try:
        if args.command == "verify":
            report = verify(args.path, state=state)
        else:
            if db is None:
                parser.error("--db is required (or set LOGSCOPE_WEBAPP_DB_PATH)")
            if args.command == "backup":
                report = backup(db, args.dest, state=state)
            elif args.command == "restore":
                report = restore(db, args.src, state=state)
            else:
                report = compact(db)
    except (ValueError, OSError, sqlite3.Error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    for key, value in report.items():
        print(f"{key}: {value}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

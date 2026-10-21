"""Keeps the durable state database (saved views) out of the real home
directory: every test gets its own XDG_DATA_HOME, and an inherited
LOGSCOPE_WEBAPP_STATE_DB_PATH is ignored."""

import os
import tempfile

import pytest

# Also covers configs loaded at import time, before any fixture runs.
os.environ["XDG_DATA_HOME"] = tempfile.mkdtemp(prefix="logscope-test-xdg-")
os.environ.pop("LOGSCOPE_WEBAPP_STATE_DB_PATH", None)


@pytest.fixture(autouse=True)
def _isolated_state_db(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg-data"))
    monkeypatch.delenv("LOGSCOPE_WEBAPP_STATE_DB_PATH", raising=False)

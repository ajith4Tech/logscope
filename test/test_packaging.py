"""packaging/check_bundle.py: the build-time assertion on the PyInstaller output."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packaging"))

import check_bundle  # noqa: E402


def test_check_bundle_flags_operator_files_and_missing_assets():
    good = list(check_bundle.REQUIRED) + ["botocore/data/secretsmanager/2017-10-17/service-2.json.gz",
                                          "botocore/data/logs/2014-03-28/service-2.json.gz"]
    assert check_bundle.check(good) == []
    for leaked in ("config.yaml", "deploy/k3s/s3-secret.yaml", "data/logscope.sqlite-wal", ".git/HEAD",
                   "logs/infra/error.log", "test/fixtures/config.test.yaml", "x/.state/s.json", "logscope.env"):
        assert check_bundle.check(good + [leaked]), leaked
    assert check_bundle.check(good[1:])  # a required asset missing

# PyInstaller spec for the `logscope` binary.
#
#   python -m PyInstaller --noconfirm --clean packaging/logscope.spec                     # onedir (container)
#   LOGSCOPE_ONEFILE=1 python -m PyInstaller --noconfirm --clean packaging/logscope.spec  # onefile (standalone)
#
# Built inside the Dockerfile's builder stage (python:3.12-slim-bookworm, glibc
# 2.36), so the binary runs on that glibc or newer. Bundled data mirrors the
# repository layout under sys._MEIPASS; logscope/resources.py resolves it.
# Write logscope/_version.py first (packaging/write_version.py).

import importlib.util
import os
import shutil
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules, copy_metadata

ROOT = Path(SPECPATH).resolve().parent  # noqa: F821 - SPECPATH is set by PyInstaller
ONEFILE = os.environ.get("LOGSCOPE_ONEFILE") == "1"
UPX = shutil.which("upx") is not None  # used only when installed; the builder image has none

if not (ROOT / "logscope" / "_version.py").is_file():
    raise SystemExit("logscope/_version.py is missing: run packaging/write_version.py VERSION first")

# Explicit file list (not a directory glob), so nothing else in webapp/ui can ride along.
datas = [(str(ROOT / "webapp" / "ui" / name), "webapp/ui") for name in ("index.html", "app.js", "styles.css")]
datas.append((str(ROOT / "config.example.yaml"), "."))  # `logscope render` fallback config
# Built-in log signatures, read next to webapp/api/signatures.py.
datas.append((str(ROOT / "webapp" / "api" / "signatures.yaml"), "webapp/api"))
# botocore/boto3 service models and endpoint data are JSON files, not imports.
datas += collect_data_files("botocore") + collect_data_files("boto3")

hiddenimports = (
    collect_submodules("logscope")
    + collect_submodules("webapp")
    + collect_submodules("anthropic")  # provider SDK, imported lazily by webapp.api.ai_summary
    + collect_submodules("cryptography")  # stored AI key encryption (webapp.api.secrets); Rust + cffi bindings
    + ["_cffi_backend"]
    + collect_submodules("botocore")
    + collect_submodules("boto3")
)

# certifi (CA bundle) only if it is part of the locked dependency set; the
# image also points SSL_CERT_FILE at the system CA bundle.
if importlib.util.find_spec("certifi") is not None:
    datas += collect_data_files("certifi")
    hiddenimports.append("certifi")

# Distribution metadata some SDKs read at runtime (importlib.metadata.version).
for dist in ("anthropic", "boto3", "botocore", "pydantic", "httpx2", "cryptography"):
    try:
        datas += copy_metadata(dist)
    except Exception:  # noqa: BLE001 - not installed
        pass

excludes = [
    "tkinter", "_tkinter", "turtle", "turtledemo", "idlelib",  # tk
    "test", "tests", "pytest", "_pytest", "lib2to3", "pydoc_data",  # tests and dev tools
]

a = Analysis(  # noqa: F821
    [str(ROOT / "packaging" / "entry.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
    optimize=0,  # keep asserts: identical behaviour to the source tree
)
pyz = PYZ(a.pure)  # noqa: F821

if ONEFILE:
    exe = EXE(  # noqa: F821
        pyz,
        a.scripts,
        a.binaries,
        a.datas,
        [],
        name="logscope",
        debug=False,
        strip=True,
        upx=UPX,
        runtime_tmpdir=None,  # $TMPDIR, else /tmp
        console=True,
    )
else:
    exe = EXE(  # noqa: F821
        pyz,
        a.scripts,
        [],
        exclude_binaries=True,
        name="logscope",
        debug=False,
        strip=True,
        upx=UPX,
        console=True,
    )
    coll = COLLECT(  # noqa: F821
        exe,
        a.binaries,
        a.datas,
        strip=True,
        upx=UPX,
        name="logscope",
    )

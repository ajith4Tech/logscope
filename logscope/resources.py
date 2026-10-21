"""Locate files shipped with Logscope in a source checkout, an installed
package and a PyInstaller bundle (onefile or onedir), never relative to the
current working directory.

Bundled data mirrors the repository layout under sys._MEIPASS
(packaging/logscope.spec): webapp/ui/* and config.example.yaml.
"""

from __future__ import annotations

import sys
from importlib import resources
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # importlib.abc.Traversable moved to importlib.resources.abc in 3.11
    from importlib.resources.abc import Traversable

# Repository root when running from a source checkout.
_SOURCE_ROOT = Path(__file__).resolve().parents[1]

UI_FILES = ("index.html", "app.js", "styles.css")


def is_frozen() -> bool:
    """True inside a PyInstaller bundle."""
    return bool(getattr(sys, "frozen", False)) and hasattr(sys, "_MEIPASS")


def bundle_root() -> Path:
    """Directory holding bundled data: the PyInstaller data directory when
    frozen, else the repository root."""
    return Path(sys._MEIPASS) if is_frozen() else _SOURCE_ROOT  # type: ignore[attr-defined]


def ui_asset(name: str) -> Traversable:
    """One of the web UI files (index.html, app.js, styles.css)."""
    if name not in UI_FILES:
        raise ValueError(f"unknown UI asset {name!r}")
    if is_frozen():
        return bundle_root() / "webapp" / "ui" / name
    return resources.files("webapp").joinpath("ui", name)


def example_config() -> Path:
    """config.example.yaml (the render fallback when no config.yaml exists)."""
    return bundle_root() / "config.example.yaml"


def project_dir() -> Path:
    """Where operator files (config.yaml, deploy/, deploy/k3s/s3-secret.yaml)
    are looked up by default: the repository root in a source checkout. A
    standalone binary has no repository, so it uses the directory it is run
    from; pass --config / --out / --secret to avoid relying on that."""
    return Path.cwd() if is_frozen() else _SOURCE_ROOT


def default_server_config() -> Path:
    """Default --config for `logscope serve`: config.yaml in the repository
    (source checkout) or /etc/logscope/config.yaml (binary / container)."""
    return Path("/etc/logscope/config.yaml") if is_frozen() else _SOURCE_ROOT / "config.yaml"

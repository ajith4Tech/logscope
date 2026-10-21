"""Build version. logscope/_version.py is generated at build time
(packaging/write_version.py, called by the Dockerfile and `make bin` /
`make image`) and is not committed; a plain source checkout reports the
fallback below."""

from __future__ import annotations

try:
    from ._version import __revision__, __version__
except ImportError:  # source checkout without a build
    __version__ = "0.0.0+dev"
    __revision__ = ""

__all__ = ["__version__", "__revision__"]

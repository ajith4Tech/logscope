#!/usr/bin/env python3
"""Render Vector Helm values, raw vector.yaml, and the backup CronJob from config.

Compatibility wrapper: the code lives in logscope/render.py and is also
available as `logscope render`. `python3 scripts/render.py` and
`import render` (with scripts/ on sys.path) keep working.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from logscope import render as _impl  # noqa: E402

if __name__ == "__main__":
    sys.exit(_impl.main())
else:
    sys.modules[__name__] = _impl  # `import render` gets the real module

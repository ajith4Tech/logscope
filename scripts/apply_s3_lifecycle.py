#!/usr/bin/env python3
"""Apply Logscope S3 Lifecycle expiration from config.yaml.

Compatibility wrapper: the code lives in logscope/s3_lifecycle.py and is also
available as `logscope s3-lifecycle`. `python3 scripts/apply_s3_lifecycle.py`
and `import apply_s3_lifecycle` (with scripts/ on sys.path) keep working.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from logscope import s3_lifecycle as _impl  # noqa: E402

if __name__ == "__main__":
    sys.exit(_impl.main())
else:
    sys.modules[__name__] = _impl  # `import apply_s3_lifecycle` gets the real module

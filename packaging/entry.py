"""PyInstaller entry script for the `logscope` binary (see logscope.spec)."""

import sys

from logscope.cli import main

if __name__ == "__main__":
    sys.exit(main())

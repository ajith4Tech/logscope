"""Download a pinned kubectl release and verify its SHA-256 (image build arg
INCLUDE_KUBECTL=true). Standard library only.

    python fetch_kubectl.py VERSION ARCH SHA256 DEST
"""

from __future__ import annotations

import hashlib
import os
import sys
import urllib.request

_URL = "https://dl.k8s.io/release/{version}/bin/linux/{arch}/kubectl"


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    version, arch, expected, dest = argv
    if arch not in ("amd64", "arm64"):
        print(f"unsupported architecture {arch!r}", file=sys.stderr)
        return 2
    url = _URL.format(version=version, arch=arch)
    digest = hashlib.sha256()
    partial = dest + ".partial"
    # Fixed https URL (_URL); the download is checked against the pinned sha256.
    with urllib.request.urlopen(url, timeout=120) as resp, open(partial, "wb") as out:  # noqa: S310
        while chunk := resp.read(1 << 20):
            digest.update(chunk)
            out.write(chunk)
    actual = digest.hexdigest()
    if actual != expected.lower():
        os.unlink(partial)
        print(f"kubectl {version} {arch}: sha256 {actual} does not match the pinned {expected}", file=sys.stderr)
        return 1
    os.chmod(partial, 0o755)  # noqa: S103 - an executable for every user of the image
    os.replace(partial, dest)
    print(f"kubectl {version} {arch}: sha256 verified")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

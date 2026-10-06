#!/usr/bin/env python3
"""Fail if the version is not the same everywhere it is written.

    python3 tools/check_version.py            # consistency of vpnman/__init__.py, README badge, man page, metainfo
    python3 tools/check_version.py 1.2.3      # ... and that it equals 1.2.3 (the release workflow passes the tag)
"""
import os
import re
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


def read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


def versions():
    found = {}
    found["vpnman/__init__.py"] = re.search(r'^__version__ = "([^"]+)"', read("vpnman/__init__.py"), re.M).group(1)
    m = re.search(r"badge/version-([0-9][^-]*)-blue", read("README.md"))
    found["README.md badge"] = m.group(1) if m else None
    m = re.search(r'^\.TH VPNMAN 1 "[^"]*" "vpnman ([^"]+)"', read("data/vpnman.1"), re.M)
    found["data/vpnman.1"] = m.group(1) if m else None
    m = re.search(r'<release version="([^"]+)"', read("data/io.github.smiley_mcsmiles.VPNMan.metainfo.xml"))
    found["metainfo (newest release)"] = m.group(1) if m else None
    return found


def main(argv):
    found = versions()
    want = argv[1].lstrip("v") if len(argv) > 1 else found["vpnman/__init__.py"]
    bad = {k: v for k, v in found.items() if v != want}
    if bad:
        print("version mismatch (expected %s):" % want, file=sys.stderr)
        for k, v in found.items():
            print("  %-28s %s%s" % (k, v, "   <-- wrong" if k in bad else ""), file=sys.stderr)
        return 1
    print("version %s everywhere" % want)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

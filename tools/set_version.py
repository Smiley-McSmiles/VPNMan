#!/usr/bin/env python3
"""Set the version everywhere it is written (the counterpart of check_version.py).

    python3 tools/set_version.py 1.2.0 [--note "what changed"]      (package.sh --version 1.2.0 does this first)

Updates vpnman/__init__.py, the README badge, the man page's .TH line (and its month) and, when the newest release in the
metainfo is a different version, adds a new release entry (with the note, default "Release X.Y.Z") above it: the release
notes of the GitHub release are written from that file, so edit the entry afterwards.
"""
import os
import re
import sys
import time

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
META = "data/io.github.smiley_mcsmiles.VPNMan.metainfo.xml"


def read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


def write(rel, text):
    with open(os.path.join(ROOT, rel), "w", encoding="utf-8") as fh:
        fh.write(text)


def sub(rel, pattern, repl, flags=0):
    text = read(rel)
    new, n = re.subn(pattern, repl, text, count=1, flags=flags)
    if n != 1:
        raise SystemExit("set_version: could not find the version in %s" % rel)
    write(rel, new)


def main(argv):
    args = argv[1:]
    note = None
    if "--note" in args:
        i = args.index("--note")
        note = args[i + 1] if i + 1 < len(args) else None
        del args[i:i + 2]
    if len(args) != 1 or not re.fullmatch(r"\d+\.\d+\.\d+(\.\d+)?", args[0].lstrip("v")):
        print("usage: set_version.py MAJOR.MINOR.PATCH[.BUILD] [--note TEXT]", file=sys.stderr)
        return 2
    version = args[0].lstrip("v")
    sub("vpnman/__init__.py", r'^__version__ = "[^"]+"', '__version__ = "%s"' % version, re.M)
    sub("README.md", r"badge/version-[0-9][^-]*-blue\.svg\?style=flat-square\" alt=\"Version [^\"]*\"",
        'badge/version-%s-blue.svg?style=flat-square" alt="Version %s"' % (version, version))
    sub("data/vpnman.1", r'^\.TH VPNMAN 1 "[^"]*" "vpnman [^"]+"',
        '.TH VPNMAN 1 "%s" "vpnman %s"' % (time.strftime("%B %Y"), version), re.M)
    meta = read(META)
    newest = re.search(r'<release version="([^"]+)"', meta).group(1)
    if newest != version:
        entry = ('    <release version="%s" date="%s">\n      <description>\n        <ul>\n          <li>%s</li>\n'
                 '        </ul>\n      </description>\n    </release>\n') % (
                     version, time.strftime("%Y-%m-%d"), (note or "Release %s" % version))
        write(META, meta.replace("  <releases>\n", "  <releases>\n" + entry, 1))
        print("added release %s to the metainfo - edit its notes" % version)
    print("version set to %s" % version)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

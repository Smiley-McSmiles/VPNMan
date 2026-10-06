#!/usr/bin/env python3
"""Print the release notes for one version as Markdown, taken from the AppStream metainfo (the single source).

    python3 tools/release_notes.py 1.0.5
"""
import os
import re
import sys
import xml.etree.ElementTree as ET

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


def notes(version):
    tree = ET.parse(os.path.join(ROOT, "data", "io.github.smiley_mcsmiles.VPNMan.metainfo.xml"))
    for rel in tree.getroot().iter("release"):
        if rel.get("version") == version:
            items = [re.sub(r"\s+", " ", (li.text or "")).strip() for li in rel.iter("li")]
            return items
    return None


if __name__ == "__main__":
    version = (sys.argv[1] if len(sys.argv) > 1 else "").lstrip("v")
    items = notes(version)
    if items is None:
        print("no release %s in the metainfo file" % version, file=sys.stderr)
        sys.exit(1)
    print("## VPNMan %s\n" % version)
    print("\n".join("- %s" % i for i in items) if items else "See the commit history for details.")

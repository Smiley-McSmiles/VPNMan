#!/usr/bin/env python3
"""Build a .deb from a staged directory tree without needing dpkg-deb.

usage: mkdeb.py <staged-root-with-DEBIAN-dir> <output.deb>

A .deb is an `ar` archive of: debian-binary, control.tar.gz, data.tar.gz.
Every entry is owned by root:root, so this works on any distribution.
"""
import gzip
import io
import os
import sys
import tarfile
import time


def tar_gz(root, base, skip_top=None):
    buf = io.BytesIO()
    now = int(os.environ.get("SOURCE_DATE_EPOCH", time.time()))

    def norm(ti):
        ti.uid = ti.gid = 0
        ti.uname = ti.gname = "root"
        ti.mtime = now
        return ti

    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=now, compresslevel=9) as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.GNU_FORMAT) as tf:
            tf.add(base, arcname=".", filter=norm, recursive=False)
            for dirpath, dirs, files in os.walk(base):
                dirs.sort()
                if dirpath == base and skip_top:
                    dirs[:] = [d for d in dirs if d != skip_top]
                for name in sorted(dirs + files):
                    full = os.path.join(dirpath, name)
                    tf.add(full, arcname="./" + os.path.relpath(full, base), filter=norm, recursive=False)
    return buf.getvalue()


def ar_member(name, data, now):
    hdr = "%-16s%-12d%-6d%-6d%-8s%-10d`\n" % (name + "/", now, 0, 0, "100644", len(data))
    out = hdr.encode() + data
    if len(data) % 2:
        out += b"\n"
    return out


def main(root, out):
    control_dir = os.path.join(root, "DEBIAN")
    if not os.path.isfile(os.path.join(control_dir, "control")):
        sys.exit("no DEBIAN/control in %s" % root)
    now = int(os.environ.get("SOURCE_DATE_EPOCH", time.time()))
    control = tar_gz(root, control_dir)
    data = tar_gz(root, root, skip_top="DEBIAN")
    with open(out, "wb") as fh:
        fh.write(b"!<arch>\n")
        fh.write(ar_member("debian-binary", b"2.0\n", now))
        fh.write(ar_member("control.tar.gz", control, now))
        fh.write(ar_member("data.tar.gz", data, now))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(*sys.argv[1:])

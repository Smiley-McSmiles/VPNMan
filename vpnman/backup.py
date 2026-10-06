"""Backup and restore of profiles (with their credentials and key files) and settings.

The archive is a plain .tar.gz.  It contains passwords and private keys, so the clients write it 0600 and warn.
Restoring never trusts the archive: only the expected file names are accepted (no paths, links or devices), sizes are
capped, and everything is written with private permissions by this module - nothing is extracted by tarfile itself.
"""

import io
import json
import os
import re
import tarfile
import time

from . import __version__

FORMAT = 1
MANIFEST = "vpnman-backup.json"
MAX_FILE = 8 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024
MAX_MEMBERS = 5000
_PROFILE_FILE = re.compile(r"^profiles/([0-9a-f]{12})/([A-Za-z0-9._-]{1,128})$")


class BackupError(ValueError):
    pass


def export_archive(config_dir, settings_path, count_hint=None):
    """Return the archive bytes for everything under <config_dir>/profiles plus the settings file."""
    buf = io.BytesIO()
    profiles = os.path.join(config_dir, "profiles")
    now = int(time.time())
    n = 0
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        def add(name, data):
            ti = tarfile.TarInfo(name)
            ti.size, ti.mode, ti.mtime, ti.uid, ti.gid = len(data), 0o600, now, 0, 0
            ti.uname = ti.gname = "root"
            tf.addfile(ti, io.BytesIO(data))
        try:
            pids = sorted(os.listdir(profiles))
        except OSError:
            pids = []
        for pid in pids:
            d = os.path.join(profiles, pid)
            if not re.match(r"^[0-9a-f]{12}$", pid) or not os.path.isdir(d):
                continue
            if not os.path.isfile(os.path.join(d, "profile.json")):
                continue
            n += 1
            for fn in sorted(os.listdir(d)):
                full = os.path.join(d, fn)
                if os.path.isfile(full) and not os.path.islink(full) and re.match(r"^[A-Za-z0-9._-]{1,128}$", fn) \
                        and not fn.endswith(".tmp"):
                    with open(full, "rb") as fh:
                        add("profiles/%s/%s" % (pid, fn), fh.read())
        if os.path.isfile(settings_path):
            with open(settings_path, "rb") as fh:
                add("settings.json", fh.read())
        manifest = {"format": FORMAT, "vpnman": __version__, "created": now, "profiles": n}
        add(MANIFEST, json.dumps(manifest).encode())
    return buf.getvalue()


def read_archive(data):
    """Validate an archive and return (manifest, {profile id: {filename: bytes}}, settings dict or None)."""
    if len(data) > MAX_TOTAL:
        raise BackupError("the backup file is too large")
    try:
        tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
    except (tarfile.TarError, OSError, EOFError) as e:
        raise BackupError("not a VPNMan backup (%s)" % e)
    manifest, settings, profiles, total = None, None, {}, 0
    with tf:
        members = tf.getmembers()
        if len(members) > MAX_MEMBERS:
            raise BackupError("the backup has too many files")
        for m in members:
            if not m.isreg():
                raise BackupError("the backup contains something that is not a plain file: %s" % m.name)
            if m.size > MAX_FILE:
                raise BackupError("a file in the backup is too large: %s" % m.name)
            total += m.size
            if total > MAX_TOTAL:
                raise BackupError("the backup is too large")
            name = m.name[2:] if m.name.startswith("./") else m.name
            body = tf.extractfile(m).read()
            if name == MANIFEST:
                try:
                    manifest = json.loads(body)
                except ValueError:
                    raise BackupError("the backup manifest is damaged")
            elif name == "settings.json":
                try:
                    settings = json.loads(body)
                except ValueError:
                    raise BackupError("the backup settings are damaged")
                if not isinstance(settings, dict):
                    raise BackupError("the backup settings are damaged")
            else:
                mt = _PROFILE_FILE.match(name)
                if not mt:
                    raise BackupError("unexpected file in the backup: %s" % name)
                profiles.setdefault(mt.group(1), {})[mt.group(2)] = body
    if not manifest or manifest.get("format") != FORMAT:
        raise BackupError("not a VPNMan backup (or from a newer version)")
    for pid, files in profiles.items():
        try:
            p = json.loads(files.get("profile.json", b""))
            if p.get("id") != pid or "name" not in p or "protocol" not in p:
                raise ValueError
        except (ValueError, AttributeError):
            raise BackupError("profile %s in the backup is damaged" % pid)
    return manifest, profiles, settings


def write_profile(profiles_root, pid, files):
    d = os.path.join(profiles_root, pid)
    os.makedirs(d, mode=0o700, exist_ok=True)
    os.chmod(profiles_root, 0o700)
    for fn, body in files.items():
        fd = os.open(os.path.join(d, fn), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(body)

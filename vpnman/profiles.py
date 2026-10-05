"""Profile storage and import.

A profile is a directory ``<profiles>/<id>/`` holding ``profile.json`` plus any
files a protocol needs (certificates, keys, the original config).  The whole
tree is root-only (0700/0600) because it contains credentials.
"""

import base64
import json
import os
import re
import shutil
import time
import uuid

from . import paths

_SAFE_NAME = re.compile(r"^[A-Za-z0-9._+=@-][A-Za-z0-9._+=@ -]{0,127}$")


class ProfileError(Exception):
    pass


def safe_filename(name):
    name = os.path.basename(name.replace("\\", "/"))
    if not _SAFE_NAME.match(name) or name in (".", ".."):
        raise ProfileError("unsafe file name: %r" % name)
    return name


def new_profile(name, protocol, **kw):
    p = {
        "id": uuid.uuid4().hex[:12],
        "name": name,
        "protocol": protocol,
        "server": "",
        "port": 0,
        "transport": "",
        "username": "",
        "password": "",
        "key_password": "",
        "config": "",
        "favorite": False,
        "blacklisted": False,
        "group": "",
        "notes": "",
        "dns": [],
        "options": {},
        "created": int(time.time()),
    }
    p.update(kw)
    return p


def public_view(p):
    """Profile without secrets - what clients get to see."""
    q = dict(p)
    q["has_password"] = bool(q.pop("password", ""))
    q["has_key_password"] = bool(q.pop("key_password", ""))
    return q


class ProfileStore:
    def __init__(self, root=None):
        self.root = root or paths.profiles_dir()

    def _dir(self, pid):
        if not re.match(r"^[0-9a-f]{12}$", pid):
            raise ProfileError("bad profile id")
        return os.path.join(self.root, pid)

    def list(self):
        out = []
        try:
            entries = sorted(os.listdir(self.root))
        except OSError:
            return out
        for e in entries:
            try:
                with open(os.path.join(self.root, e, "profile.json")) as fh:
                    out.append(json.load(fh))
            except (OSError, ValueError):
                continue
        out.sort(key=lambda p: (not p.get("favorite"), p.get("name", "").lower()))
        return out

    def find(self, ident):
        """Resolve by id, exact name, then unique case-insensitive substring."""
        profiles = self.list()
        for p in profiles:
            if p["id"] == ident:
                return p
        for p in profiles:
            if p["name"] == ident:
                return p
        low = ident.lower()
        for p in profiles:
            if p["name"].lower() == low:
                return p
        hits = [p for p in profiles if low in p["name"].lower()]
        if len(hits) == 1:
            return hits[0]
        if len(hits) > 1:
            raise ProfileError("'%s' is ambiguous: %s" % (ident, ", ".join(h["name"] for h in hits[:6])))
        raise ProfileError("no such profile: %s" % ident)

    def dir_of(self, p):
        return self._dir(p["id"])

    def save(self, p, files=None):
        d = self._dir(p["id"])
        os.makedirs(d, mode=0o700, exist_ok=True)
        os.chmod(self.root, 0o700)
        for name, data in (files or {}).items():
            fn = safe_filename(name)
            if isinstance(data, str):
                data = data.encode()
            fd = os.open(os.path.join(d, fn), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
        tmp = os.path.join(d, "profile.json.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(p, fh, indent=2)
        os.replace(tmp, os.path.join(d, "profile.json"))
        return p

    def update(self, ident, changes):
        p = self.find(ident)
        for k, v in changes.items():
            if k in ("id", "created"):
                continue
            if k not in p:
                raise ProfileError("unknown field: %s" % k)
            p[k] = v
        return self.save(p)

    def remove(self, ident):
        p = self.find(ident)
        shutil.rmtree(self._dir(p["id"]), ignore_errors=True)
        return p

    def read_file(self, p, name):
        with open(os.path.join(self._dir(p["id"]), safe_filename(name)), "rb") as fh:
            return fh.read()


# ---------------------------------------------------------------- client side

_OVPN_FILE_DIRECTIVES = ("ca", "cert", "key", "dh", "pkcs12", "crl-verify", "tls-auth", "tls-crypt",
                         "tls-crypt-v2", "secret", "extra-certs", "auth-user-pass", "askpass",
                         "http-proxy-user-pass")


def collect_files(path):
    """Read a config file plus the files it references (client side).

    Returns ``(text, files)`` where ``files`` maps safe basenames to base64 data
    and ``text`` has file references rewritten to those basenames, so the
    profile is self-contained once it is stored by the root daemon.
    """
    with open(path, "rb") as fh:
        raw = fh.read()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("latin-1")
    files = {}
    base = os.path.dirname(os.path.abspath(path))
    if not looks_like_openvpn(text):
        return text, files
    out = []
    inline = None
    for line in text.splitlines():
        s = line.strip()
        if inline:
            if s.startswith("</" + inline):
                inline = None
            out.append(line)
            continue
        m = re.match(r"^<([a-z0-9-]+)>$", s)
        if m:
            inline = m.group(1)
            out.append(line)
            continue
        parts = s.split(None, 2)
        if parts and parts[0] in _OVPN_FILE_DIRECTIVES and len(parts) >= 2 and not s.startswith(("#", ";")):
            ref = parts[1].strip("\"'")
            full = ref if os.path.isabs(ref) else os.path.join(base, ref)
            if os.path.isfile(full) and ref != "[inline]":
                bn = os.path.basename(full)
                if bn in files and files[bn][0] != full:
                    bn = "%d-%s" % (len(files), bn)
                try:
                    with open(full, "rb") as fh:
                        files[bn] = (full, base64.b64encode(fh.read()).decode())
                    rest = (" " + parts[2]) if len(parts) > 2 else ""
                    out.append("%s %s%s" % (parts[0], bn, rest))
                    continue
                except OSError:
                    pass
        out.append(line)
    return "\n".join(out) + "\n", {k: v[1] for k, v in files.items()}


def looks_like_openvpn(text):
    return bool(re.search(r"^\s*(remote|client|dev|proto)\b", text, re.M)) and \
        bool(re.search(r"^\s*(remote\s|client\s*$|<ca>|tls-client)", text, re.M))

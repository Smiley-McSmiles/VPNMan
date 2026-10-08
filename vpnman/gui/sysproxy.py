"""Reading the desktop's proxy settings (for "Copy from the desktop settings" of the network proxy), and the small
host/port helpers the proxy boxes share.

Two readers, picked by ``detect()``:

* ``GnomeProxy``  the ``org.gnome.system.proxy`` settings (gsettings-desktop-schemas): GNOME, Cinnamon, Budgie,
  Pantheon, Unity and most desktops that ship those schemas.
* ``KdeProxy``    Plasma's ``kioslaverc`` (read with kreadconfig6/5).

Both return {"mode": "none"|"manual"|"auto", "auto_url": str, "http"|"https"|"ftp"|"socks": (host, port),
"ignore": [hosts]}.
"""

import os
import re
import shutil
import subprocess

KINDS = ("http", "https", "ftp", "socks")
MODES = ("none", "manual", "auto")
DEFAULT_IGNORE = ["localhost", "127.0.0.0/8", "::1"]


def clean_host(text):
    """'http://proxy.example:3128/' -> 'proxy.example' (the scheme, a path and a port typed into the URL box are not part
    of the host setting; the port has its own field)."""
    t = (text or "").strip()
    t = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", t)
    t = t.split("/", 1)[0]
    if t.startswith("["):                                   # [::1]:8080
        return t[1:t.index("]")] if "]" in t else t[1:]
    if t.count(":") == 1:
        t = t.split(":", 1)[0]
    return t


def port_in(text):
    """A port typed into the URL box ('host:3128'), or None."""
    m = re.search(r"(?:^|[^:]):(\d{1,5})(?:/|$)", re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", (text or "").strip()))
    return int(m.group(1)) if m and 0 < int(m.group(1)) < 65536 else None


def split_hosts(text):
    return [h.strip() for h in re.split(r"[,\s]+", text or "") if h.strip()]


class GnomeProxy:
    name = "GNOME"
    SCHEMA = "org.gnome.system.proxy"

    def __init__(self):
        from gi.repository import Gio
        self.s = Gio.Settings.new(self.SCHEMA)
        self.kids = {k: self.s.get_child(k) for k in KINDS}

    @classmethod
    def available(cls):
        try:
            from gi.repository import Gio
        except ImportError:
            return False
        src = Gio.SettingsSchemaSource.get_default()
        return bool(src and src.lookup(cls.SCHEMA, True))

    def read(self):
        out = {"mode": self.s.get_string("mode"), "auto_url": self.s.get_string("autoconfig-url"),
               "ignore": list(self.s.get_strv("ignore-hosts"))}
        for k in KINDS:
            out[k] = (self.kids[k].get_string("host"), self.kids[k].get_int("port"))
        return out


class KdeProxy:
    name = "KDE Plasma"
    KEYS = {"http": "httpProxy", "https": "httpsProxy", "ftp": "ftpProxy", "socks": "socksProxy"}

    def __init__(self, read_tool=None, run=None):
        self.r = read_tool or shutil.which("kreadconfig6") or shutil.which("kreadconfig5")
        self.run = run or (lambda cmd: subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout)

    @staticmethod
    def available():
        return bool((shutil.which("kreadconfig6") or shutil.which("kreadconfig5"))
                    and "KDE" in os.environ.get("XDG_CURRENT_DESKTOP", "").upper())

    def _get(self, key):
        return self.run([self.r, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", key]).strip()

    @staticmethod
    def parse(value):
        """'http://127.0.0.1 8080' (KDE's form) or 'http://127.0.0.1:8080' -> ('127.0.0.1', 8080)."""
        v = (value or "").strip()
        if not v:
            return "", 0
        host, _, port = v.partition(" ")
        p = int(port) if port.strip().isdigit() else (port_in(host) or 0)
        return clean_host(host), p

    def read(self):
        t = self._get("ProxyType")
        mode = {0: "none", 1: "manual", 2: "auto", 3: "auto"}.get(int(t) if t.isdigit() else 0, "none")
        out = {"mode": mode, "auto_url": self._get("Proxy Config Script"),
               "ignore": split_hosts(self._get("NoProxyFor")) or list(DEFAULT_IGNORE)}
        for k in KINDS:
            out[k] = self.parse(self._get(self.KEYS[k]))
        return out


def detect():
    """(reader or None, why not)."""
    if KdeProxy.available():
        return KdeProxy(), ""
    if GnomeProxy.available():
        try:
            return GnomeProxy(), ""
        except Exception as e:  # noqa: BLE001
            return None, "the desktop proxy settings cannot be opened: %s" % e
    return None, ("This desktop keeps no proxy settings VPNMan knows (it needs the org.gnome.system.proxy settings - "
                  "package gsettings-desktop-schemas - or KDE Plasma). Fill in the proxies by hand.")


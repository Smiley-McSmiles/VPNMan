"""Desktop integration checks (launcher, icons, tray) used by `vpnman doctor`."""

import glob
import os
import subprocess
import sys

from . import APP_ID
from . import platform as plat

SYSTEM_SHARE = "/usr/share"
CANDIDATE_SHARES = ["/usr/local/share", "/usr/share"]


def session_data_dirs():
    """What a desktop session searches for launchers and icons (XDG default when unset)."""
    home = os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share")
    raw = os.environ.get("XDG_DATA_DIRS") or "/usr/local/share:/usr/share"
    return [home] + [d for d in raw.split(":") if d]


def installed_shares():
    return [s for s in CANDIDATE_SHARES + [os.path.join(os.path.expanduser("~"), ".local", "share")]
            if os.path.exists(os.path.join(s, "applications", APP_ID + ".desktop"))]


def check():
    """List of (ok, message) about launcher + icon visibility."""
    out = []
    shares = installed_shares()
    if not shares:
        return [(False, "no %s.desktop found in /usr/local/share, /usr/share or ~/.local/share - is VPNMan installed?" % APP_ID)]
    seen = session_data_dirs()
    visible = [s for s in shares if os.path.realpath(s) in {os.path.realpath(d) for d in seen}]
    for s in shares:
        out.append((True, "launcher installed in %s/applications" % s))
    if visible:
        out.append((True, "this session searches %s for launchers and icons" % ", ".join(visible)))
    else:
        out.append((False, "this session's XDG_DATA_DIRS (%s) does not include %s - the menu will not show VPNMan"
                    % (":".join(seen), " or ".join(shares))))
    desktop = os.path.join(shares[0], "applications", APP_ID + ".desktop")
    exe = None
    try:
        with open(desktop) as fh:
            for line in fh:
                if line.startswith("Exec="):
                    exe = line.split("=", 1)[1].split()[0]
    except OSError:
        pass
    if exe:
        ok = os.path.isfile(exe) and os.access(exe, os.X_OK)
        out.append((ok, "launcher runs %s (%s)" % (exe, "exists" if ok else "MISSING or not executable")))
    return out


def tray_check():
    """Probe the session bus the way the app's tray code does."""
    out = []
    desk = os.environ.get("XDG_CURRENT_DESKTOP") or os.environ.get("DESKTOP_SESSION") or "unknown"
    out.append((True, "desktop: %s (session type: %s)" % (desk, os.environ.get("XDG_SESSION_TYPE", "unknown"))))
    code = r'''
import json, sys
try:
    import gi
    from gi.repository import Gio, GLib
except Exception as e:
    print(json.dumps({"error": "PyGObject not available: %s" % e})); sys.exit(0)
res = {}
try:
    c = Gio.bus_get_sync(Gio.BusType.SESSION, None)
    res["names"] = [n for n in c.call_sync("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                    "ListNames", None, None, 0, 3000, None).unpack()[0] if not n.startswith(":")]
except Exception as e:
    res["error"] = "no session bus: %s" % e
for ns, ver in (("Gtk", "3.0"), ("XApp", "1.0"), ("Gtk4", "4.0"), ("Adw", "1")):
    try:
        gi.require_version(ns.replace("Gtk4", "Gtk"), ver)
        res.setdefault("typelibs", []).append(ns + "-" + ver)
    except Exception:
        pass
print(json.dumps(res))
'''
    try:
        import json
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=15)
        data = json.loads(r.stdout.strip().splitlines()[-1])
    except Exception as e:  # noqa: BLE001
        return out + [(False, "could not probe the session bus: %s" % e)]
    if data.get("error"):
        return out + [(False, data["error"])]
    names = data.get("names", [])
    typelibs = data.get("typelibs", [])
    cinnamon = "cinnamon" in desk.lower()
    xapp_monitor = any(n.startswith("org.x.StatusIconMonitor") for n in names)
    sni_watcher = "org.kde.StatusNotifierWatcher" in names or "org.freedesktop.StatusNotifierWatcher" in names
    if cinnamon:
        out.append(("Gtk-3.0" in typelibs and "XApp-1.0" in typelibs,
                    "GTK 3 + XApp typelibs for the Cinnamon tray helper: %s" %
                    ("found" if "XApp-1.0" in typelibs and "Gtk-3.0" in typelibs else
                     "MISSING - install xapp (Void: xbps-install xapp; Debian/Mint: gir1.2-xapp-1.0)")))
        out.append((xapp_monitor, "XApp Status applet on the panel (org.x.StatusIconMonitor): %s" %
                    ("present" if xapp_monitor else "NOT FOUND - add the 'XApp Status Applet' (or 'System Tray') to your panel")))
    out.append((sni_watcher, "StatusNotifier watcher: %s" % ("running" if sni_watcher else
                "not running (Cinnamon: xapp-sn-watcher starts only once the XApp status applet is on the panel)")))
    return out


def link_system_dirs():
    """Make the launcher/icons of a /usr/local install visible in /usr/share (root).  Returns messages."""
    msgs = []
    shares = [s for s in CANDIDATE_SHARES[:1] if os.path.exists(os.path.join(s, "applications", APP_ID + ".desktop"))]
    for share in shares:
        pairs = [(os.path.join(share, "applications", APP_ID + ".desktop"), os.path.join(SYSTEM_SHARE, "applications", APP_ID + ".desktop")),
                 (os.path.join(share, "metainfo", APP_ID + ".metainfo.xml"), os.path.join(SYSTEM_SHARE, "metainfo", APP_ID + ".metainfo.xml")),
                 (os.path.join(share, "pixmaps", APP_ID + ".svg"), os.path.join(SYSTEM_SHARE, "pixmaps", APP_ID + ".svg"))]
        for f in glob.glob(os.path.join(share, "icons", "hicolor", "*", "apps", APP_ID + "*")):
            pairs.append((f, os.path.join(SYSTEM_SHARE, os.path.relpath(f, share))))
        made = 0
        for src, dst in pairs:
            if not os.path.exists(src) or (os.path.exists(dst) and not os.path.islink(dst)):
                continue
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            if os.path.islink(dst):
                os.unlink(dst)
            os.symlink(src, dst)
            made += 1
        msgs.append("linked %d launcher/icon files from %s into %s" % (made, share, SYSTEM_SHARE))
    for theme in ("/usr/share/icons/hicolor", "/usr/local/share/icons/hicolor"):
        if os.path.isdir(theme):
            for tool in ("gtk4-update-icon-cache", "gtk-update-icon-cache"):
                exe = plat.which(tool)
                if exe and plat.run([exe, "-q", "-f", "-t", theme])[0] == 0:
                    msgs.append("rebuilt icon cache in %s" % theme)
                    break
    exe = plat.which("update-desktop-database")
    if exe:
        plat.run([exe, "-q", "/usr/share/applications"])
    return msgs


def bytecode_check():
    """Is the running code the code on disk?  Python trusts __pycache__ by source mtime+size only, so an upgrade
    can silently keep running the previous version (e.g. 1.0.0 -> 1.0.2 are the same length)."""
    import re
    from . import __version__
    pkg = os.path.dirname(os.path.abspath(__file__))
    try:
        with open(os.path.join(pkg, "__init__.py")) as fh:
            disk = re.search(r'__version__\s*=\s*"([^"]+)"', fh.read()).group(1)
    except (OSError, AttributeError):
        return [(True, "running vpnman %s" % __version__)]
    if disk == __version__:
        return [(True, "running vpnman %s (matches the installed files)" % __version__)]
    return [(False, "running code is %s but the installed files are %s - stale compiled cache in %s "
                    "(sudo vpnman doctor --fix removes it)" % (__version__, disk, pkg))]


def purge_bytecode():
    import shutil
    pkg = os.path.dirname(os.path.abspath(__file__))
    n = 0
    for root, dirs, _files in os.walk(pkg):
        if "__pycache__" in dirs:
            shutil.rmtree(os.path.join(root, "__pycache__"), ignore_errors=True)
            n += 1
    return ["removed %d stale __pycache__ director%s under %s" % (n, "y" if n == 1 else "ies", pkg)]

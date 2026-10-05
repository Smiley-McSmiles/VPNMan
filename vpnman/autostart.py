"""XDG autostart entry so the tray application starts at login (works on GNOME, KDE, XFCE, ...)."""

import os
import shutil

from . import APP_ID


def path():
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, "autostart", APP_ID + ".desktop")


def is_enabled():
    return os.path.exists(path())


def enable(exe=None):
    exe = exe or shutil.which("vpnman-gtk") or "vpnman-gtk"
    os.makedirs(os.path.dirname(path()), exist_ok=True)
    with open(path(), "w") as fh:
        fh.write("[Desktop Entry]\nType=Application\nName=VPNMan\n"
                 "Comment=VPN manager (starts minimised to the system tray)\n"
                 "Exec=%s --background\nIcon=%s\nTerminal=false\n"
                 "X-GNOME-Autostart-enabled=true\nX-GNOME-Autostart-Delay=3\n"
                 "X-KDE-autostart-after=panel\n" % (exe, APP_ID))
    return path()


def disable():
    try:
        os.unlink(path())
    except FileNotFoundError:
        pass

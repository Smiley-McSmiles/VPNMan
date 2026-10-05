"""Run under xvfb + dbus-run-session: the Cinnamon tray helper (GTK3 + XApp) against an emulated XApp panel applet."""
import json
import os
import re
import subprocess
import sys
import threading
import time

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
import gi  # noqa: E402
from gi.repository import Gio, GLib  # noqa: E402

bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
# the panel's "XApp Status" applet announces itself with a bus name; XApp.StatusIcon only exports when one exists
Gio.bus_own_name_on_connection(bus, "org.x.StatusIconMonitor.test_0", Gio.BusNameOwnerFlags.NONE, None, None)
errors, events = [], []


def run():
    try:
        env = dict(os.environ, PYTHONPATH=ROOT, XDG_CURRENT_DESKTOP="X-Cinnamon")
        p = subprocess.Popen([sys.executable, "-m", "vpnman.gui.trayhelper", os.path.join(ROOT, "data", "icons")],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1, env=env)

        def reader():
            for line in p.stdout:
                events.append(json.loads(line))
        threading.Thread(target=reader, daemon=True).start()

        def send(o):
            p.stdin.write(json.dumps(o) + "\n")
            p.stdin.flush()
        send({"cmd": "state", "icon": "io.github.smiley_mcsmiles.VPNMan-connected-symbolic", "tooltip": "Connected to Lab"})
        send({"cmd": "menu", "items": [{"id": 1, "label": "Show", "enabled": True}, {"separator": True}]})
        end = time.time() + 8
        while time.time() < end and not any(e.get("event") in ("ready",) for e in events):
            time.sleep(0.1)
        assert any(e.get("event") == "ready" and e.get("kind") == "xapp" for e in events), events
        time.sleep(1)
        names = bus.call_sync("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "ListNames",
                              None, None, 0, 3000, None).unpack()[0]
        icon = [n for n in names if n.startswith("org.x.StatusIcon.")]
        assert icon, "the helper did not export an XApp status icon: %r" % names
        props = bus.call_sync(icon[0], "/org/x/StatusIcon/Icon", "org.freedesktop.DBus.Properties", "GetAll",
                              GLib.Variant("(s)", ("org.x.StatusIcon",)), None, 0, 3000, None).unpack()[0]
        assert props["IconName"].endswith("connected-symbolic"), props
        assert props["Visible"] is True, props
        assert any(e.get("event") == "availability" and e.get("available") for e in events) or \
            any(e.get("event") == "ready" and e.get("available") for e in events), events
        # a left click on the applet
        for meth in ("ButtonPress", "ButtonRelease"):
            bus.call_sync(icon[0], "/org/x/StatusIcon/Icon", "org.x.StatusIcon", meth,
                          GLib.Variant("(iiuui)", (0, 0, 1, 0, 0)), None, 0, 3000, None)
        end = time.time() + 5
        while time.time() < end and not any(e.get("event") == "activate" for e in events):
            time.sleep(0.1)
        assert any(e.get("event") == "activate" for e in events), "left click did not activate: %r" % events
        send({"cmd": "quit"})
        p.wait(timeout=5)
        print("HELPER OK")
    except Exception as e:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        errors.append(repr(e))
    GLib.idle_add(loop.quit)


loop = GLib.MainLoop()
threading.Thread(target=run, daemon=True).start()
GLib.timeout_add_seconds(40, loop.quit)
loop.run()
sys.exit(1 if errors else 0)

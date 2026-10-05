"""Run inside `dbus-run-session`: exercises the tray against a fake StatusNotifierWatcher/host."""
import os
import sys
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import gi  # noqa: E402
gi.require_version("Gtk", "4.0")
from gi.repository import Gio, GLib  # noqa: E402
from vpnman.gui.tray import Tray  # noqa: E402

WATCHER_XML = """<node><interface name="org.kde.StatusNotifierWatcher">
<method name="RegisterStatusNotifierItem"><arg type="s" direction="in"/></method>
<property name="IsStatusNotifierHostRegistered" type="b" access="read"/>
<property name="RegisteredStatusNotifierItems" type="as" access="read"/></interface></node>"""

registered, clicks, activated, avail = [], [], [], []
loop = GLib.MainLoop()
conn = Gio.bus_get_sync(Gio.BusType.SESSION, None)


def wcall(c, s, p, i, m, params, inv):
    registered.append(params.unpack()[0])
    inv.return_value(None)


def wget(c, s, p, i, prop):
    return GLib.Variant("b", True) if prop == "IsStatusNotifierHostRegistered" else GLib.Variant("as", registered)


def start_watcher():
    conn.register_object("/StatusNotifierWatcher", Gio.DBusNodeInfo.new_for_xml(WATCHER_XML).interfaces[0],
                         wcall, wget, None)
    Gio.bus_own_name_on_connection(conn, "org.kde.StatusNotifierWatcher", Gio.BusNameOwnerFlags.NONE, None, None)


state = {"connected": False}
menu = lambda: [  # noqa: E731
    {"label": "Show", "callback": lambda: clicks.append("show")},
    {"separator": True},
    {"label": "Connect", "enabled": not state["connected"], "callback": lambda: clicks.append("connect")},
]

# the tray starts BEFORE the watcher exists: it must register when the watcher appears (GNOME extension case)
tray = Tray("test.app", "Test", lambda: activated.append(1), menu, on_availability=avail.append, icon_theme_path="/x")
tray.start(conn)
GLib.timeout_add(300, lambda: (start_watcher(), False)[1])
errors = []


def client():
    try:
        addr = Gio.dbus_address_get_for_bus_sync(Gio.BusType.SESSION, None)
        c = Gio.DBusConnection.new_for_address_sync(addr, Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT |
                                                    Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION, None, None)
        end = 0
        import time
        while not avail and end < 50:
            time.sleep(0.1)
            end += 1
        assert avail == [True], "tray never became available: %r" % avail
        assert registered == [tray._name], registered

        def call(path, iface, method, params, name=None):
            return c.call_sync(name or tray._name, path, iface, method, params, None, Gio.DBusCallFlags.NONE, 5000, None)

        props = call("/StatusNotifierItem", "org.freedesktop.DBus.Properties", "GetAll",
                     GLib.Variant("(s)", ("org.kde.StatusNotifierItem",))).unpack()[0]
        assert props["Id"] == "test.app" and props["Menu"] == "/MenuBar" and props["IconThemePath"] == "/x", props
        rev, layout = call("/MenuBar", "com.canonical.dbusmenu", "GetLayout",
                           GLib.Variant("(iias)", (0, -1, []))).unpack()
        kids = layout[2]
        assert [k[1].get("label") for k in kids] == ["Show", None, "Connect"], kids
        assert kids[1][1]["type"] == "separator"
        call("/MenuBar", "com.canonical.dbusmenu", "Event", GLib.Variant("(isvu)", (3, "clicked", GLib.Variant("s", ""), 0)))
        call("/StatusNotifierItem", "org.kde.StatusNotifierItem", "Activate", GLib.Variant("(ii)", (0, 0)))
        state["connected"] = True
        kids = call("/MenuBar", "com.canonical.dbusmenu", "GetLayout", GLib.Variant("(iias)", (0, -1, []))).unpack()[1][2]
        assert kids[2][1]["enabled"] is False
        time.sleep(0.3)
        assert clicks == ["connect"], clicks
        assert activated == [1], activated
        # watcher disappears -> unavailable again
        tray.set_state("test-icon", "tip", attention=True)
        props = call("/StatusNotifierItem", "org.freedesktop.DBus.Properties", "GetAll",
                     GLib.Variant("(s)", ("org.kde.StatusNotifierItem",))).unpack()[0]
        assert props["Status"] == "NeedsAttention" and props["IconName"] == "test-icon", props
        print("TRAY OK")
    except Exception as e:  # noqa: BLE001
        errors.append(repr(e))
        import traceback
        traceback.print_exc()
    GLib.idle_add(loop.quit)


threading.Thread(target=client, daemon=True).start()
GLib.timeout_add_seconds(20, loop.quit)
loop.run()
sys.exit(1 if errors else 0)

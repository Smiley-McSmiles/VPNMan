"""System tray via the StatusNotifierItem (SNI) D-Bus protocol, with a dbusmenu context menu.

GTK 4 has no tray API, so this speaks the freedesktop/KDE protocol directly through Gio.
Hosts that implement it: KDE Plasma, XFCE (status-notifier plugin), Cinnamon, MATE, LXQt,
Budgie, Deepin, Pantheon, and GNOME with the "AppIndicator and KStatusNotifierItem Support"
extension.  Where no host exists `available` stays False and the app falls back to a normal
window (closing it never disconnects the VPN - that lives in the daemon).
"""

import os

from gi.repository import Gio, GLib

WATCHERS = ("org.kde.StatusNotifierWatcher", "org.freedesktop.StatusNotifierWatcher")
WATCHER_PATH = "/StatusNotifierWatcher"
ITEM_PATH = "/StatusNotifierItem"
MENU_PATH = "/MenuBar"

SNI_XML = """
<node>
  <interface name="org.kde.StatusNotifierItem">
    <property name="Category" type="s" access="read"/>
    <property name="Id" type="s" access="read"/>
    <property name="Title" type="s" access="read"/>
    <property name="Status" type="s" access="read"/>
    <property name="WindowId" type="u" access="read"/>
    <property name="IconThemePath" type="s" access="read"/>
    <property name="IconName" type="s" access="read"/>
    <property name="IconPixmap" type="a(iiay)" access="read"/>
    <property name="OverlayIconName" type="s" access="read"/>
    <property name="OverlayIconPixmap" type="a(iiay)" access="read"/>
    <property name="AttentionIconName" type="s" access="read"/>
    <property name="AttentionIconPixmap" type="a(iiay)" access="read"/>
    <property name="AttentionMovieName" type="s" access="read"/>
    <property name="ToolTip" type="(sa(iiay)ss)" access="read"/>
    <property name="ItemIsMenu" type="b" access="read"/>
    <property name="Menu" type="o" access="read"/>
    <method name="ContextMenu"><arg type="i" name="x" direction="in"/><arg type="i" name="y" direction="in"/></method>
    <method name="Activate"><arg type="i" name="x" direction="in"/><arg type="i" name="y" direction="in"/></method>
    <method name="SecondaryActivate"><arg type="i" name="x" direction="in"/><arg type="i" name="y" direction="in"/></method>
    <method name="Scroll"><arg type="i" name="delta" direction="in"/><arg type="s" name="orientation" direction="in"/></method>
    <signal name="NewTitle"/>
    <signal name="NewIcon"/>
    <signal name="NewAttentionIcon"/>
    <signal name="NewOverlayIcon"/>
    <signal name="NewToolTip"/>
    <signal name="NewStatus"><arg type="s" name="status"/></signal>
  </interface>
</node>
"""

MENU_XML = """
<node>
  <interface name="com.canonical.dbusmenu">
    <property name="Version" type="u" access="read"/>
    <property name="TextDirection" type="s" access="read"/>
    <property name="Status" type="s" access="read"/>
    <property name="IconThemePath" type="as" access="read"/>
    <method name="GetLayout">
      <arg type="i" name="parentId" direction="in"/>
      <arg type="i" name="recursionDepth" direction="in"/>
      <arg type="as" name="propertyNames" direction="in"/>
      <arg type="u" name="revision" direction="out"/>
      <arg type="(ia{sv}av)" name="layout" direction="out"/>
    </method>
    <method name="GetGroupProperties">
      <arg type="ai" name="ids" direction="in"/>
      <arg type="as" name="propertyNames" direction="in"/>
      <arg type="a(ia{sv})" name="properties" direction="out"/>
    </method>
    <method name="GetProperty">
      <arg type="i" name="id" direction="in"/>
      <arg type="s" name="name" direction="in"/>
      <arg type="v" name="value" direction="out"/>
    </method>
    <method name="Event">
      <arg type="i" name="id" direction="in"/>
      <arg type="s" name="eventId" direction="in"/>
      <arg type="v" name="data" direction="in"/>
      <arg type="u" name="timestamp" direction="in"/>
    </method>
    <method name="EventGroup">
      <arg type="a(isvu)" name="events" direction="in"/>
      <arg type="ai" name="idErrors" direction="out"/>
    </method>
    <method name="AboutToShow">
      <arg type="i" name="id" direction="in"/>
      <arg type="b" name="needUpdate" direction="out"/>
    </method>
    <method name="AboutToShowGroup">
      <arg type="ai" name="ids" direction="in"/>
      <arg type="ai" name="updatesNeeded" direction="out"/>
      <arg type="ai" name="idErrors" direction="out"/>
    </method>
    <signal name="ItemsPropertiesUpdated">
      <arg type="a(ia{sv})" name="updatedProps"/>
      <arg type="a(ias)" name="removedProps"/>
    </signal>
    <signal name="LayoutUpdated"><arg type="u" name="revision"/><arg type="i" name="parent"/></signal>
    <signal name="ItemActivationRequested"><arg type="i" name="id"/><arg type="u" name="timestamp"/></signal>
  </interface>
</node>
"""


class Tray:
    """menu_provider() -> list of dicts: {"label", "enabled", "callback"} or {"separator": True}."""

    def __init__(self, app_id, title, on_activate, menu_provider, on_availability=None, icon_theme_path=""):
        self.app_id, self.title = app_id, title
        self.on_activate, self.menu_provider = on_activate, menu_provider
        self.on_availability = on_availability
        self.icon_theme_path = icon_theme_path
        self.available = False
        self.icon, self.status, self.tooltip = app_id, "Active", title
        self.attention_icon = ""
        self._rev = 1
        self._items = []
        self._conn = None
        self._watcher = None
        self._registered = False
        self._name_owned = False
        self._name = "org.kde.StatusNotifierItem-%d-1" % os.getpid()
        self._sni = Gio.DBusNodeInfo.new_for_xml(SNI_XML).interfaces[0]
        self._menu = Gio.DBusNodeInfo.new_for_xml(MENU_XML).interfaces[0]

    # ------------------------------------------------------------- lifecycle
    def start(self, bus=None):
        """Connect to the session bus.  Safe on systems without one (stays unavailable)."""
        try:
            self._conn = bus or Gio.bus_get_sync(Gio.BusType.SESSION, None)
        except GLib.Error:
            return False
        self._conn.register_object(ITEM_PATH, self._sni, self._sni_call, self._sni_get, None)
        self._conn.register_object(MENU_PATH, self._menu, self._menu_call, self._menu_get, None)
        # register with a watcher only once the name is really ours: watchers read our properties immediately
        Gio.bus_own_name_on_connection(self._conn, self._name, Gio.BusNameOwnerFlags.NONE,
                                       self._name_acquired, None)
        for w in WATCHERS:
            Gio.bus_watch_name_on_connection(self._conn, w, Gio.BusNameWatcherFlags.NONE,
                                             self._watcher_appeared, self._watcher_vanished)
        GLib.timeout_add_seconds(2, self._wake_xapp_watcher)
        return True

    def _wake_xapp_watcher(self):
        """Cinnamon's bridge (xapp-sn-watcher) is D-Bus activatable; start it if autostart did not."""
        if not self._watcher and "cinnamon" in os.environ.get("XDG_CURRENT_DESKTOP", "").lower():
            self._conn.call("org.x.StatusNotifierWatcher", "/org/x/StatusNotifierWatcher",
                            "org.freedesktop.Application", "Activate", GLib.Variant("(a{sv})", ({},)), None,
                            Gio.DBusCallFlags.NONE, 5000, None, lambda *_: None)
        return False

    def stop(self):
        self._set_available(False)

    def _name_acquired(self, conn, name):
        self._name_owned = True
        self._register()

    def _watcher_appeared(self, conn, name, owner):
        self._watcher = name
        # hosts can appear after the watcher
        self._conn.signal_subscribe(name, name, "StatusNotifierHostRegistered", WATCHER_PATH, None,
                                    Gio.DBusSignalFlags.NONE, lambda *_: self._check_host())
        self._register()

    def _register(self):
        if not (self._watcher and self._name_owned):
            return
        self._conn.call(self._watcher, WATCHER_PATH, self._watcher, "RegisterStatusNotifierItem",
                        GLib.Variant("(s)", (self._name,)), None, Gio.DBusCallFlags.NONE, 5000, None,
                        self._registered_cb)

    def _watcher_vanished(self, conn, name):
        if self._watcher == name:
            self._watcher = None
            self._registered = False
            self._set_available(False)

    def _registered_cb(self, conn, res):
        try:
            conn.call_finish(res)
            self._registered = True
        except GLib.Error:
            self._registered = False
            return
        self._check_host()

    def _check_host(self):
        if not self._watcher:
            return
        self._conn.call(self._watcher, WATCHER_PATH, "org.freedesktop.DBus.Properties", "Get",
                        GLib.Variant("(ss)", (self._watcher, "IsStatusNotifierHostRegistered")), None,
                        Gio.DBusCallFlags.NONE, 5000, None, self._host_cb)

    def _host_cb(self, conn, res):
        try:
            host = conn.call_finish(res).unpack()[0]
        except GLib.Error:
            host = False
        self._set_available(bool(host) and self._registered)

    def _set_available(self, value):
        if value != self.available:
            self.available = value
            if self.on_availability:
                self.on_availability(value)

    # --------------------------------------------------------------- updates
    def set_state(self, icon, tooltip, attention=False, title=None):
        self.icon = icon
        self.tooltip = tooltip
        self.status = "NeedsAttention" if attention else "Active"
        self.attention_icon = icon if attention else ""
        if title:
            self.title = title
        if self._conn:
            for sig, args in (("NewIcon", None), ("NewAttentionIcon", None), ("NewToolTip", None),
                              ("NewStatus", GLib.Variant("(s)", (self.status,)))):
                self._emit(ITEM_PATH, "org.kde.StatusNotifierItem", sig, args)

    def update_menu(self):
        self._rev += 1
        if self._conn:
            self._emit(MENU_PATH, "com.canonical.dbusmenu", "LayoutUpdated",
                       GLib.Variant("(ui)", (self._rev, 0)))

    def _emit(self, path, iface, signal, params):
        try:
            self._conn.emit_signal(None, path, iface, signal, params)
        except GLib.Error:
            pass

    # ------------------------------------------------------------------- SNI
    def _sni_get(self, conn, sender, path, iface, prop):
        pix = GLib.Variant("a(iiay)", [])
        table = {
            "Category": GLib.Variant("s", "ApplicationStatus"),
            "Id": GLib.Variant("s", self.app_id),
            "Title": GLib.Variant("s", self.title),
            "Status": GLib.Variant("s", self.status),
            "WindowId": GLib.Variant("u", 0),
            "IconThemePath": GLib.Variant("s", self.icon_theme_path),
            "IconName": GLib.Variant("s", self.icon),
            "IconPixmap": pix,
            "OverlayIconName": GLib.Variant("s", ""),
            "OverlayIconPixmap": pix,
            "AttentionIconName": GLib.Variant("s", self.attention_icon or self.icon),
            "AttentionIconPixmap": pix,
            "AttentionMovieName": GLib.Variant("s", ""),
            "ToolTip": GLib.Variant("(sa(iiay)ss)", (self.icon, [], self.title, self.tooltip)),
            "ItemIsMenu": GLib.Variant("b", False),
            "Menu": GLib.Variant("o", MENU_PATH),
        }
        return table.get(prop)

    def _sni_call(self, conn, sender, path, iface, method, params, invocation):
        if method in ("Activate", "SecondaryActivate"):
            GLib.idle_add(self.on_activate)
        invocation.return_value(None)

    # -------------------------------------------------------------- dbusmenu
    def _build(self):
        self._items = list(self.menu_provider())
        return self._items

    @staticmethod
    def _props(item):
        if item.get("separator"):
            return {"type": GLib.Variant("s", "separator")}
        return {"label": GLib.Variant("s", item["label"]),
                "enabled": GLib.Variant("b", bool(item.get("enabled", True))),
                "visible": GLib.Variant("b", True)}

    def _layout(self):
        children = [GLib.Variant("(ia{sv}av)", (i + 1, self._props(it), []))
                    for i, it in enumerate(self._build())]
        return (0, {"children-display": GLib.Variant("s", "submenu")}, children)

    def _menu_get(self, conn, sender, path, iface, prop):
        return {"Version": GLib.Variant("u", 3), "TextDirection": GLib.Variant("s", "ltr"),
                "Status": GLib.Variant("s", "normal"), "IconThemePath": GLib.Variant("as", [])}.get(prop)

    def _menu_call(self, conn, sender, path, iface, method, params, invocation):
        if method == "GetLayout":
            invocation.return_value(GLib.Variant("(u(ia{sv}av))", (self._rev, self._layout())))
        elif method == "GetGroupProperties":
            ids = params.unpack()[0]
            items = self._items or self._build()
            out = [(i, self._props(items[i - 1])) for i in ids if 1 <= i <= len(items)]
            if not ids:
                ids = list(range(0, len(items) + 1))
                out = [(i, self._props(items[i - 1])) for i in ids if i >= 1]
            if 0 in ids or not params.unpack()[0]:
                out.insert(0, (0, {"children-display": GLib.Variant("s", "submenu")}))
            invocation.return_value(GLib.Variant("(a(ia{sv}))", (out,)))
        elif method == "GetProperty":
            i, name = params.unpack()
            items = self._items or self._build()
            if i == 0:
                val = {"children-display": GLib.Variant("s", "submenu")}.get(name)
            else:
                val = self._props(items[i - 1]).get(name) if 1 <= i <= len(items) else None
            invocation.return_value(GLib.Variant("(v)", (val or GLib.Variant("s", ""),)))
        elif method == "Event":
            i, event, _data, _ts = params.unpack()
            self._fire(i, event)
            invocation.return_value(None)
        elif method == "EventGroup":
            for i, event, _d, _t in params.unpack()[0]:
                self._fire(i, event)
            invocation.return_value(GLib.Variant("(ai)", ([],)))
        elif method == "AboutToShow":
            invocation.return_value(GLib.Variant("(b)", (True,)))
        elif method == "AboutToShowGroup":
            ids = params.unpack()[0]
            invocation.return_value(GLib.Variant("(aiai)", (list(ids), [])))
        else:
            invocation.return_error_literal(Gio.dbus_error_quark(), 19, "unknown method")

    def _fire(self, item_id, event):
        if event != "clicked":
            return
        items = self._items
        if 1 <= item_id <= len(items):
            cb = items[item_id - 1].get("callback")
            if cb and items[item_id - 1].get("enabled", True):
                GLib.idle_add(lambda: (cb(), False)[1])


class HelperTray:
    """Same interface as Tray, but the icon lives in a GTK 3 + XApp helper process (see trayhelper.py).

    Used on Cinnamon: XApp.StatusIcon is its native tray API and does not depend on the StatusNotifier bridge.
    """

    def __init__(self, app_id, title, on_activate, menu_provider, on_availability=None, icon_theme_path="",
                 on_failure=None):
        self.app_id, self.title = app_id, title
        self.on_activate, self.menu_provider = on_activate, menu_provider
        self.on_availability, self.on_failure = on_availability, on_failure
        self.icon_theme_path = icon_theme_path
        self.available = False
        self.kind = None
        self._proc = None
        self._buf = b""
        self._items = {}
        self._watch = None
        self._ready = False

    def start(self):
        import subprocess
        import sys
        pkg_parent = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        env = dict(os.environ)
        env["PYTHONPATH"] = pkg_parent + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
        try:
            self._proc = subprocess.Popen([sys.executable, "-m", "vpnman.gui.trayhelper", self.icon_theme_path],
                                          stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=env)
        except OSError:
            return False
        os.set_blocking(self._proc.stdout.fileno(), False)
        self._watch = GLib.io_add_watch(self._proc.stdout.fileno(), GLib.PRIORITY_DEFAULT,
                                        GLib.IOCondition.IN | GLib.IOCondition.HUP | GLib.IOCondition.ERR, self._on_data)
        GLib.timeout_add_seconds(6, self._startup_check)
        return True

    def _startup_check(self):
        if not self._ready:                       # the helper never said hello (GTK 3 missing, crashed, ...)
            self._failed()
        return False

    def _failed(self):
        self.stop()
        if self.on_failure:
            self.on_failure()

    def _send(self, obj):
        import json
        if self._proc and self._proc.poll() is None:
            try:
                self._proc.stdin.write((json.dumps(obj) + "\n").encode())
                self._proc.stdin.flush()
            except OSError:
                pass

    def _on_data(self, fd, cond):
        import json
        try:
            chunk = os.read(fd, 65536)
        except BlockingIOError:
            return True
        except OSError:
            chunk = b""
        if not chunk:
            if self._proc and not self._ready:
                self._failed()
            else:
                self._set_available(False)
            return False
        self._buf += chunk
        while b"\n" in self._buf:
            line, self._buf = self._buf.split(b"\n", 1)
            try:
                msg = json.loads(line.decode())
            except ValueError:
                continue
            ev = msg.get("event")
            if ev == "ready":
                self._ready, self.kind = True, msg.get("kind")
                self.update_menu()
                self._set_available(bool(msg.get("available")))
            elif ev == "availability":
                self._set_available(bool(msg.get("available")))
            elif ev == "activate":
                GLib.idle_add(lambda: (self.on_activate(), False)[1])
            elif ev == "menu":
                cb = self._items.get(msg.get("id"))
                if cb:
                    GLib.idle_add(lambda cb=cb: (cb(), False)[1])
            elif ev == "error":
                self._failed()
                return False
        return True

    def _set_available(self, value):
        if value != self.available:
            self.available = value
            if self.on_availability:
                self.on_availability(value)

    # same interface as Tray ------------------------------------------------
    def set_state(self, icon, tooltip, attention=False, title=None):
        self._last_state = (icon, tooltip, attention)
        self._send({"cmd": "state", "icon": icon, "tooltip": tooltip, "attention": attention})

    def update_menu(self):
        items, self._items = [], {}
        for i, it in enumerate(self.menu_provider(), 1):
            if it.get("separator"):
                items.append({"separator": True})
            else:
                items.append({"id": i, "label": it["label"], "enabled": bool(it.get("enabled", True))})
                if it.get("callback"):
                    self._items[i] = it["callback"]
        self._send({"cmd": "menu", "items": items})

    def stop(self):
        if self._watch:
            GLib.source_remove(self._watch)
            self._watch = None
        if self._proc:
            self._send({"cmd": "quit"})
            try:
                self._proc.stdin.close()
            except OSError:
                pass
            try:
                self._proc.wait(timeout=2)
            except Exception:  # noqa: BLE001
                self._proc.kill()
            self._proc = None
        self._set_available(False)


def wants_helper():
    """Cinnamon: use the XApp helper.  Other desktops speak StatusNotifierItem natively."""
    d = (os.environ.get("XDG_CURRENT_DESKTOP", "") + ":" + os.environ.get("DESKTOP_SESSION", "")).lower()
    return "cinnamon" in d and os.environ.get("VPNMAN_TRAY") != "sni"

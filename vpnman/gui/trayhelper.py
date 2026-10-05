"""Tray helper process (GTK 3 + XApp) - used on Cinnamon.

The main app is GTK 4 and GTK 3 cannot live in the same process, so the XApp status icon runs in this tiny
companion process.  XApp.StatusIcon is Cinnamon's native tray API: it talks straight to the panel's
"XApp Status" applet (no StatusNotifier bridge needed) and falls back to an XEmbed icon for the classic
System Tray applet.  It also works unchanged on MATE and XFCE.

Protocol (one JSON object per line):
  parent -> helper   {"cmd": "state", "icon": NAME_OR_PATH, "tooltip": TEXT, "attention": BOOL}
                     {"cmd": "menu", "items": [{"id": N, "label": TEXT, "enabled": BOOL} | {"separator": true}]}
                     {"cmd": "quit"}
  helper -> parent   {"event": "ready", "kind": "xapp"|"gtk-status-icon", "available": BOOL}
                     {"event": "availability", "available": BOOL}
                     {"event": "activate"}   {"event": "menu", "id": N}
The helper exits when its stdin closes (parent died).
"""

import json
import os
import sys

try:
    import gi
    gi.require_version("Gtk", "3.0")
    from gi.repository import GLib, Gtk
    try:
        gi.require_version("XApp", "1.0")
        from gi.repository import XApp
    except (ValueError, ImportError):
        XApp = None
except (ImportError, ValueError) as exc:
    print(json.dumps({"event": "error", "message": "GTK 3 is not available: %s" % exc}), flush=True)
    raise SystemExit(2)


def emit(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


class Helper:
    def __init__(self, theme_dir=""):
        if theme_dir and os.path.isdir(theme_dir):
            Gtk.IconTheme.get_default().append_search_path(theme_dir)
            Gtk.IconTheme.get_default().prepend_search_path(theme_dir)
        self.available = False
        self.menu = None
        self.items = []
        self._buf = b""
        if XApp is not None:
            self.kind = "xapp"
            self.icon = XApp.StatusIcon()
            self.icon.set_name("vpnman")
            self.icon.connect("activate", self._on_activate)
            # the panel applet reports clicks as button events; depending on the XApp version `activate` is not
            # always emitted for them, so also treat a left-button release as an activation (de-duplicated)
            self.icon.connect("button-release-event", self._on_release)
            self.icon.connect("state-changed", self._on_state)
        else:
            self.kind = "gtk-status-icon"
            self.icon = Gtk.StatusIcon()
            self.icon.connect("activate", lambda *_: self._activate_once())
            self.icon.connect("popup-menu", self._popup)
        self._set_icon("network-vpn-symbolic")
        self._set_visible(True)
        GLib.io_add_watch(sys.stdin.fileno(), GLib.PRIORITY_DEFAULT, GLib.IOCondition.IN | GLib.IOCondition.HUP,
                          self._stdin)
        GLib.timeout_add(1500, self._poll)
        self._poll()
        emit({"event": "ready", "kind": self.kind, "available": self.available})

    # ---- availability: is anything on the panel actually going to show the icon?
    def _check(self):
        if self.kind == "xapp":
            try:
                return bool(XApp.StatusIcon.any_monitors()) or self.icon.get_state() != XApp.StatusIconState.NO_SUPPORT
            except Exception:  # noqa: BLE001
                return True
        try:
            return bool(self.icon.is_embedded())
        except Exception:  # noqa: BLE001
            return False

    def _poll(self):
        now = self._check()
        if now != self.available:
            self.available = now
            emit({"event": "availability", "available": now})
        return True

    def _on_state(self, _icon, _state):
        self._poll()

    def _activate_once(self):
        now = GLib.get_monotonic_time()
        if now - getattr(self, "_last_activate", -10**9) > 400000:      # 400 ms de-duplication
            self._last_activate = now
            emit({"event": "activate"})

    def _on_activate(self, _icon, button, _time):
        if button in (1, 0):
            self._activate_once()

    def _on_release(self, _icon, _x, _y, button, _time, _pos):
        if button == 1:
            self._activate_once()

    # ---- commands
    def _set_icon(self, name):
        (self.icon.set_icon_name if self.kind == "xapp" else self.icon.set_from_icon_name)(name)

    def _set_visible(self, v):
        self.icon.set_visible(v) if self.kind == "xapp" else self.icon.set_visible(v)

    def _set_tooltip(self, text):
        (self.icon.set_tooltip_text)(text)

    def _build_menu(self, items):
        menu = Gtk.Menu()
        for it in items:
            if it.get("separator"):
                menu.append(Gtk.SeparatorMenuItem())
                continue
            mi = Gtk.MenuItem.new_with_label(it["label"])
            mi.set_sensitive(bool(it.get("enabled", True)))
            mi.connect("activate", lambda _w, i=it["id"]: emit({"event": "menu", "id": i}))
            menu.append(mi)
        menu.show_all()
        return menu

    def _popup(self, icon, button, time):
        if self.menu:
            self.menu.popup(None, None, Gtk.StatusIcon.position_menu, icon, button, time)

    def handle(self, msg):
        cmd = msg.get("cmd")
        if cmd == "state":
            self._set_icon(msg.get("icon") or "network-vpn-symbolic")
            self._set_tooltip(msg.get("tooltip") or "")
        elif cmd == "menu":
            self.menu = self._build_menu(msg.get("items", []))
            if self.kind == "xapp":
                self.icon.set_secondary_menu(self.menu)
        elif cmd == "quit":
            Gtk.main_quit()

    def _stdin(self, fd, cond):
        if cond & GLib.IOCondition.HUP and not cond & GLib.IOCondition.IN:
            Gtk.main_quit()
            return False
        chunk = os.read(fd, 65536)
        if not chunk:
            Gtk.main_quit()
            return False
        self._buf += chunk
        while b"\n" in self._buf:
            line, self._buf = self._buf.split(b"\n", 1)
            if line.strip():
                try:
                    self.handle(json.loads(line.decode()))
                except ValueError:
                    pass
        return True


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    GLib.set_prgname("io.github.smiley_mcsmiles.VPNMan")
    Helper(argv[0] if argv else "")
    Gtk.main()
    return 0


if __name__ == "__main__":
    sys.exit(main())

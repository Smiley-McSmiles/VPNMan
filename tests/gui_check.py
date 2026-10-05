"""Run under xvfb: the server dropdown must live in a ListBox (so clicks work) and follow the active connection."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import gi
gi.require_version("Gtk", "4.0")
from gi.repository import GLib, Gtk
from vpnman.gui import app as A

def popover_visible(w):
    def walk(x):
        c = x.get_first_child()
        while c:
            if isinstance(c, Gtk.Popover) and c.get_visible():
                return True
            if walk(c):
                return True
            c = c.get_next_sibling()
        return False
    return walk(w)

class App(A.Application):
    def do_activate(self):
        super().do_activate()
        w = self.win
        def go():
            w.profiles = [{"id": "a" * 12, "name": "alpha", "favorite": False, "blacklisted": False, "protocol": "openvpn", "server": "", "port": 0},
                          {"id": "b" * 12, "name": "beta", "favorite": False, "blacklisted": False, "protocol": "openvpn", "server": "", "port": 0}]
            w._on_profiles(w.profiles)
            row = w.server_row
            assert isinstance(row.get_parent(), Gtk.ListBox), "ComboRow must be inside a GtkListBox or clicks do nothing"
            assert not popover_visible(row)
            row.get_parent().emit("row-activated", row)
            GLib.timeout_add(400, lambda: finish(row))
            return False
        def finish(row):
            assert popover_visible(row), "dropdown did not open"
            st = {"state": "connected", "profile": "beta", "profile_id": "b" * 12, "protocol": "openvpn", "iface": "tun0",
                  "public_ip": None, "uptime": 1, "rx": 0, "tx": 0, "rx_rate": 0, "tx_rate": 0, "message": "",
                  "netlock": {"engaged": False, "backend": None}}
            w._on_status(st)
            assert w.server_row.get_selected() == 1, "dropdown must show the connected server"
            self.on_about()
            GLib.timeout_add(1500, about_check)
            return False
        def about_check():
            found = []
            for top in [w] + list(Gtk.Window.list_toplevels()):
                found += [x for x in self._iter_descendants(top) if getattr(x, "_vpnman_donate", False)]
            assert found, "About dialog has no Donate row"
            # an old process that survives an upgrade (it lives on in the tray) must replace itself with the new code
            calls = []
            real_execv, real_version = A.os.execv, A.__version__
            A.os.execv = lambda exe, argv: calls.append(argv)
            A.__version__ = "0.0.1"
            try:
                self._restart_if_stale()
            finally:
                A.os.execv, A.__version__ = real_execv, real_version
            assert calls and calls[0][-3:] == ["-m", "vpnman", "gui"] and calls[0][1] == "-X", "stale GUI did not restart itself: %r" % calls
            calls.clear()
            A.os.execv = lambda exe, argv: calls.append(argv)
            try:
                self._restart_if_stale()                    # same version on disk: must NOT restart
            finally:
                A.os.execv = real_execv
            assert not calls, "restarted although the version matches"
            print("GUI OK")
            self.quit()
            return False
        GLib.timeout_add(500, go)

App().run([])

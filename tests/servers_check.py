"""Run under xvfb: multi-select + bulk remove on the Servers tab, and switching servers without double requests."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, GLib, Gtk
from vpnman.gui import app as A

CALLS, DIALOGS = [], []


def prof(i):
    return {"id": "%012d" % i, "name": "srv%d" % i, "favorite": False, "blacklisted": False, "protocol": "openvpn",
            "server": "h%d" % i, "port": 1194}


class App(A.Application):
    def do_activate(self):
        super().do_activate()
        w = self.win
        A.rpc = lambda method, ok=None, fail=None, **kw: CALLS.append((method, kw)) or (
            ok and method == "profiles.remove_many" and ok({"removed": ["x"] * len(kw["ids"]), "failed": []}))
        profiles = [prof(i) for i in range(1, 6)]
        w.profiles = profiles
        w._on_profiles(profiles)
        rows = [w._rows[p["id"]] for p in profiles]
        assert w.listbox.get_selection_mode() == Gtk.SelectionMode.MULTIPLE
        assert not w.sel_bar.get_reveal_child()
        # select a range and one more individually (what shift/ctrl click end up doing)
        for r in rows[1:4]:
            w.listbox.select_row(r)
        w.listbox.select_row(rows[0])
        assert len(w.selected_profiles()) == 4 and w.sel_bar.get_reveal_child() and w.sel_label.get_label() == "4 selected"
        w.listbox.unselect_row(rows[2])
        assert len(w.selected_profiles()) == 3
        # selection survives a list refresh
        w._on_profiles(profiles)
        assert len(w.selected_profiles()) == 3, "selection lost on refresh"
        rows = [w._rows[p["id"]] for p in profiles]        # the list was rebuilt
        w.listbox.select_all()
        assert len(w.selected_profiles()) == 5
        w.listbox.unselect_all()
        assert not w.sel_bar.get_reveal_child()
        # bulk remove goes through one confirmation and one request
        real = Gtk.Window.present
        Gtk.Window.present = lambda d: DIALOGS.append(d)
        for r in rows[:3]:
            w.listbox.select_row(r)
        w._remove_selected()
        d = DIALOGS[-1]
        assert d.get_heading() == "Remove 3 profiles?", d.get_heading()
        d.emit("response", "remove")
        rm = [c for c in CALLS if c[0] == "profiles.remove_many"]
        assert len(rm) == 1 and rm[0][1]["ids"] == [p["id"] for p in profiles[:3]], rm
        # the row menu on a selected row removes the whole selection, on an unselected row only that row
        w._remove_for_row(rows[0])
        assert DIALOGS[-1].get_heading() == "Remove 3 profiles?"
        w.listbox.unselect_all()
        w._remove_for_row(rows[4])
        assert DIALOGS[-1].get_heading() == "Remove srv5?"
        Gtk.Window.present = real
        # switching servers: a second click while the first request is in flight is ignored
        CALLS.clear()
        w.connect_to(profiles[1]["id"])
        w.connect_to(profiles[1]["id"])
        assert [c[0] for c in CALLS] == ["connect"], CALLS
        # ... and the polling refresh must not snap the selection back to the old server meanwhile
        st = {"state": "connected", "profile": "srv1", "profile_id": profiles[0]["id"], "protocol": "openvpn",
              "iface": "tun0", "public_ip": None, "uptime": 1, "rx": 0, "tx": 0, "rx_rate": 0, "tx_rate": 0,
              "message": "", "netlock": {"engaged": False, "backend": None}}
        w._on_status(st)
        assert w.sel_id == profiles[1]["id"], "selection snapped back to the old server"
        print("SERVERS-OK")
        self.quit()
        return False


App().run([])

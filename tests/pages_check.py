"""Run under xvfb: the Schedule and Apps pages build, render daemon data and open their dialogs."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import gi
gi.require_version("Gtk", "4.0")
from gi.repository import GLib, Gtk
from vpnman.gui import app as A
from vpnman.gui import pages as P

CALLS = []


class App(A.Application):
    def do_activate(self):
        super().do_activate()
        w = self.win
        w.profiles = [{"id": "a" * 12, "name": "alpha", "favorite": False, "blacklisted": False, "protocol": "openvpn",
                       "server": "", "port": 0}]
        pg = w.stack.get_pages(); names = [pg.get_item(i).get_name() for i in range(pg.get_n_items())]
        assert "schedule" in names and "bypass" in names, names
        entry = {"id": "e1", "name": "Work", "enabled": True, "days": [0, 1, 2, 3, 4], "start": "08:00", "end": "17:30",
                 "profile": "alpha", "active": False, "next_in": 95, "summary": "Weekdays · 08:00 → 17:30"}
        w.sched_page.rpc = lambda m, ok=None, fail=None, **kw: CALLS.append((m, kw)) or (ok and ok({"enabled": True, "entries": []}))
        w.bypass_page.rpc = w.sched_page.rpc
        w.sched_page.update({"enabled": True, "entries": [entry], "owned": None})
        w.bypass_page.update({"enabled": True, "supported": True, "reason": "", "active": True, "moved": 3,
                              "apps": [{"id": "x.desktop", "name": "Steam", "match": ["steam"], "icon": "steam"}]})
        assert len(w.sched_page._rows) == 1 and len(w.bypass_page._rows) == 1
        # saving from the dialog sends validated fields
        dlg = P.ScheduleDialog(w, w.profiles, entry, lambda e: CALLS.append(("done", e)))
        assert dlg.start.value() == "08:00" and dlg.end.value() == "17:30" and dlg.use_end.get_active()
        dlg.day_btns[6].set_active(True)
        dlg._submit()
        done = [c for c in CALLS if c[0] == "done"][0][1]
        assert done["days"] == [0, 1, 2, 3, 4, 6] and done["profile"] == "a" * 12 and done["end"] == "17:30", done
        w.sched_page._save([done])
        assert CALLS[-1][0] == "schedule.set" and CALLS[-1][1]["entries"][0]["start"] == "08:00"
        # picker lists installed apps and returns the typed custom program
        got = []
        pick = P.AppPicker(w, [], got.extend)
        pick.custom.set_text("firefox")
        pick._submit()
        assert got and got[-1]["match"] == ["firefox"], got
        w.bypass_page.update({"enabled": False, "supported": False, "reason": "needs nftables", "active": False, "apps": []})
        assert not w.bypass_page.enabled.get_sensitive()
        print("PAGES-OK")
        self.quit()
        return False


App().run([])

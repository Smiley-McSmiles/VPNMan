"""Run under xvfb with xdotool: REAL clicks - plain, Ctrl+click and Shift+click selection on the Servers tab."""
import os, sys, subprocess
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import gi
gi.require_version("Gtk", "4.0"); gi.require_version("Adw", "1"); gi.require_version("Graphene", "1.0")
from gi.repository import GLib, Gtk, Graphene
from vpnman.gui import app as A
A.rpc = lambda *a, **k: None
def prof(i):
    return {"id": "%012d" % i, "name": "srv%d" % i, "favorite": False, "blacklisted": False, "protocol": "openvpn", "server": "h%d" % i, "port": 1194}
def x(*args): subprocess.run(["xdotool"] + list(args), check=False)
class App(A.Application):
    def do_activate(self):
        super().do_activate()
        w = self.win
        w._tick = lambda: True
        ps = [prof(i) for i in range(1, 7)]
        w.profiles = ps; w._on_profiles(ps)
        w.stack.set_visible_child_name("servers")
        rows = [w._rows[p["id"]] for p in ps]
        order = sorted(rows, key=lambda r: r.get_index())
        def pos(i):
            ok, pt = order[i].compute_point(w, Graphene.Point().init(60, 20))
            return int(pt.x), int(pt.y)
        def names(): return sorted(p["name"] for p in w.selected_profiles())
        steps = []
        def click(i, mod=None):
            px, py = pos(i)
            if mod: x("keydown", mod)
            x("mousemove", str(px), str(py)); x("click", "1")   # +40: toolbar/header offset
            if mod: x("keyup", mod)
        res = {}
        def s1(): click(1); return False
        def s2(): res["plain"] = names(); click(3, "ctrl"); return False
        def s3(): res["ctrl"] = names(); click(5, "shift"); return False
        def s4():
            res["shift"] = names()
            ok = (res["plain"] == ["srv2"] and res["ctrl"] == ["srv2", "srv4"]
                  and res["shift"] == ["srv2", "srv3", "srv4", "srv5", "srv6"] and w.sel_bar.get_reveal_child())
            print("SELECT-OK" if ok else "SELECT-FAIL %s" % res, flush=True)
            self.quit(); return False
        for i, f in enumerate((s1, s2, s3, s4)):
            GLib.timeout_add(1500 + 700 * i, f)
App().run([])

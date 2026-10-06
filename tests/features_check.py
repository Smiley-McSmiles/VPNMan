"""Run under xvfb: the new dialogs and pages build and behave - credentials prompt, connection test, traffic graph,
history, bypass addresses and mode, networks preferences, server groups and sorting."""
import os, sys, tempfile
os.environ["XDG_CONFIG_HOME"] = tempfile.mkdtemp()
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import cairo
import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk
from vpnman.gui import app as A
from vpnman.gui import pages as P
from vpnman.settings import DEFAULTS

CALLS = []


def fake_rpc(method, ok=None, fail=None, **kw):
    CALLS.append((method, kw))
    canned = {
        "leaktest": {"checks": [{"id": "tunnel", "name": "VPN tunnel", "status": "ok", "detail": "Connected"},
                                {"id": "dns", "name": "DNS servers", "status": "fail", "detail": "leak <&> test"},
                                {"id": "ipv6", "name": "IPv6", "status": "warn", "detail": "maybe"}], "summary": "fail"},
        "network.status": {"id": "Home", "name": "Home", "kind": "wifi", "device": "wlan0", "gateway": "1.1.1.1",
                           "trusted": False},
        "network.trust": {"id": "Home", "name": "Home", "kind": "wifi", "device": "wlan0", "gateway": "1.1.1.1",
                          "trusted": True},
    }
    if ok and method in canned:
        ok(canned[method])


def prof(i, group="", fav=False):
    return {"id": "%012d" % i, "name": "srv%d" % i, "favorite": fav, "blacklisted": False, "protocol": "openvpn",
            "server": "h%d" % i, "port": 1194, "group": group, "username": "bob"}


class App(A.Application):
    def do_activate(self):
        super().do_activate()
        w = self.win
        A.rpc = fake_rpc
        P_rpc = fake_rpc
        # ---- credentials prompt
        saved = []
        dlg = A.CredentialsPrompt(w, prof(1), "The server rejected the login.", lambda *a: saved.append(a))
        assert dlg.user.get_text() == "bob"
        dlg.password.set_text("secret")
        dlg._response(dlg, "retry")
        assert saved == [("%012d" % 1, "bob", "secret")], saved
        saved.clear()
        dlg.password.set_text("")
        dlg._response(dlg, "retry")
        assert not saved, "empty password must not be submitted"
        # the window asks once per failure, only when it can be seen
        asked = []
        w._ask_credentials = lambda st: asked.append(st["message"])
        w.profiles = [prof(1)]
        base = {"state": "error", "profile": "srv1", "profile_id": "%012d" % 1, "protocol": "openvpn", "iface": None,
                "public_ip": None, "uptime": 0, "rx": 0, "tx": 0, "rx_rate": 0, "tx_rate": 0, "message": "bad login",
                "error_kind": "auth", "netlock": {"engaged": False, "backend": None}}
        w._last_state = "connecting"
        w.is_visible = lambda: True
        w._on_status(base)
        assert asked == ["bad login"], asked
        w._on_status(base)                                   # still the same failure: no second prompt
        assert len(asked) == 1
        w._on_status(dict(base, error_kind=None))
        assert len(asked) == 1
        # ---- connection test dialog
        lt = A.LeakTestDialog(w)
        titles = [r.get_title() for r in lt.rows]
        assert "VPN tunnel" in titles and "DNS servers" in titles and any("Problems found" in t for t in titles), titles
        # ---- traffic graph draws and scales
        g = P.TrafficGraph()
        for i in range(30):
            g._last = 0
            g.push(1000 * i, 500 * i)
        surf = cairo.ImageSurface(cairo.FORMAT_ARGB32, 300, 96)
        g._draw(g.area, cairo.Context(surf), 300, 96)
        assert "peak" in g.legend.get_label()
        pts = P.graph_points([0, 50, 100], 200, 100, 100)
        assert pts[-1][0] == 200 and pts[0][1] > pts[-1][1], pts
        g.reset()
        assert not g.rx
        # ---- history
        h = P.HistoryGroup(fake_rpc, None)
        h.update([{"profile": "A <b>", "protocol": "openvpn", "start": 1, "end": 61, "duration": 60, "rx": 2048, "tx": 10,
                   "reason": "Disconnected"}])
        assert len(h._rows) == 1 and h.get_visible()
        h.update([])
        assert not h.get_visible()
        # ---- bypass page: addresses and mode
        bp = w.bypass_page
        bp.rpc = fake_rpc
        bp.update({"enabled": True, "supported": True, "reason": "", "active": False, "moved": 0, "apps": [],
                   "mode": "include", "routes": ["10.0.0.0/8", "nas.example.com"]})
        assert len(bp._addr_rows) == 2 and bp.mode.get_selected() == 1
        assert bp.top_group.get_title() == "Apps That Use the VPN"
        CALLS.clear()
        bp.mode.set_selected(0)
        assert ("split.set", {"mode": "exclude"}) in CALLS, CALLS
        CALLS.clear()
        bp._save_routes(["10.0.0.0/8"])
        assert CALLS[-1] == ("routes.set", {"entries": ["10.0.0.0/8"]})
        bp.addr_entry.set_text("printer.lan, 192.168.5.5")
        CALLS.clear()
        bp._add_address(bp.addr_entry)
        assert CALLS[-1][1]["entries"] == ["10.0.0.0/8", "nas.example.com", "printer.lan", "192.168.5.5"], CALLS
        # ---- preferences: networks page
        settings = {k: (dict(v) if isinstance(v, dict) else v) for k, v in DEFAULTS.items()}
        pw = A.PreferencesWindow(w, settings)
        assert pw.net_btn.get_label() == "Trust This Network" and "Home" in pw.net_row.get_subtitle()
        CALLS.clear()
        pw._toggle_trust()
        assert CALLS[-1] == ("network.trust", {"name": "Home", "trusted": True}), CALLS
        assert pw.net_btn.get_label() == "Stop Trusting"
        # ---- servers: groups, sorting, headers
        profs = [prof(1, "Zeta"), prof(2, ""), prof(3, "Alpha", fav=True), prof(4, "Alpha")]
        w.profiles = profs
        w._on_profiles(profs)
        w.latency = {profs[2]["id"]: 80.0, profs[3]["id"]: 20.0}
        order = lambda: [r.profile["name"] for r in sorted(w._rows.values(), key=w._sort_key)]   # noqa: E731
        assert order() == ["srv2", "srv3", "srv4", "srv1"], order()          # ungrouped, Alpha (fav first), Zeta
        w.sort_drop.set_selected(2)                                           # fastest first, still grouped
        assert order() == ["srv2", "srv4", "srv3", "srv1"], order()
        w.sort_drop.set_selected(1)
        assert order() == ["srv2", "srv3", "srv4", "srv1"]
        rows = sorted(w._rows.values(), key=w._sort_key)
        w._header(rows[1], rows[0])
        assert rows[1].get_header() is not None and rows[1].get_header().get_label() == "Alpha"
        w._header(rows[2], rows[1])
        assert rows[2].get_header() is None
        w._header(rows[0], None)
        assert rows[0].get_header() is None                                   # no heading for ungrouped servers
        # ---- failover chooser and the edit dialog
        p1 = dict(prof(1), failover=["%012d" % 3])
        ed = A.ProfileDialog(w, "edit", [], profile=p1)
        assert "srv3" in ed.fo_row.get_subtitle(), ed.fo_row.get_subtitle()
        got = []
        fd = A.FailoverDialog(ed, [prof(2), prof(3), prof(4)], ["%012d" % 3], got.append)
        assert [p["id"] for p in fd.order][0] == "%012d" % 3                   # chosen ones first, in order
        fd.checks["%012d" % 4].set_active(True)
        fd._move(0, 1)                                                          # srv3 down: srv2, srv3, srv4
        fd._save()
        assert got == [["%012d" % 3, "%012d" % 4]], got
        ed.failover = got[0]
        ed.name.set_text("srv1")
        ed._submit()
        ch = [kw for m, kw in CALLS if m == "profiles.update" and "failover" in kw.get("changes", {})]
        assert ch and ch[-1]["changes"]["failover"] == got[0], ch
        # ---- update result dialog / import notes build without errors
        w.show_warnings(["a: Will be ignored: 'register-dns'"])
        w._update_result({"current": "1.0.6", "latest": "9.9.9", "newer": True, "url": "https://github.com/x", "notes": "n"}, False)
        w._update_result({"error": "offline"}, True)
        print("FEATURES-OK")
        self.quit()
        return False


App().run([])

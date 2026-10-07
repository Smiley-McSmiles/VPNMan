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
from vpnman.gui import proxypage as PP
from vpnman.settings import DEFAULTS

CALLS = []
PROXY_STATUS = {"enabled": True, "selected": "%012d" % 1, "name": "Home", "order": "vpn_proxy", "mode": "local", "running": True,
                "carrier": False, "error": "", "socks": 10808, "http": 10809, "installed": True, "system_ok": True,
                "socks_port": 10808, "http_port": 10809, "dns": "1.1.1.1", "udp": "block"}


def fake_rpc(method, ok=None, fail=None, **kw):
    CALLS.append((method, kw))
    canned = {
        "proxy.list": [{"id": "%012d" % i, "name": n, "protocol": "vless", "server": "p%d.example.com" % i, "port": 443,
                        "group": g, "selected": i == 1, "notes": ""} for i, (n, g) in enumerate([("Home", ""), ("WS", "sub"), ("TR", "sub")], 1)],
        "proxy.status": PROXY_STATUS, "proxy.sources": [], "proxy.set": PROXY_STATUS, "proxy.select": {"id": "x"},
        "proxy.latency": {"%012d" % 1: 12.5, "%012d" % 2: None},
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


def fake_proxy_list():
    return [{"id": "%012d" % i, "name": n, "protocol": "vless", "server": "p%d.example.com" % i,
                                        "port": 443, "group": g, "selected": i == 1, "notes": ""}
                                       for i, (n, g) in enumerate([("Home", ""), ("WS", "sub"), ("TR", "sub")], 1)]


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
        assert rows[1].get_header() is not None and rows[1].get_header().get_first_child().get_label() == "Alpha"
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
        # ---- batch edit: group header button, group dialog, selection dialog
        rows = sorted(w._rows.values(), key=w._sort_key)
        w._header(rows[1], rows[0])
        hdr = rows[1].get_header()
        btns = []
        c = hdr.get_first_child()
        while c:
            if isinstance(c, A.Gtk.Button):
                btns.append(c.get_label())
            c = c.get_next_sibling()
        assert btns == ["Edit…"], btns
        members = [p for p in w.profiles if p.get("group") == "Alpha"]
        bd = A.BatchEditDialog(w, members, group="Alpha")
        assert bd.group_row.get_text() == "Alpha" and bd.changes() == {}
        bd.group_row.set_text("Beta"); bd.user.set_text("bob"); bd.password.set_text("pw")
        assert bd.changes() == {"group": "Beta", "username": "bob", "password": "pw"}, bd.changes()
        bd.st_mode.set_selected(1)
        try:
            bd.changes(); raise SystemExit("empty stunnel host must be refused")
        except ValueError:
            pass
        bd.st_host.set_text("vpn.example.com:8443"); bd.st_sni.set_text("sni.example")
        assert bd.changes()["stunnel"] == {"mode": "set", "host": "vpn.example.com", "port": 8443, "sni": "sni.example"}
        bd.st_mode.set_selected(2)
        assert bd.changes()["stunnel"] == {"mode": "off"}
        sel = A.BatchEditDialog(w, members)
        assert sel.changes() == {}
        sel.group_row.set_text("Moved")
        assert sel.changes() == {"group": "Moved"}
        CALLS.clear()
        bd._apply()
        call = [kw for m, kw in CALLS if m == "profiles.update_many"]
        assert call and call[0]["ids"] == [p["id"] for p in members] and call[0]["changes"]["group"] == "Beta", call
        # ---- servers tab: search above the buttons, VPN / Proxy sub-tabs
        assert w.srv_tabs.get_visible_child_name() == "vpn"
        sib = w.search.get_next_sibling()
        assert sib is not None and w.sort_drop.get_parent() is sib and w.ping_btn.get_parent() is sib, "search must sit above the buttons"
        # ---- proxy page
        pp = w.proxy_page
        pp.rpc = fake_rpc
        pp.update_list(fake_proxy_list())
        pp.update_status(PROXY_STATUS)
        assert len(pp._rows) == 3 and pp.enable.get_active() and "Running" in pp.enable.get_subtitle()
        assert pp.order.get_selected() == 1 and pp.mode.get_visible() and "SOCKS5 127.0.0.1:10808" in pp.addr.get_subtitle()
        CALLS.clear()
        pp.order.set_selected(2)                                  # "Proxy, then VPN"
        assert CALLS[-1] == ("proxy.set", {"order": "proxy_vpn"}), CALLS
        pp.update_status(dict(PROXY_STATUS, order="proxy_vpn", running=False))
        assert not pp.mode.get_visible() and "Starts with the next VPN" in pp.enable.get_subtitle()
        pp.update_status(dict(PROXY_STATUS, error="boom <b>", running=False))
        assert "boom" in pp.enable.get_subtitle()
        pp.update_status(dict(PROXY_STATUS, installed=False))
        assert pp.banner.get_revealed()
        CALLS.clear()
        pp.update_status(PROXY_STATUS)
        assert not CALLS, "updating the widgets from a status must not send changes back"
        pp.enable.set_active(False)
        assert CALLS[-1] == ("proxy.set", {"enabled": False}), CALLS
        pp.update_status(PROXY_STATUS)
        CALLS.clear()
        pp._rows["%012d" % 2].use.set_active(True)
        assert ("proxy.select", {"ident": "%012d" % 2}) in CALLS, CALLS
        pp.search.set_text("tr")
        pp.listbox.invalidate_filter()
        add = PP.ProxyAddDialog(w, fake_rpc, lambda: None)
        add._submit()
        assert add.err.get_revealed(), "an empty add dialog must complain"
        add.url.set_text("ftp://x")
        add._submit()
        assert "http" in add.err.get_title()
        PP.ProxyEditDialog(w, fake_rpc, fake_proxy_list()[0], lambda: None)
        # ---- connection table
        cg = w.conn_group
        rows = [{"dir": "out", "proto": "tcp", "v6": False, "local": "10.0.0.2", "lport": 40000, "remote": "93.184.216.34", "rport": 443,
                 "state": "ESTABLISHED", "pid": 7, "app": "firefox"},
                {"dir": "in", "proto": "udp", "v6": True, "local": "::1", "lport": 53, "remote": "::", "rport": 0, "state": "", "pid": 0, "app": ""}]
        cg.update({"rows": rows})
        assert cg.store.get_n_items() == 2 and cg.params() == {"listening": False, "local": False}
        assert "2 connections" in cg.summary.get_label()
        cg.search.set_text("firefox")
        cg.refilter()
        assert cg.filtered.get_n_items() == 1 and "of 2" in cg.summary.get_label()
        cg.search.set_text("")
        cg.refilter()
        first = cg.store.get_item(0)
        cg.update({"rows": rows})
        assert cg.store.get_item(0) is first, "an unchanged table must not be rebuilt"
        cg.update({"rows": rows[:1], "note": "n"})
        assert cg.store.get_n_items() == 1 and "n" in cg.summary.get_label()
        # ---- update result dialog / import notes build without errors
        w.show_warnings(["a: Will be ignored: 'register-dns'"])
        w._update_result({"current": "1.0.6", "latest": "9.9.9", "newer": True, "url": "https://github.com/x", "notes": "n"}, False)
        w._update_result({"error": "offline"}, True)
        print("FEATURES-OK")
        self.quit()
        return False


App().run([])

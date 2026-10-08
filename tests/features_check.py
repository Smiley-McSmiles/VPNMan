"""Run under xvfb: the new dialogs and pages build and behave - credentials prompt, connection test, traffic graph,
history, bypass addresses and mode, networks preferences, server groups and sorting."""
import os, subprocess, sys, tempfile
os.environ["XDG_CONFIG_HOME"] = tempfile.mkdtemp()
# GNOME's proxy settings (a copy of the org.gnome.system.proxy schema), in memory: "Copy from the desktop settings"
_SCHEMAS = tempfile.mkdtemp()
with open(os.path.join(_SCHEMAS, "org.gnome.system.proxy.gschema.xml"), "w") as _fh:
    _fh.write("""<schemalist>
  <enum id="org.gnome.desktop.GDesktopProxyMode"><value nick="none" value="0"/><value nick="manual" value="1"/>
    <value nick="auto" value="2"/></enum>
  <schema id="org.gnome.system.proxy" path="/system/proxy/">
    <child name="http" schema="org.gnome.system.proxy.http"/><child name="https" schema="org.gnome.system.proxy.https"/>
    <child name="ftp" schema="org.gnome.system.proxy.ftp"/><child name="socks" schema="org.gnome.system.proxy.socks"/>
    <key name="mode" enum="org.gnome.desktop.GDesktopProxyMode"><default>'none'</default></key>
    <key name="autoconfig-url" type="s"><default>''</default></key>
    <key name="ignore-hosts" type="as"><default>['localhost', '127.0.0.0/8', '::1']</default></key>
  </schema>
  <schema id="org.gnome.system.proxy.http" path="/system/proxy/http/">
    <key name="host" type="s"><default>''</default></key><key name="port" type="i"><default>8080</default></key></schema>
  <schema id="org.gnome.system.proxy.https" path="/system/proxy/https/">
    <key name="host" type="s"><default>''</default></key><key name="port" type="i"><default>0</default></key></schema>
  <schema id="org.gnome.system.proxy.ftp" path="/system/proxy/ftp/">
    <key name="host" type="s"><default>''</default></key><key name="port" type="i"><default>0</default></key></schema>
  <schema id="org.gnome.system.proxy.socks" path="/system/proxy/socks/">
    <key name="host" type="s"><default>''</default></key><key name="port" type="i"><default>0</default></key></schema>
</schemalist>""")
subprocess.run(["glib-compile-schemas", _SCHEMAS], check=True)
os.environ.update(GSETTINGS_SCHEMA_DIR=_SCHEMAS, GSETTINGS_BACKEND="memory", XDG_CURRENT_DESKTOP="GNOME")
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
NET_STATUS = {"enabled": False, "active": False, "error": "", "ignore": ["localhost", "127.0.0.0/8", "::1"], "apps": [],
              "dns": "1.1.1.1", "udp": "block", "servers": {}, "supported": True, "installed": True,
              "http": {"host": "", "port": 8080, "user": "", "password": "", "has_password": False},
              "https": {"host": "", "port": 0, "user": "", "password": "", "has_password": False},
              "ftp": {"host": "", "port": 0, "user": "", "password": "", "has_password": False},
              "socks": {"host": "", "port": 0, "user": "", "password": "", "has_password": False}}
BLOCK_STATUS = {"enabled": True, "active": True, "error": "", "supported": True, "reason": "", "apps_supported": True, "apps_reason": "",
                "entries": [{"id": "aaaa1111", "kind": "address", "value": "203.0.113.9/32", "proto": "any", "note": "bad", "enabled": True, "created": 0},
                            {"id": "bbbb2222", "kind": "endpoint", "value": "203.0.113.9:443", "proto": "tcp", "note": "", "enabled": False, "created": 0},
                            {"id": "cccc3333", "kind": "app", "value": "steam", "proto": "any", "note": "", "enabled": True, "created": 0}]}
PROXY_STATUS = {"enabled": True, "selected": "%012d" % 1, "name": "Home", "order": "vpn_proxy", "mode": "local", "running": True,
                "carrier": False, "error": "", "socks": 10808, "http": 10809, "installed": True, "system_ok": True,
                "socks_port": 10808, "http_port": 10809, "dns": "1.1.1.1", "udp": "block"}


def fake_rpc(method, ok=None, fail=None, **kw):
    CALLS.append((method, kw))
    canned = {
        "proxy.list": [{"id": "%012d" % i, "name": n, "protocol": "vless", "server": "p%d.example.com" % i, "port": 443,
                        "group": g, "selected": i == 1, "notes": ""} for i, (n, g) in enumerate([("Home", ""), ("WS", "sub"), ("TR", "sub")], 1)],
        "proxy.status": PROXY_STATUS, "netproxy.status": NET_STATUS, "netproxy.set": NET_STATUS, "proxy.sources": [], "proxy.set": PROXY_STATUS, "proxy.select": {"id": "x"},
        "proxy.latency": {"%012d" % 1: 12.5, "%012d" % 2: None},
        "proxy.remove": {"removed": ["WS", "TR"], "failed": []},
        "proxy.fastest": {"id": "%012d" % 2, "name": "WS", "latency": 9.4},
        "proxy.link": {"id": "%012d" % 1, "name": "Home", "link": "vless://11111111-2222-3333-4444-555555555555@p1.example.com:443?security=tls#Home"},
        "blocks.status": BLOCK_STATUS, "blocks.add": {"id": "abcd1234", "kind": "address", "value": "x", "proto": "any", "closed": 2},
        "blocks.remove": {"removed": ["aaaa1111"]}, "blocks.set": BLOCK_STATUS, "blocks.update": {"id": "aaaa1111"},
        "connections.close": {"closed": True}, "connections": {"rows": [], "supported": True},
        "profiles.list": [{"id": "%012d" % i, "name": "srv%d" % i, "favorite": False, "blacklisted": False, "protocol": "openvpn",
                           "server": "h", "port": 1, "group": "", "username": ""} for i in (1, 2)],
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
        try:
            self.checks()
        except BaseException:                    # a failed check ends the run at once (instead of a hanging app)
            import traceback
            traceback.print_exc()
            os._exit(1)

    def checks(self):
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
        # ---- network proxy: Preferences → Connection and the switch on the Connection page
        from vpnman.gui import proxyprefs as PX
        np_ = pw.netproxy
        assert set(np_.hosts) == {"http", "https", "ftp", "socks"} and int(np_.ports["http"].get_value()) == 8080
        assert np_.ignore.get_text() == "localhost, 127.0.0.0/8, ::1"
        CALLS.clear()
        np_.hosts["http"].set_text("http://proxy.example.com:3128/")
        np_._save()
        assert CALLS[-1] == ("netproxy.set", {"http": {"host": "proxy.example.com", "port": 3128, "user": ""}}), CALLS
        CALLS.clear()
        np_.hosts["socks"].set_text("me:pw@10.0.0.5")                    # no port yet: nothing is sent
        np_._save()
        assert not CALLS and "socks" in np_._dirty, CALLS
        np_.ports["socks"].set_value(1080)
        assert CALLS[-1] == ("netproxy.set", {"socks": {"host": "10.0.0.5", "port": 1080, "user": "me", "password": "pw"}}), CALLS
        CALLS.clear()
        np_.apps.set_text("steam, thunderbird")
        np_.ignore.set_text("localhost, *.corp.example")
        np_._save()
        assert CALLS[-1] == ("netproxy.set", {"ignore": ["localhost", "*.corp.example"], "apps": ["steam", "thunderbird"]}), CALLS
        from gi.repository import Gio
        gs = Gio.Settings.new("org.gnome.system.proxy")
        CALLS.clear()
        np_._import()
        assert not any(c[0] == "netproxy.set" for c in CALLS), "nothing set on the desktop: nothing copied"
        gs.set_string("mode", "manual")
        gs.get_child("http").set_string("host", "corp-proxy.example")
        gs.get_child("http").set_int("port", 3128)
        gs.get_child("socks").set_string("host", "10.0.0.9")
        gs.get_child("socks").set_int("port", 1080)
        np_._import()
        got = next(c[1] for c in CALLS if c[0] == "netproxy.set")
        assert got["http"] == {"host": "corp-proxy.example", "port": 3128, "user": "", "password": ""}, got
        assert got["socks"]["host"] == "10.0.0.9" and got["https"]["host"] == "" and got["ignore"] == ["localhost", "127.0.0.0/8", "::1"]
        assert PX.parse_url("u:p@[2001:db8::1]:1080") == ("u", "p", "2001:db8::1", 1080)
        assert PX.show_url({"host": "2001:db8::1", "user": "u"}) == "u@[2001:db8::1]"
        assert PX.summary(dict(NET_STATUS, enabled=True, active=True,
                               http={"host": "p", "port": 3128})) == "All traffic goes through HTTP p:3128"
        assert PX.summary(dict(NET_STATUS, enabled=True, error="no proxy server is set")).startswith("Not running")
        sw = w.netproxy_switch.row                                        # the Connection page
        grp = sw.get_ancestor(A.Adw.PreferencesGroup)
        assert grp.get_title() == "Network Proxy"
        CALLS.clear()
        sw.set_active(True)
        assert ("netproxy.set", {"enabled": True}) in CALLS, CALLS
        w.netproxy.update(dict(NET_STATUS, enabled=True, active=True, http={"host": "p", "port": 3128}))
        assert sw.get_active() and "HTTP p:3128" in sw.get_subtitle(), (sw.get_active(), sw.get_subtitle())
        assert pw.netproxy.switch.row.get_active()
        w.netproxy.update(dict(NET_STATUS))
        assert not sw.get_active()
        pw.present()
        pw.close()
        assert np_.sync not in w.netproxy.listeners, "a closed Preferences window stops listening"
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
        # ---- the lists load even if the daemon was not up yet when the window opened (e.g. right after a reinstall)
        w.profiles, w._synced, w._sync_try = [], False, 0.0
        CALLS.clear()
        w._on_status(dict(base, state="disconnected", error_kind=None, message=""))
        assert any(c[0] == "profiles.list" for c in CALLS), "an answering daemon with no lists loaded must trigger a load"
        assert w._synced and len(w.profiles) == 2
        CALLS.clear()
        w._on_status(dict(base, state="disconnected", error_kind=None, message=""))
        assert not any(c[0] == "profiles.list" for c in CALLS), "once loaded, status updates do not reload the lists"
        w._set_daemon(False)
        assert not w._synced, "a daemon that went away means: load again when it is back"
        w._sync_try = 0.0
        CALLS.clear()
        w._on_status(dict(base, state="disconnected", error_kind=None, message=""))
        assert any(c[0] == "profiles.list" for c in CALLS)
        # ---- Connection tab selector: current / last connected server, predictable
        w.profiles = [prof(1), prof(2), prof(3)]
        ids = [p["id"] for p in w.profiles]
        w._pending, w._user_pick = None, None
        w.status = {"state": "disconnected", "last_profile": ids[2]}
        assert w.wanted_selection() == ids[2], "disconnected: the last connected server"
        w.status = {"state": "disconnected", "last_profile": "gone"}
        assert w.wanted_selection() == ids[0], "unknown last server: the first one"
        w._user_pick = ids[1]
        w.status = {"state": "disconnected", "last_profile": ids[2]}
        assert w.wanted_selection() == ids[1], "a hand pick holds while nothing is connecting"
        w.status = {"state": "connecting", "profile_id": ids[0], "last_profile": ids[0]}
        assert w.wanted_selection() == ids[0] and w._user_pick is None, "a connection under way decides"
        w.status = {"state": "disconnected", "last_profile": ids[0]}
        assert w.wanted_selection() == ids[0], "and the hand pick is gone afterwards"
        import time as _t
        w._pending = (ids[1], _t.monotonic() + 60)
        w.status = {"state": "connected", "profile_id": ids[0], "last_profile": ids[0]}
        assert w.wanted_selection() == ids[1], "a click still on its way wins over the old connection"
        w._pending = None
        w.status = {"state": "error", "profile_id": ids[2], "last_profile": ids[2]}
        assert w.wanted_selection() == ids[2], "after a failed attempt: the server that failed"
        w.status = {"state": "connected", "profile_id": ids[1], "last_profile": ids[1]}
        w._sync_selector()
        assert w.server_row.get_selected() == 1 and w.sel_id == ids[1]
        w.status = {"state": "disconnected", "last_profile": ids[1]}
        w._on_profiles([prof(1), prof(2), prof(3)][::-1])           # a refreshed list keeps the right server selected
        assert w.profiles[w.server_row.get_selected()]["id"] == ids[1]
        w._on_profiles([prof(3), prof(1)])                           # the selected server was deleted
        assert w.profiles[w.server_row.get_selected()]["id"] == ids[2]   # falls back to the first of what is left
        w._pending = None
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
        # multi-select and bulk remove, like the VPN servers list
        assert pp.listbox.get_selection_mode() == A.Gtk.SelectionMode.MULTIPLE and not pp.sel_bar.get_reveal_child()
        pp.listbox.select_all()
        assert len(pp.selected_proxies()) == 3 and pp.sel_label.get_label() == "3 selected" and pp.sel_bar.get_reveal_child()
        pp.update_list(fake_proxy_list())                              # a refresh keeps the selection
        assert len(pp.selected_proxies()) == 3
        pp.listbox.unselect_all()
        assert not pp.sel_bar.get_reveal_child()
        pp.listbox.select_row(pp._rows["%012d" % 2])
        assert [p["name"] for p in pp.selected_proxies()] == ["WS"]
        CALLS.clear()
        pp.do_remove([p["id"] for p in pp.selected_proxies()] + ["%012d" % 3])
        assert CALLS[0] == ("proxy.remove", {"ids": ["%012d" % 2, "%012d" % 3]}), CALLS
        pp.listbox.unselect_all()
        rows_before = dict(pp._rows)
        pp.update_list(fake_proxy_list())
        assert all(pp._rows[k] is v for k, v in rows_before.items()), "an unchanged list must keep its rows (and the scroll position)"
        CALLS.clear()
        pp.update_status(PROXY_STATUS)
        pp._rows["%012d" % 3].use.set_active(True)                     # choosing a proxy must not reload the whole list
        assert ("proxy.select", {"ident": "%012d" % 3}) in CALLS and not any(c[0] == "proxy.list" for c in CALLS), CALLS
        pp.update_status(PROXY_STATUS)
        pp._rows["%012d" % 1].use.set_active(False)                    # the chosen proxy cannot be un-chosen
        assert pp._rows["%012d" % 1].use.get_active()
        pp.search.set_text("tr")
        pp.listbox.invalidate_filter()
        add = PP.ProxyAddDialog(w, fake_rpc, lambda: None)
        add._submit()
        assert add.err.get_revealed(), "an empty add dialog must complain"
        add.url.set_text("ftp://x")
        add._submit()
        assert "http" in add.err.get_title()
        PP.ProxyEditDialog(w, fake_rpc, fake_proxy_list()[0], lambda: None)
        # use fastest, failover switch, share dialog with a QR code
        CALLS.clear()
        pp._on_fastest()
        assert CALLS[0] == ("proxy.fastest", {}) and pp.latency["%012d" % 2] == 9.4 and "9 ms" in pp._rows["%012d" % 2].lat.get_label()
        pp.update_status(dict(PROXY_STATUS, failover=False))
        CALLS.clear()
        pp.failover.set_active(True)
        assert ("proxy.set", {"failover": True}) in CALLS, CALLS
        CALLS.clear()
        pp.update_status(dict(PROXY_STATUS, failover=True))
        assert not CALLS, "the failover switch follows the status without sending it back"
        import time as _t
        pp.update_status(dict(PROXY_STATUS, failover=True, last_failover={"from": "Home", "to": "WS", "reason": "x", "at": int(_t.time())}))
        assert any(c[0] == "proxy.list" for c in CALLS), "after a failover the list (the chosen proxy) is reloaded"
        shown = []
        orig_present = PP.ProxyShareDialog.present
        PP.ProxyShareDialog.present = lambda self: shown.append(self)
        pp.share(fake_proxy_list()[0])
        PP.ProxyShareDialog.present = orig_present
        sd = shown[0]
        assert sd.qr is not None and len(sd.qr.matrix) >= 21 and sd.link.startswith("vless://")
        sd._copy()
        sd.close()
        assert PP.qr_widget("x" * 3000) is None, "a link too long for a QR code shows only the text"
        # the tray offers the proxy switch
        w.proxy_page.update_status(dict(PROXY_STATUS, enabled=False))
        labels_tray = [i.get("label") for i in w.tray_menu()]
        assert "Turn Proxy On (Home)" in labels_tray, labels_tray
        w.proxy_page.update_status(PROXY_STATUS)
        item = next(i for i in w.tray_menu() if i.get("label") == "Turn Proxy Off")
        CALLS.clear()
        item["callback"]()
        assert ("proxy.set", {"enabled": False}) in CALLS, CALLS
        w.proxy_page.update_status(dict(PROXY_STATUS, name="", selected=""))
        assert not any("Proxy" in (i.get("label") or "") for i in w.tray_menu()), "no proxy chosen: no tray item"
        w.proxy_page.update_status(PROXY_STATUS)
        # ---- connection table
        cg = w.conn_group
        rows = [{"dir": "out", "proto": "tcp", "v6": False, "local": "10.0.0.2", "lport": 40000, "remote": "93.184.216.34", "rport": 443,
                 "state": "ESTABLISHED", "pid": 7, "app": "firefox"},
                {"dir": "in", "proto": "udp", "v6": True, "local": "::1", "lport": 53, "remote": "::", "rport": 0, "state": "", "pid": 0, "app": ""}]
        cg.update({"rows": rows})
        assert cg.table.store.get_n_items() == 2 and cg.params() == {"listening": False, "local": False, "resolve": False}
        assert "2 connections" in cg.table.summary.get_label()
        cg.table.search.set_text("firefox")
        cg.table.refilter()
        assert cg.table.filtered.get_n_items() == 1 and "of 2" in cg.table.summary.get_label()
        cg.table.search.set_text("")
        cg.table.refilter()
        first = cg.table.store.get_item(0)
        cg.update({"rows": rows})
        assert cg.table.store.get_item(0) is first, "an unchanged table must not be rebuilt"
        cg.update({"rows": rows[:1], "note": "n"})
        assert cg.table.store.get_n_items() == 1 and "n" in cg.table.summary.get_label()
        # ---- right-click menu, actions, pop-out window, blocked connections
        tb = cg.table
        r0 = {"dir": "out", "proto": "tcp", "v6": False, "local": "10.0.0.2", "lport": 40000, "remote": "93.184.216.34", "rport": 443,
              "state": "ESTABLISHED", "pid": 7, "app": "firefox"}
        rl = {"dir": "listen", "proto": "udp", "v6": False, "local": "0.0.0.0", "lport": 5353, "remote": "0.0.0.0", "rport": 0,
              "state": "", "pid": 0, "app": ""}

        def labels(menu):
            out = []
            for i in range(menu.get_n_items()):
                sec = menu.get_item_link(i, "section")
                if sec is not None:
                    out += labels(sec)
                else:
                    out.append(menu.get_item_attribute_value(i, "label", None).get_string())
            return out
        got = labels(tb.menu_for(r0))
        for want in ("Copy remote address (93.184.216.34:443)", "Copy remote IP", "Copy application name", "Force-close this connection",
                     "Stop application “firefox”…", "Force-kill application “firefox”…", "Block remote address 93.184.216.34",
                     "Block 93.184.216.34:443 (TCP)", "Block remote port 443 (TCP)", "Block application “firefox”"):
            assert want in got, (want, got)
        assert not any("local port" in x for x in got), "an outgoing connection has no local service to block"
        named = dict(r0, rname="example.net")
        assert "Copy remote host name (example.net)" in labels(tb.menu_for(named))
        assert "Copy remote host name" not in " ".join(labels(tb.menu_for(r0)))
        assert tb.text_for(named, "remote_host") == "example.net" and tb.text_for(r0, "remote_host") == "93.184.216.34"
        cg.table.update({"rows": [named]})
        cg.table.search.set_text("93.184")                       # the address still finds the row when a name is shown
        cg.table.refilter()
        assert cg.table.filtered.get_n_items() == 1
        cg.table.search.set_text("example.net")
        cg.table.refilter()
        assert cg.table.filtered.get_n_items() == 1
        cg.table.search.set_text("")
        cg.table.refilter()
        cg.table.resolve.set_active(True)
        assert cg.params()["resolve"] is True
        cg.table.resolve.set_active(False)
        got = labels(tb.menu_for(rl))
        assert "Block local port 5353 (UDP)" in got and not any(x.startswith(("Force-close", "Stop", "Copy remote")) for x in got), got
        assert tb.block_spec(r0, "endpoint") == ("endpoint", "93.184.216.34:443", "tcp")
        assert tb.block_spec(dict(r0, remote="2001:db8::1", v6=True), "endpoint")[1] == "[2001:db8::1]:443"
        assert tb.block_spec(r0, "remote_port") == ("port", "443", "tcp") and tb.block_spec(r0, "app") == ("app", "firefox", "any")
        assert tb.text_for(r0, "remote") == "93.184.216.34:443" and tb.text_for(r0, "row").count("\t") == 5
        cg.rpc = tb.rpc = fake_rpc
        CALLS.clear()
        tb._row = r0
        tb._act_block(None, A.GLib.Variant("s", "endpoint"))
        assert ("blocks.add", {"kind": "endpoint", "value": "93.184.216.34:443", "proto": "tcp"}) in CALLS, CALLS
        CALLS.clear()
        tb._act_block(None, A.GLib.Variant("s", "endpoint|60"))
        assert ("blocks.add", {"kind": "endpoint", "value": "93.184.216.34:443", "proto": "tcp", "minutes": 60}) in CALLS, CALLS
        CALLS.clear()
        tb._act_block(None, A.GLib.Variant("s", "app|reboot"))
        assert ("blocks.add", {"kind": "app", "value": "firefox", "proto": "any", "until_reboot": True}) in CALLS, CALLS
        # every block item opens a submenu with the durations
        menu = tb.menu_for(r0)
        subs = []
        for i in range(menu.get_n_items()):
            sec = menu.get_item_link(i, "section")
            for j in range(sec.get_n_items()):
                sub = sec.get_item_link(j, "submenu")
                if sub is not None:
                    subs.append((sec.get_item_attribute_value(j, "label", None).get_string(),
                                 [sub.get_item_attribute_value(k, "target", None).get_string() for k in range(sub.get_n_items())]))
        assert len(subs) == 4 and subs[0][1] == ["address|0", "address|15", "address|60", "address|1440", "address|reboot"], subs
        # export the rows shown as CSV
        tb.update({"rows": [r0, rl]})
        assert len(tb.shown_rows()) == 2
        tb._act_export_copy()
        from vpnman.conntable import to_csv
        csv_text = to_csv(tb.shown_rows())
        assert csv_text.splitlines()[0].startswith("direction,application,pid") and "93.184.216.34" in csv_text
        saved_to = []
        import vpnman.gui.connpage as CP
        orig_save = CP.save_file
        out_csv = os.path.join(tempfile.mkdtemp(), "c.csv")
        CP.save_file = lambda parent, title, name, cb: (saved_to.append(name), cb(out_csv))
        tb._act_export_save()
        CP.save_file = orig_save
        assert saved_to[0].endswith(".csv") and open(out_csv).read() == csv_text
        CALLS.clear()
        tb._act_close(None, None)
        assert CALLS[0][0] == "connections.close" and CALLS[0][1]["rport"] == 443, CALLS
        import subprocess
        sp = subprocess.Popen(["sleep", "30"])
        assert tb.stop_process(sp.pid, "sleep", False) and sp.wait(5) == -15, "SIGTERM reaches the user's own program"
        assert not tb.stop_process(1, "init", True) and not tb.stop_process(os.getpid(), "me", True)
        win = cg.popout()
        win = cg._win
        assert win is not None and win.table.controls.get_parent() is not None
        cg.popout()
        assert cg._win is win, "a second click re-uses the pop-out window"
        win.table.update({"rows": [r0, rl]})
        assert win.table.store.get_n_items() == 2
        win.pause.set_active(True)
        win.table.update({"rows": [r0]})
        assert win.table.store.get_n_items() == 2 and "paused" in win.table.summary.get_label(), "paused table must not change"
        win.pause.set_active(False)
        win.table.update({"rows": [r0]})
        assert win.table.store.get_n_items() == 1
        win._alive = False
        win.close()
        cg.refresh_blocked()
        assert cg.blocked_count == 3 and "(3)" in cg.blocked_btn.get_label()
        cg.open_blocked()
        bw = cg._blocked
        assert bw is not None and len(bw._rows) == 3 and bw.enforce.get_active() and "Enforced" in bw.enforce.get_subtitle()
        bw.kind.set_selected(0)
        assert not bw.proto.get_visible()
        bw.kind.set_selected(2)
        assert bw.proto.get_visible()
        CALLS.clear()
        bw.value.set_text("6881")
        bw.proto.set_selected(2)
        bw.note.set_text("torrents")
        bw._add()
        assert ("blocks.add", {"kind": "port", "value": "6881", "proto": "udp", "note": "torrents"}) in CALLS, CALLS
        CALLS.clear()
        bw.value.set_text("6881")
        bw.duration.set_selected(2)
        bw._add()
        assert ("blocks.add", {"kind": "port", "value": "6881", "proto": "udp", "note": "", "minutes": 60}) in CALLS, CALLS
        bw.duration.set_selected(0)
        row = bw._make_row(dict(BLOCK_STATUS["entries"][0], expires=int(__import__("time").time()) + 600))
        assert "more minutes" in row.get_subtitle(), row.get_subtitle()
        bw.value.set_text("")
        CALLS.clear()
        bw._add()
        assert not any(c[0] == "blocks.add" for c in CALLS), "an empty value is not sent"
        bw.listbox.select_row(bw._rows["aaaa1111"])
        bw.listbox.select_row(bw._rows["cccc3333"])
        assert bw.selected_ids() == ["aaaa1111", "cccc3333"] and bw.sel_bar.get_reveal_child()
        CALLS.clear()
        bw._remove_selected()
        assert CALLS[0] == ("blocks.remove", {"ids": ["aaaa1111", "cccc3333"]}), CALLS
        CALLS.clear()
        bw._on_entry_switch("aaaa1111", False)
        assert ("blocks.update", {"ident": "aaaa1111", "enabled": False}) in CALLS, CALLS
        ctrls = [bw.observe_controllers().get_item(i) for i in range(bw.observe_controllers().get_n_items())]
        assert any(isinstance(c, A.Gtk.ShortcutController) for c in ctrls), "pop-ups close with Escape and Ctrl+W"
        bw.fill(dict(BLOCK_STATUS, supported=False, reason="needs Linux", active=False))
        assert bw.banner.get_revealed()
        bw.close()
        # ---- update result dialog / import notes build without errors
        # ---- the Connect buttons in the server list and Disconnecting… follow what the daemon does
        held = {}

        def hold_rpc(method, ok=None, fail=None, **kw):
            CALLS.append((method, kw))
            if method in ("connect", "disconnect"):
                held[method] = (ok, fail)                 # answered later, like a slow daemon
            else:
                fake_rpc(method, ok, fail, **kw)
        A.rpc = hold_rpc

        def status(state, pid=None):
            name = {"%012d" % 1: "srv1", "%012d" % 2: "srv2"}.get(pid)
            return {"state": state, "profile_id": pid, "profile": name, "protocol": "openvpn" if pid else None,
                    "message": "", "iface": "tun0" if state == "connected" else None, "public_ip": None, "since": 1,
                    "rx": 0, "tx": 0, "rx_rate": 0, "tx_rate": 0, "uptime": 3, "error_kind": None,
                    "netlock": {"engaged": False}, "last_profile": pid, "version": "x"}
        p1, p2 = "%012d" % 1, "%012d" % 2
        w._on_profiles([prof(1), prof(2)])
        w._on_status(status("connected", p1))
        r1, r2 = w._rows[p1], w._rows[p2]

        def look(r):
            return r.go.get_label(), r.go.get_sensitive()
        assert look(r1) == ("Connected", False) and look(r2) == ("Connect", True), (look(r1), look(r2))
        assert r1.dot.get_opacity() == 1 and r1.dot.has_css_class("success") and r2.dot.get_opacity() == 0
        assert not r1.go.has_css_class("suggested-action") and r2.go.has_css_class("suggested-action")
        w.stack.set_visible_child_name("servers")
        CALLS.clear()
        r1.go.emit("clicked")
        assert not any(c[0] == "connect" for c in CALLS), "the connected server's button does nothing"
        r2.go.emit("clicked")                                     # switch servers from the list
        assert ("connect", {"ident": p2}) in CALLS and w.stack.get_visible_child_name() == "servers", "stays on the list"
        assert look(r2) == ("Connecting…", False) and look(r1) == ("Connect", True), (look(r1), look(r2))
        CALLS.clear()
        r2.go.emit("clicked")
        assert not any(c[0] == "connect" for c in CALLS), "no second request while one is on its way"
        w._on_status(status("connected", p1))                     # an older poll answer must not undo the switch
        assert look(r2) == ("Connecting…", False) and look(r1) == ("Connect", True)
        w._on_status(status("connecting", p2))
        held.pop("connect")[0]({"id": p2})
        assert look(r2) == ("Connecting…", False)
        w._on_status(status("connected", p2))
        assert look(r2) == ("Connected", False) and look(r1) == ("Connect", True) and w.main_btn.get_label() == "Disconnect"
        # disconnect: grey "Disconnecting…" until the daemon is done
        CALLS.clear()
        w.on_main_button()
        assert w.main_btn.get_label() == "Disconnecting…" and not w.main_btn.get_sensitive()
        assert look(r2) == ("Disconnecting…", False) and look(r1) == ("Connect", False), "nothing starts meanwhile"
        assert not w.server_row.get_sensitive()
        w._on_status(status("connected", p2))                     # the tunnel is still up for a few seconds
        assert w.main_btn.get_label() == "Disconnecting…" and not w.main_btn.get_sensitive()
        assert w.hero.title.get_label() == "Disconnecting…" and not w.stats.get_visible()
        w.on_main_button()
        assert [c[0] for c in CALLS].count("disconnect") == 1, "a second click does not send a second disconnect"
        assert next(i for i in w.tray_menu() if "Disconnect" in i["label"])["enabled"] is False
        w._on_status(status("disconnecting", p2))
        assert w.main_btn.get_label() == "Disconnecting…"
        held.pop("disconnect")[0](True)
        w._on_status(status("disconnected"))
        assert w.main_btn.get_label() == "Connect" and w.main_btn.get_sensitive()
        assert look(r1) == ("Connect", True) and look(r2) == ("Connect", True) and r2.dot.get_opacity() == 0
        # a disconnect started elsewhere (tray, CLI) shows up through the daemon's state alone
        w._on_status(status("disconnecting", p1))
        assert w.main_btn.get_label() == "Disconnecting…" and not w.main_btn.get_sensitive()
        assert look(r1) == ("Disconnecting…", False)
        # a failed disconnect request gives the button back
        w._on_status(status("connected", p1))
        w.on_main_button()
        held.pop("disconnect")[1]("daemon gone", False)
        w._on_status(status("connected", p1))
        assert w.main_btn.get_label() == "Disconnect" and w.main_btn.get_sensitive()
        # connecting from the list while disconnected; a failed connect gives the button back
        w._on_status(status("disconnected"))
        r1.go.emit("clicked")
        assert look(r1) == ("Connecting…", False)
        held.pop("connect")[1]("no such profile", False)
        assert look(r1) == ("Connect", True)
        w._on_status(status("error", p1))
        assert look(r1) == ("Connect", True), "a failed connection can be retried"
        A.rpc = fake_rpc
        w.show_warnings(["a: Will be ignored: 'register-dns'"])
        w._update_result({"current": "1.0.6", "latest": "9.9.9", "newer": True, "url": "https://github.com/x", "notes": "n"}, False)
        w._update_result({"error": "offline"}, True)
        print("FEATURES-OK")
        self.quit()
        return False


App().run([])

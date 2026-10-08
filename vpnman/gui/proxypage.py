"""The Proxy sub-tab of the Servers page (Xray proxies) and its dialogs."""

import re
import threading

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, GLib, Gtk  # noqa: E402

from ..xray import fetch  # noqa: E402
from .keys import close_keys, restore_scroll  # noqa: E402

ORDERS = [
    ("proxy_only", "Proxy only", "You → Proxy → Internet. It runs whenever it is switched on, with or without the VPN."),
    ("vpn_proxy", "VPN, then proxy",
     "You → VPN → Proxy → Internet. The proxy runs inside the VPN tunnel and starts once the VPN is connected. "
     "Websites see the proxy server's address."),
    ("proxy_vpn", "Proxy, then VPN",
     "You → Proxy → VPN → Internet. The VPN connection itself travels through the proxy (OpenVPN and WireGuard). "
     "Your ISP only sees the proxy; websites see the VPN's address."),
]
MODES = [
    ("local", "Local proxy", "A SOCKS5 and an HTTP proxy on this computer for the applications you point at it."),
    ("system", "System-wide", "All TCP and DNS of this computer go through the proxy (Linux). IPv6 and other UDP are blocked."),
]




class ProxyAddDialog(Adw.Window):
    """Paste share links, load a file, or give a subscription URL."""

    def __init__(self, parent, rpc, on_done):
        super().__init__(transient_for=parent, modal=True, default_width=520, default_height=560, title="Add Proxies")
        close_keys(self)
        self.rpc, self.on_done, self.parent_win = rpc, on_done, parent
        view = Adw.ToolbarView()
        header = Adw.HeaderBar(show_end_title_buttons=False, show_start_title_buttons=False)
        cancel = Gtk.Button(label="Cancel")
        cancel.connect("clicked", lambda *_: self.close())
        self.add_btn = Gtk.Button(label="Import")
        self.add_btn.add_css_class("suggested-action")
        self.add_btn.connect("clicked", self._submit)
        header.pack_start(cancel)
        header.pack_end(self.add_btn)
        view.add_top_bar(header)
        self.err = Adw.Banner(revealed=False)
        view.add_top_bar(self.err)
        page = Adw.PreferencesPage()
        g = Adw.PreferencesGroup(title="Share links",
                                 description="One per line: vless://, vmess://, trojan:// or ss://. An Xray config (JSON) "
                                             "or a whole subscription text works too.")
        self.text = Gtk.TextView(wrap_mode=Gtk.WrapMode.CHAR, monospace=True, top_margin=8, bottom_margin=8,
                                 left_margin=8, right_margin=8)
        sc = Gtk.ScrolledWindow(min_content_height=130, hscrollbar_policy=Gtk.PolicyType.NEVER)
        sc.set_child(self.text)
        frame = Gtk.Frame()
        frame.set_child(sc)
        g.add(frame)
        pick = Gtk.Button(label="Load from a File…", halign=Gtk.Align.START, margin_top=6)
        pick.connect("clicked", self._pick)
        g.add(pick)
        page.add(g)
        g2 = Adw.PreferencesGroup(title="Subscription",
                                  description="A web address that lists servers. Use Refresh later to update the list.")
        self.url = Adw.EntryRow(title="Subscription URL (https://…)")
        self.group = Adw.EntryRow(title="Group name (optional)")
        g2.add(self.url)
        g2.add(self.group)
        page.add(g2)
        view.set_content(page)
        self.set_content(view)

    def _pick(self, *_):
        from .app import choose_files

        def got(files):
            try:
                with open(files[0], errors="replace") as fh:
                    self.text.get_buffer().set_text(fh.read(5 << 20))
            except OSError as e:
                self._error(e)
        choose_files(self, "Choose a file with proxy links", got, multiple=False)

    def _error(self, msg, *_):
        self.err.set_title(str(msg))
        self.err.set_revealed(True)
        self.add_btn.set_sensitive(True)

    def _submit(self, *_):
        buf = self.text.get_buffer()
        text = buf.get_text(buf.get_start_iter(), buf.get_end_iter(), False).strip()
        url = self.url.get_text().strip()
        group = self.group.get_text().strip()
        if not text and not url:
            return self._error("Paste a link or enter a subscription URL")
        if url and not re.match(r"^https?://", url, re.I):
            return self._error("The subscription URL must start with http:// or https://")
        self.add_btn.set_sensitive(False)

        def work():
            total = {"added": 0, "updated": 0, "removed": 0, "skipped": 0, "errors": []}
            try:
                batches = []
                if text:
                    batches.append({"text": text, "group": group})
                if url:
                    batches.append({"text": fetch(url), "source": url,
                                    "group": group or re.sub(r"^https?://([^/]+).*$", r"\1", url)})
                from ..ipc import Client
                for b in batches:
                    res = Client(timeout=60).call("proxy.import", **b)
                    for k in ("added", "updated", "removed", "skipped"):
                        total[k] += res[k]
                    total["errors"] += res["errors"]
            except Exception as e:  # noqa: BLE001  (network, daemon and parsing errors all end up in the banner)
                GLib.idle_add(self._error, e)
                return
            GLib.idle_add(self._done, total)
        threading.Thread(target=work, daemon=True).start()

    def _done(self, total):
        n = total["added"] + total["updated"]
        if not n and not total["skipped"]:
            return self._error("; ".join(total["errors"]) or "Nothing was imported")
        self.parent_win.toast("Proxies: %d new, %d updated%s" % (total["added"], total["updated"],
                                                                  ", %d skipped" % len(total["errors"]) if total["errors"] else ""))
        self.on_done()
        self.close()


class ProxyEditDialog(Adw.Window):
    def __init__(self, parent, rpc, proxy, on_done):
        super().__init__(transient_for=parent, modal=True, default_width=420, default_height=360, title="Edit Proxy")
        close_keys(self)
        self.rpc, self.proxy, self.on_done = rpc, proxy, on_done
        view = Adw.ToolbarView()
        header = Adw.HeaderBar(show_end_title_buttons=False, show_start_title_buttons=False)
        cancel = Gtk.Button(label="Cancel")
        cancel.connect("clicked", lambda *_: self.close())
        save = Gtk.Button(label="Save")
        save.add_css_class("suggested-action")
        save.connect("clicked", self._save)
        header.pack_start(cancel)
        header.pack_end(save)
        view.add_top_bar(header)
        page = Adw.PreferencesPage()
        g = Adw.PreferencesGroup()
        self.name = Adw.EntryRow(title="Name")
        self.name.set_text(proxy["name"])
        self.group = Adw.EntryRow(title="Group")
        self.group.set_text(proxy.get("group") or "")
        self.notes = Adw.EntryRow(title="Notes")
        self.notes.set_text(proxy.get("notes") or "")
        for r in (self.name, self.group, self.notes):
            g.add(r)
        page.add(g)
        view.set_content(page)
        self.set_content(view)

    def _save(self, *_):
        name = self.name.get_text().strip()
        if not name:
            return
        self.rpc("proxy.update", lambda *_: (self.on_done(), self.close()), None, ident=self.proxy["id"],
                 changes={"name": name, "group": self.group.get_text().strip(), "notes": self.notes.get_text()})


class ProxyPage(Gtk.Box):
    """Controls (on/off, path, mode) on top, the list of proxies below."""

    def __init__(self, window, rpc):
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self.win, self.rpc = window, rpc
        self.proxies, self.status, self.latency = [], {}, {}
        self._quiet = False
        self._rows = {}

        # ---- controls
        self.banner = Adw.Banner(title="xray is not installed, so proxies cannot start. Install it with: sudo ./install.sh --xray-only",
                                 revealed=False)
        self.append(self.banner)
        ctl = Adw.PreferencesGroup()
        self.enable = Adw.SwitchRow(title="Use the proxy", subtitle="Off")
        self.enable.connect("notify::active", self._on_enable)
        ctl.add(self.enable)
        self.order = Adw.ComboRow(title="Path of your traffic", model=Gtk.StringList.new([o[1] for o in ORDERS]))
        self.order.connect("notify::selected", self._on_order)
        ctl.add(self.order)
        self.mode = Adw.ComboRow(title="Mode", model=Gtk.StringList.new([m[1] for m in MODES]))
        self.mode.connect("notify::selected", self._on_mode)
        ctl.add(self.mode)
        self.addr = Adw.ActionRow(title="Local addresses", subtitle="–", subtitle_selectable=True)
        copy_socks = Gtk.Button(label="Copy SOCKS5", valign=Gtk.Align.CENTER)
        copy_socks.connect("clicked", lambda *_: self._copy("socks"))
        copy_http = Gtk.Button(label="Copy HTTP", valign=Gtk.Align.CENTER)
        copy_http.connect("clicked", lambda *_: self._copy("http"))
        self.addr.add_suffix(copy_socks)
        self.addr.add_suffix(copy_http)
        ctl.add(self.addr)
        adv = Adw.ExpanderRow(title="Ports and DNS")
        self.socks_port = Adw.SpinRow.new_with_range(1024, 65535, 1)
        self.socks_port.set_title("SOCKS5 port")
        self.http_port = Adw.SpinRow.new_with_range(1024, 65535, 1)
        self.http_port.set_title("HTTP port")
        self.dns = Adw.EntryRow(title="DNS server for system-wide mode", show_apply_button=True)
        self.udp = Adw.ComboRow(title="Other UDP in system-wide mode",
                                model=Gtk.StringList.new(["Block (nothing leaks around the proxy)", "Let it bypass the proxy"]))
        for r in (self.socks_port, self.http_port):
            r.connect("notify::value", self._on_ports)
            adv.add_row(r)
        self.dns.connect("apply", lambda r: self._set(dns=r.get_text().strip()))
        self.udp.connect("notify::selected", lambda r, _p: self._set(udp=["block", "direct"][r.get_selected()]) if not self._quiet else None)
        adv.add_row(self.dns)
        adv.add_row(self.udp)
        ctl.add(adv)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.append(ctl)

        # ---- list
        self.search = Gtk.SearchEntry(placeholder_text="Search proxies")
        self.search.connect("search-changed", lambda *_: self.listbox.invalidate_filter())
        top = Gtk.Box(spacing=6)
        self.ping = Gtk.Button(label="Test Latency")
        self.ping.connect("clicked", self._on_ping)
        self.refresh_btn = Gtk.Button(label="Refresh Subscriptions", visible=False)
        self.refresh_btn.connect("clicked", self._on_refresh)
        self.add_btn = Gtk.Button(label="Add Proxy")
        self.add_btn.add_css_class("suggested-action")
        self.add_btn.connect("clicked", lambda *_: ProxyAddDialog(self.win, self.rpc, self.reload).present())
        spacer = Gtk.Box(hexpand=True)
        for w in (self.ping, self.refresh_btn, spacer, self.add_btn):
            top.append(w)
        # MULTIPLE gives Ctrl+click (toggle one), Shift+click (range) and Ctrl+A, like the VPN servers list
        self.listbox = Gtk.ListBox(selection_mode=Gtk.SelectionMode.MULTIPLE, activate_on_single_click=False)
        self.listbox.add_css_class("boxed-list")
        self.listbox.set_filter_func(self._filter)
        self.listbox.set_sort_func(self._sort)
        self.listbox.set_header_func(self._header)
        self.listbox.connect("selected-rows-changed", self._on_selection_changed)
        keys = Gtk.EventControllerKey()
        keys.connect("key-pressed", self._on_list_key)
        self.listbox.add_controller(keys)
        self.empty = Adw.StatusPage(icon_name="network-server-symbolic", title="No Proxies",
                                    description="Add VLESS, VMess, Trojan or Shadowsocks links, or a subscription.",
                                    vexpand=False)
        box.append(self.search)
        box.append(top)
        box.append(self.listbox)
        box.append(self.empty)
        clamp = Adw.Clamp(maximum_size=720, margin_top=12, margin_bottom=12, margin_start=12, margin_end=12,
                          valign=Gtk.Align.START)
        clamp.set_child(box)
        scroll = self.scroll = Gtk.ScrolledWindow(vexpand=True, hscrollbar_policy=Gtk.PolicyType.NEVER)
        scroll.set_child(clamp)
        self.append(scroll)
        self._sig = None
        # selection bar: appears as soon as something is selected
        self.sel_label = Gtk.Label(label="", hexpand=True, xalign=0, margin_start=6)
        sel_all = Gtk.Button(label="Select All")
        sel_all.connect("clicked", lambda *_: self.listbox.select_all())
        sel_none = Gtk.Button(label="Clear")
        sel_none.connect("clicked", lambda *_: self.listbox.unselect_all())
        self.sel_remove = Gtk.Button(label="Remove…")
        self.sel_remove.add_css_class("destructive-action")
        self.sel_remove.connect("clicked", lambda *_: self._remove_selected())
        bar = Gtk.ActionBar()
        bar.pack_start(self.sel_label)
        bar.pack_end(self.sel_remove)
        bar.pack_end(sel_none)
        bar.pack_end(sel_all)
        self.sel_bar = Gtk.Revealer(child=bar, reveal_child=False, transition_type=Gtk.RevealerTransitionType.SLIDE_UP)
        self.append(self.sel_bar)

    # ---- data in
    def reload(self, *_):
        self.rpc("proxy.list", self.update_list, None)
        self.rpc("proxy.status", self.update_status, None)
        self.rpc("proxy.sources", lambda s: self.refresh_btn.set_visible(bool(s)), None)

    def update_list(self, proxies):
        self.proxies = proxies
        sig = [(p["id"], p["name"], p["protocol"], p["server"], p["port"], p.get("group", "")) for p in proxies]
        if sig == self._sig:
            # nothing but, perhaps, the chosen proxy changed: leave the rows (and the scroll position) alone
            for pid, row in self._rows.items():
                want = any(p["id"] == pid and p.get("selected") for p in proxies)
                if row.use.get_active() != want:
                    self._quiet = True
                    row.use.set_active(want)
                    self._quiet = False
            return
        self._sig = sig
        adj = self.scroll.get_vadjustment()
        pos = adj.get_value()
        keep = {r.proxy["id"] for r in self.listbox.get_selected_rows()}
        old = self._rows
        for r in old.values():
            self.listbox.remove(r)
        self._rows = {}
        for p in proxies:
            row = self._make_row(p)
            self._rows[p["id"]] = row
            self.listbox.append(row)
            if p["id"] in keep:
                self.listbox.select_row(row)
        self.empty.set_visible(not proxies)
        self.listbox.set_visible(bool(proxies))
        self.search.set_visible(bool(proxies))
        restore_scroll(adj, pos)                          # a rebuilt list must not throw the user back to the top

    def update_status(self, st):
        self.status = st
        self._quiet = True
        self.banner.set_revealed(not st["installed"])
        self.enable.set_active(st["enabled"])
        self.order.set_selected(next((i for i, o in enumerate(ORDERS) if o[0] == st["order"]), 0))
        self.order.set_subtitle(next((o[2] for o in ORDERS if o[0] == st["order"]), ""))
        self.mode.set_selected(next((i for i, m in enumerate(MODES) if m[0] == st["mode"]), 0))
        self.mode.set_subtitle(next((m[2] for m in MODES if m[0] == st["mode"]), "")
                               + ("" if st["system_ok"] else "  (needs Linux with nft)"))
        self.mode.set_visible(st["order"] != "proxy_vpn")
        self.socks_port.set_value(st["socks_port"])
        self.http_port.set_value(st["http_port"])
        self.dns.set_text(st["dns"])
        self.udp.set_selected(0 if st["udp"] == "block" else 1)
        self.addr.set_subtitle("SOCKS5 127.0.0.1:%d    HTTP 127.0.0.1:%d" % (
            st["socks"] or st["socks_port"], st["http"] or st["http_port"]) if st["order"] != "proxy_vpn"
            else "Not used: in this path the proxy only carries the VPN connection")
        if st["error"]:
            sub = "Error: %s" % st["error"]
        elif st["running"]:
            sub = "Running%s" % (" – carrying the VPN connection" if st["carrier"] else
                                 (" – %s" % st["name"] if st["name"] else ""))
        elif st["enabled"] and st["order"] == "vpn_proxy":
            sub = "Waiting for the VPN to connect"
        elif st["enabled"] and st["order"] == "proxy_vpn":
            sub = "Starts with the next VPN connection"
        elif st["enabled"]:
            sub = "Starting…"
        else:
            sub = "Off" if st["name"] else "Off – choose a proxy below"
        self.enable.set_subtitle(GLib.markup_escape_text(sub))
        for pid, row in self._rows.items():
            if row.use.get_active() != (pid == st["selected"]):
                row.use.set_active(pid == st["selected"])
        self._quiet = False

    # ---- rows
    def _make_row(self, p):
        row = Adw.ActionRow(title=GLib.markup_escape_text(p["name"]),
                            subtitle=GLib.markup_escape_text("%s  ·  %s:%s" % (p["protocol"], p["server"], p["port"])))
        row.proxy = p
        use = Gtk.CheckButton(valign=Gtk.Align.CENTER, tooltip_text="Use this proxy")
        use.set_active(bool(p.get("selected")))
        use.connect("toggled", self._on_use, p)
        row.use = use
        row.add_prefix(use)
        row.set_activatable(False)                 # a click on the row selects it (multi-select); "use" has its own button
        lat = Gtk.Label(label=self._lat_text(p["id"]), css_classes=["dim-label", "numeric"])
        row.lat = lat
        row.add_suffix(lat)
        edit = Gtk.Button(label="Edit…", valign=Gtk.Align.CENTER)
        edit.add_css_class("flat")
        edit.connect("clicked", lambda *_: ProxyEditDialog(self.win, self.rpc, p, self.reload).present())
        rm = Gtk.Button(label="Remove", valign=Gtk.Align.CENTER)
        rm.add_css_class("flat")
        rm.add_css_class("error")
        rm.connect("clicked", lambda *_: self._remove(p))
        row.add_suffix(edit)
        row.add_suffix(rm)
        return row

    def _lat_text(self, pid):
        ms = self.latency.get(pid, "?")
        return "" if ms == "?" else ("%d ms" % ms if ms else "unreachable")

    def _filter(self, row):
        q = self.search.get_text().lower()
        p = row.proxy
        return not q or q in p["name"].lower() or q in p["protocol"] or q in (p.get("group") or "").lower() \
            or q in p["server"].lower()

    def _sort(self, a, b):
        ka = ((a.proxy.get("group") or "~").lower(), a.proxy["name"].lower())
        kb = ((b.proxy.get("group") or "~").lower(), b.proxy["name"].lower())
        return (ka > kb) - (ka < kb)

    def _header(self, row, before):
        g = row.proxy.get("group") or ""
        prev = (before.proxy.get("group") or "") if before else None
        if g and g != prev:
            lbl = Gtk.Label(label=g, xalign=0, margin_start=12, margin_top=10, margin_bottom=4)
            lbl.add_css_class("heading")
            row.set_header(lbl)
        else:
            row.set_header(None)

    # ---- actions
    def _set(self, **kw):
        if self._quiet:
            return
        self.rpc("proxy.set", self.update_status, self._fail, **kw)

    def _fail(self, msg, *_):
        self.win.toast(msg)
        self.rpc("proxy.status", self.update_status, None)       # put the controls back to what is really set

    def _on_enable(self, row, _p):
        if not self._quiet and row.get_active() != self.status.get("enabled"):
            self._set(enabled=row.get_active())

    def _on_order(self, row, _p):
        i = row.get_selected()
        if not self._quiet and 0 <= i < len(ORDERS) and ORDERS[i][0] != self.status.get("order"):
            self._set(order=ORDERS[i][0])

    def _on_mode(self, row, _p):
        i = row.get_selected()
        if not self._quiet and 0 <= i < len(MODES) and MODES[i][0] != self.status.get("mode"):
            self._set(mode=MODES[i][0])

    def _on_ports(self, *_):
        if self._quiet:
            return
        s, h = int(self.socks_port.get_value()), int(self.http_port.get_value())
        if (s, h) != (self.status.get("socks_port"), self.status.get("http_port")):
            if s == h:
                return
            self._set(socks_port=s, http_port=h)

    def _on_use(self, btn, p):
        if self._quiet:
            return
        if not btn.get_active():
            if p["id"] == self.status.get("selected"):          # a radio button: the chosen one cannot be un-chosen
                self._quiet = True
                btn.set_active(True)
                self._quiet = False
            return
        if p["id"] == self.status.get("selected"):
            return
        # only the status is needed back: reloading the whole list would rebuild the rows under the user's cursor
        self.rpc("proxy.select", lambda *_: self.rpc("proxy.status", self.update_status, None), self._fail, ident=p["id"])

    def _copy(self, kind):
        st = self.status
        port = st.get(kind) or st.get(kind + "_port")
        text = ("socks5://127.0.0.1:%d" if kind == "socks" else "http://127.0.0.1:%d") % port
        disp = Gdk.Display.get_default()
        if disp:
            disp.get_clipboard().set(text)
            self.win.toast("Copied %s" % text)

    def _on_ping(self, *_):
        self.ping.set_sensitive(False)

        def done(res):
            self.latency = res
            for pid, row in self._rows.items():
                row.lat.set_label(self._lat_text(pid))
            self.ping.set_sensitive(True)
        self.rpc("proxy.latency", done, lambda *a: (self.ping.set_sensitive(True), self.win.toast(a[0])))

    def _on_refresh(self, *_):
        self.refresh_btn.set_sensitive(False)

        def work():
            from ..ipc import Client
            msg = ""
            try:
                cl = Client(timeout=60)
                tot = {"added": 0, "updated": 0, "removed": 0}
                for s in cl.call("proxy.sources"):
                    res = cl.call("proxy.import", text=fetch(s["source"]), source=s["source"])
                    for k in tot:
                        tot[k] += res[k]
                msg = "Subscriptions refreshed: %(added)d new, %(updated)d updated, %(removed)d removed" % tot
            except Exception as e:  # noqa: BLE001
                msg = "Refresh failed: %s" % e
            GLib.idle_add(lambda: (self.refresh_btn.set_sensitive(True), self.win.toast(msg), self.reload()))
        threading.Thread(target=work, daemon=True).start()

    # ---- selection / bulk actions
    def selected_proxies(self):
        return [r.proxy for r in self.listbox.get_selected_rows()]

    def _on_selection_changed(self, *_):
        n = len(self.listbox.get_selected_rows())
        self.sel_label.set_label("%d selected" % n)
        self.sel_bar.set_reveal_child(n > 0)

    def _on_list_key(self, _c, keyval, _code, _state):
        if keyval == Gdk.KEY_Delete:
            self._remove_selected()
            return True
        if keyval == Gdk.KEY_Escape and self.listbox.get_selected_rows():
            self.listbox.unselect_all()
            return True
        return False

    def _remove_selected(self):
        sel = self.selected_proxies()
        if sel:
            self._remove_many(sel)

    def _remove(self, p):
        self._remove_many([p])

    def _remove_many(self, proxies):
        if not proxies:
            return
        if len(proxies) == 1:
            heading, body = "Remove %s?" % proxies[0]["name"], "The proxy will be deleted."
        else:
            names = [p["name"] for p in proxies]
            shown = ", ".join(names[:6]) + (" and %d more" % (len(names) - 6) if len(names) > 6 else "")
            heading, body = "Remove %d proxies?" % len(proxies), "%s\n\nThe proxies will be deleted." % shown
        if any(p["id"] == self.status.get("selected") for p in proxies) and self.status.get("enabled"):
            body += " The proxy in use will be switched off."
        d = Adw.MessageDialog(transient_for=self.win, heading=heading, body=body)
        d.add_response("cancel", "Cancel")
        d.add_response("remove", "Remove")
        d.set_response_appearance("remove", Adw.ResponseAppearance.DESTRUCTIVE)
        ids = [p["id"] for p in proxies]
        d.connect("response", lambda _d, r: r == "remove" and self.do_remove(ids))
        d.present()

    def do_remove(self, ids):
        def done(res):
            gone = len(res.get("removed", []))
            if res.get("failed"):
                self.win.toast("Removed %d, %d failed: %s" % (gone, len(res["failed"]), res["failed"][0]["error"]))
            else:
                self.win.toast("Removed %d prox%s" % (gone, "y" if gone == 1 else "ies"))
            self.reload()
        self.rpc("proxy.remove", done, self._fail, ids=ids)

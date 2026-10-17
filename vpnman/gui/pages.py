"""Schedule and App-bypass pages (plus their dialogs) for the main window."""

import collections
import time

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib, GObject, Gtk  # noqa: E402

from .. import apps as appmod, schedule as sched  # noqa: E402
from ..settings import DNS_PRESETS  # noqa: E402
from .keys import close_keys  # noqa: E402

try:                                    # drawing needs pycairo (Debian/Ubuntu: python3-gi-cairo); without it the graph
    gi.require_foreign("cairo")         # degrades to the text line instead of failing
    HAVE_CAIRO = True
except Exception:                       # noqa: BLE001
    HAVE_CAIRO = False

FALLBACK_ICON = "application-x-executable-symbolic"


def icon_for(name):
    """The launcher's icon if the theme has it, else a generic one (avoids the 'missing image' placeholder)."""
    from gi.repository import Gdk
    display = Gdk.Display.get_default()
    if name and display and (Gtk.IconTheme.get_for_display(display).has_icon(name) or name.startswith("/")):
        return name
    return FALLBACK_ICON


def _clear(group, rows):
    for r in rows:
        group.remove(r)
    rows.clear()


class TimeRow(Adw.ActionRow):
    """24-hour time entry: two spin buttons."""

    def __init__(self, title, hhmm="08:00"):
        super().__init__(title=title)
        h, m = divmod(sched.minutes(hhmm), 60)
        self.hour = Gtk.SpinButton.new_with_range(0, 23, 1)
        self.minute = Gtk.SpinButton.new_with_range(0, 59, 1)
        for w, v in ((self.hour, h), (self.minute, m)):
            w.set_value(v)
            w.set_wrap(True)
            w.set_valign(Gtk.Align.CENTER)
            w.set_width_chars(2)
            w.set_orientation(Gtk.Orientation.VERTICAL)
            w.connect("output", lambda s: s.set_text("%02d" % s.get_value_as_int()) or True)
        colon = Gtk.Label(label=":", valign=Gtk.Align.CENTER)
        for w in (self.hour, colon, self.minute):
            self.add_suffix(w)

    def value(self):
        return "%02d:%02d" % (self.hour.get_value_as_int(), self.minute.get_value_as_int())


class ScheduleDialog(Adw.Window):
    def __init__(self, parent, profiles, entry=None, on_done=None):
        super().__init__(transient_for=parent, modal=True, default_width=460, default_height=620)
        close_keys(self)
        self.entry = dict(entry or {"enabled": True, "days": [0, 1, 2, 3, 4], "start": "08:00", "end": "",
                                    "profile": "", "name": ""})
        self.on_done = on_done
        self.set_title("Edit Schedule" if entry else "Add Schedule")
        view = Adw.ToolbarView()
        header = Adw.HeaderBar(show_end_title_buttons=False, show_start_title_buttons=False)
        cancel = Gtk.Button(label="Cancel")
        cancel.connect("clicked", lambda *_: self.close())
        save = Gtk.Button(label="Save")
        save.add_css_class("suggested-action")
        save.connect("clicked", self._submit)
        header.pack_start(cancel)
        header.pack_end(save)
        view.add_top_bar(header)
        page = Adw.PreferencesPage()
        view.set_content(page)
        self.set_content(view)

        g = Adw.PreferencesGroup()
        self.name = Adw.EntryRow(title="Name (optional)")
        self.name.set_text(self.entry.get("name", ""))
        g.add(self.name)
        page.add(g)

        g = Adw.PreferencesGroup(title="Days")
        box = Gtk.Box(spacing=0, homogeneous=True, hexpand=True)
        box.add_css_class("linked")
        self.day_btns = []
        for i, d in enumerate(sched.DAYS):
            b = Gtk.ToggleButton(label=d)
            b.set_active(i in self.entry.get("days", []))
            self.day_btns.append(b)
            box.append(b)
        g.add(box)
        page.add(g)

        g = Adw.PreferencesGroup(title="Time", description="Uses this computer's local time.")
        self.start = TimeRow("Connect at", self.entry.get("start") or "08:00")
        g.add(self.start)
        self.use_end = Adw.SwitchRow(title="Disconnect again", subtitle="Otherwise the VPN stays up after connecting")
        self.use_end.set_active(bool(self.entry.get("end")))
        g.add(self.use_end)
        self.end = TimeRow("Disconnect at", self.entry.get("end") or "17:00")
        self.use_end.bind_property("active", self.end, "sensitive", GObject.BindingFlags.SYNC_CREATE)
        g.add(self.end)
        page.add(g)

        g = Adw.PreferencesGroup(title="Server")
        self.choices = [("", "Last used"), ("fastest", "Fastest")] + [(p["id"], p["name"]) for p in profiles]
        self.profile = Adw.ComboRow(title="Connect to", model=Gtk.StringList.new([c[1] for c in self.choices]))
        cur = self.entry.get("profile", "")
        ids = [c[0] for c in self.choices]
        by_name = {c[1]: c[0] for c in self.choices}
        cur = cur if cur in ids else by_name.get(cur, "")
        self.profile.set_selected(ids.index(cur) if cur in ids else 0)
        g.add(self.profile)
        page.add(g)

    def _submit(self, *_):
        days = [i for i, b in enumerate(self.day_btns) if b.get_active()]
        if not days:
            self.add_toast_fallback("Pick at least one day")
            return
        e = dict(self.entry, name=self.name.get_text().strip(), days=days, start=self.start.value(),
                 end=self.end.value() if self.use_end.get_active() else "",
                 profile=self.choices[self.profile.get_selected()][0])
        if self.on_done:
            self.on_done(e)
        self.close()

    def add_toast_fallback(self, text):
        d = Adw.MessageDialog(transient_for=self, heading=text)
        d.add_response("ok", "OK")
        d.present()


class SchedulePage(Adw.PreferencesPage):
    def __init__(self, win, rpc):
        super().__init__()
        self.win, self.rpc = win, rpc
        self.state = {"enabled": True, "entries": []}
        self._rows = []
        self._quiet = False
        g = Adw.PreferencesGroup(
            title="Scheduled Connections",
            description="Connect the VPN automatically at the times you choose, and optionally disconnect again. "
                        "The schedule is run by the background service, so it works while this window is closed.")
        self.enabled = Adw.SwitchRow(title="Use schedule")
        self.enabled.connect("notify::active", self._on_enabled)
        g.add(self.enabled)
        self.add(g)
        self.group = Adw.PreferencesGroup(title="Schedules")
        add = Gtk.Button(label="Add Schedule", valign=Gtk.Align.CENTER)
        add.add_css_class("suggested-action")
        add.connect("clicked", lambda *_: self.edit(None))
        self.group.set_header_suffix(add)
        self.add(self.group)

    def update(self, st):
        self.state = st
        self._quiet = True
        self.enabled.set_active(st["enabled"])
        self._quiet = False
        _clear(self.group, self._rows)
        if not st["entries"]:
            row = Adw.ActionRow(title="Nothing scheduled", subtitle="Add a schedule to connect at set times.")
            row.add_css_class("dim-label")
            self.group.add(row)
            self._rows.append(row)
        for e in st["entries"]:
            self._rows.append(self._row(e))
            self.group.add(self._rows[-1])

    def _row(self, e):
        title = e.get("name") or e["summary"]
        sub = [e["summary"] if e.get("name") else "", self._profile_label(e.get("profile", ""))]
        if e.get("active"):
            sub.append("active now")
        elif e.get("enabled") and e.get("next_in"):
            sub.append("next in %s" % _eta(e["next_in"]))
        row = Adw.ActionRow(title=GLib.markup_escape_text(title),
                            subtitle=GLib.markup_escape_text(" · ".join(x for x in sub if x)), activatable=True)
        row.connect("activated", lambda *_: self.edit(e))
        sw = Gtk.Switch(active=e.get("enabled", True), valign=Gtk.Align.CENTER, tooltip_text="Enabled")
        sw.connect("notify::active", lambda s, _p: self._toggle(e, s.get_active()))
        row.add_suffix(sw)
        rm = Gtk.Button(icon_name="user-trash-symbolic", valign=Gtk.Align.CENTER, tooltip_text="Delete")
        rm.add_css_class("flat")
        rm.connect("clicked", lambda *_: self._save([x for x in self.state["entries"] if x["id"] != e["id"]]))
        row.add_suffix(rm)
        return row

    def _profile_label(self, ident):
        if ident in ("", "last"):
            return "last used server"
        if ident == "fastest":
            return "fastest server"
        for p in self.win.profiles:
            if ident in (p["id"], p["name"]):
                return p["name"]
        return ident

    def _on_enabled(self, row, _p):
        if not self._quiet:
            self.rpc("schedule.set", self.update, self.win._fail, enabled=row.get_active())

    def _toggle(self, e, on):
        if not self._quiet and e.get("enabled") != on:
            self._save([dict(x, enabled=on) if x["id"] == e["id"] else x for x in self.state["entries"]])

    def edit(self, entry):
        def done(new):
            cur = list(self.state["entries"])
            if entry:
                cur = [new if x["id"] == entry["id"] else x for x in cur]
            else:
                cur.append(new)
            self._save(cur)
        ScheduleDialog(self.win, self.win.profiles, entry, done).present()

    def _save(self, entries):
        keys = ("id", "name", "enabled", "days", "start", "end", "profile")
        self.rpc("schedule.set", lambda st: (self.update(st), self.win.toast("Schedule saved")), self.win._fail,
                 entries=[{k: e[k] for k in keys if k in e} for e in entries])


def _eta(minutes):
    h, m = divmod(int(minutes), 60)
    d, h = divmod(h, 24)
    return " ".join(x for x in ("%dd" % d if d else "", "%dh" % h if h else "", "%dm" % m if m or not (d or h) else "") if x)


class AppPicker(Adw.Window):
    """Choose installed applications (or type a program name) for the bypass list."""

    def __init__(self, parent, already, on_done):
        super().__init__(transient_for=parent, modal=True, default_width=480, default_height=640)
        close_keys(self)
        self.on_done, self.checks, self.have = on_done, {}, set(already)
        self.set_title("Add Apps")
        view = Adw.ToolbarView()
        header = Adw.HeaderBar(show_end_title_buttons=False, show_start_title_buttons=False)
        cancel = Gtk.Button(label="Cancel")
        cancel.connect("clicked", lambda *_: self.close())
        add = Gtk.Button(label="Add")
        add.add_css_class("suggested-action")
        add.connect("clicked", self._submit)
        header.pack_start(cancel)
        header.pack_end(add)
        view.add_top_bar(header)
        self.search = Gtk.SearchEntry(placeholder_text="Search installed apps", margin_start=12, margin_end=12,
                                      margin_top=6, margin_bottom=6)
        self.search.connect("search-changed", lambda *_: self.listbox.invalidate_filter())
        view.add_top_bar(self.search)
        self.listbox = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE, margin_start=12, margin_end=12,
                                   margin_bottom=12)
        self.listbox.add_css_class("boxed-list")
        self.listbox.set_filter_func(self._filter)
        self.custom = Adw.EntryRow(title="Other program (process name, e.g. firefox)")
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.append(self.listbox)
        cbox = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE, margin_start=12, margin_end=12, margin_bottom=12)
        cbox.add_css_class("boxed-list")
        cbox.append(self.custom)
        box.append(cbox)
        sc = Gtk.ScrolledWindow(vexpand=True, hscrollbar_policy=Gtk.PolicyType.NEVER)
        sc.set_child(box)
        view.set_content(sc)
        self.set_content(view)
        self.entries = {}
        for a in appmod.discover():
            if a["id"] in self.have:
                continue
            self.entries[a["id"]] = a
            row = Adw.ActionRow(title=GLib.markup_escape_text(a["name"]),
                                subtitle=GLib.markup_escape_text(a.get("comment") or ", ".join(a["match"])))
            row.entry = a
            icon = Gtk.Image(icon_name=icon_for(a.get("icon")), pixel_size=32)
            row.add_prefix(icon)
            chk = Gtk.CheckButton(valign=Gtk.Align.CENTER)
            row.add_suffix(chk)
            row.set_activatable_widget(chk)
            self.checks[a["id"]] = chk
            self.listbox.append(row)

    def _filter(self, row):
        q = self.search.get_text().strip().lower()
        a = getattr(row, "entry", None)
        return not q or not a or q in a["name"].lower() or any(q in m.lower() for m in a["match"])

    def _submit(self, *_):
        picked = [self.entries[i] for i, c in self.checks.items() if c.get_active()]
        text = self.custom.get_text().strip()
        if text:
            try:
                picked.append(appmod.custom_entry(text))
            except ValueError:
                pass
        if picked:
            self.on_done(picked)
        self.close()


def bypass_details(st):
    """What the app bypass is doing right now, as (title, text) pairs: one per app with its processes, then the way out,
    the DNS of those apps and the addresses that skip the VPN.  Shared by the Apps tab and the Log tab."""
    out = []
    by_app = {}
    for p in st.get("processes") or []:
        by_app.setdefault(p["app"], []).append(p)
    for a in st.get("apps") or []:
        procs = by_app.pop(a["name"], [])
        out.append((a["name"], ", ".join("%s (%d)" % (p["name"], p["pid"]) for p in procs) if procs else "not running"))
    for app, procs in sorted(by_app.items()):
        out.append((app, ", ".join("%s (%d)" % (p["name"], p["pid"]) for p in procs)))
    route = st.get("route")
    if route:
        out.append(("Way out", "%s%s" % (route.get("device") or "?",
                                          " via %s" % route["gateway"] if route.get("gateway") else "")))
    dns = st.get("dns_now") or []
    if st.get("active"):
        how = []
        if st.get("dns"):
            how.append("chosen in this tab")
        if st.get("dns_nss"):
            how.append("lookups through systemd-resolved are switched to its stub")
        out.append(("DNS", (", ".join(dns) or "unchanged") + (" (%s)" % "; ".join(how) if how else "")))
    if st.get("routes"):
        out.append(("Addresses", ", ".join(st["routes"])))
    return out


class BypassDns:
    """The name server the programs that skip the VPN use: automatic (the one the computer had before the VPN), a preset
    or your own.  ``done(status)`` gets the new app-bypass status after a change."""

    def __init__(self, rpc, fail, done, title="DNS for apps that skip the VPN"):
        self.rpc, self.fail, self.done = rpc, fail, done
        self._quiet = False
        self.labels = ["Automatic (your normal DNS)"] + [n for n, _ in DNS_PRESETS] + ["Custom…"]
        self.row = Adw.ComboRow(title=title, model=Gtk.StringList.new(self.labels))
        self.row.add_prefix(Gtk.Image.new_from_icon_name("network-server-symbolic"))
        self.row.connect("notify::selected", self._on_choice)
        self.entry = Adw.EntryRow(title="Custom DNS servers (comma separated, the first is used)", show_apply_button=True,
                                  visible=False)
        self.entry.connect("apply", lambda r: self._save(self._parse(r.get_text())))
        self.widgets = (self.row, self.entry)

    @staticmethod
    def _parse(text):
        return [x.strip() for x in text.replace(";", ",").replace(" ", ",").split(",") if x.strip()]

    def _save(self, servers):
        self.rpc("split.set", self.done, self.fail, dns=servers)

    def _on_choice(self, row, _p):
        i, n = row.get_selected(), len(DNS_PRESETS)
        self.entry.set_visible(i == n + 1)
        if self._quiet:
            return
        if i == 0:
            self._save([])
        elif 1 <= i <= n:
            self._save(DNS_PRESETS[i - 1][1])
        elif self.entry.get_text():
            self._save(self._parse(self.entry.get_text()))

    def sync(self, st):
        n = len(DNS_PRESETS)
        servers = st.get("dns") or []
        idx = 0
        if servers:
            idx = n + 1
            for k, (_name, ips) in enumerate(DNS_PRESETS, 1):
                if ips == servers:
                    idx = k
        self._quiet = True
        self.row.set_selected(idx)
        self.entry.set_visible(idx == n + 1)
        if idx == n + 1 and self._parse(self.entry.get_text()) != servers:
            self.entry.set_text(", ".join(servers))
        self._quiet = False
        orig = st.get("dns_original") or []
        text = ", ".join(servers) if servers else ("now: " + ", ".join(orig) if orig else "your router")
        self.row.set_subtitle(GLib.markup_escape_text(text))
        for w in self.widgets:
            w.set_sensitive(st.get("supported", True))


class BypassPage(Adw.PreferencesPage):
    DNS_TEXT = ("The name server the listed apps ask while they skip the VPN. Everything inside the tunnel keeps using the "
                "VPN's or the DNS you chose on the main page.")
    DNS_CAVEAT = (" Apps that resolve names through systemd-resolved itself (most GNOME apps on Fedora) are not redirected: "
                  "they ask it directly, and it uses the VPN's DNS. Programs that read /etc/resolv.conf are.")
    DNS_NSS = (" While this is on, name lookups on this computer go to systemd-resolved's stub instead of its NSS module "
               "(/etc/nsswitch.conf is changed and restored when the bypass stops), so Firefox, GNOME apps and the rest can follow it.")

    def __init__(self, win, rpc):
        super().__init__()
        self.win, self.rpc = win, rpc
        self.state = {"apps": [], "enabled": True, "supported": True, "reason": "", "active": False}
        self._rows = []
        self.routes = []
        self._quiet = False
        self.banner = Adw.Banner(revealed=False)
        g = Adw.PreferencesGroup(
            title="Apps That Skip the VPN",
            description="While the VPN is connected, these programs - and anything they start - keep using your normal "
                        "internet connection. Everything else stays inside the tunnel.")
        self.enabled = Adw.SwitchRow(title="Exclude these apps from the VPN")
        self.enabled.connect("notify::active", self._on_enabled)
        g.add(self.enabled)
        self.mode = Adw.ComboRow(title="Listed apps", model=Gtk.StringList.new(
            ["Skip the VPN", "Are the only ones using the VPN (experimental)"]))
        self.mode.connect("notify::selected", self._on_mode)
        g.add(self.mode)
        # click to see what is bypassed right now: each app and its processes, the way out, the DNS
        self.status = Adw.ExpanderRow(title="Status")
        self._detail_rows, self._detail_key = [], None
        g.add(self.status)
        self.add(g)
        self.top_group = g
        self.dns = BypassDns(rpc, win._fail, lambda st: win._on_split_status(st))
        self.dns_group = dg = Adw.PreferencesGroup(title="DNS for These Apps", description=self.DNS_TEXT)
        for w in self.dns.widgets:
            dg.add(w)
        self.add(dg)
        self.group = Adw.PreferencesGroup(title="Apps")
        add = Gtk.Button(label="Add Apps…", valign=Gtk.Align.CENTER)
        add.add_css_class("suggested-action")
        add.connect("clicked", self._pick)
        self.group.set_header_suffix(add)
        self.add(self.group)

        self.addr_group = Adw.PreferencesGroup(
            title="Addresses That Skip the VPN",
            description="IP addresses, networks (10.0.0.0/8) or domain names that always use your normal connection - "
                        "for example a printer, a NAS or a work intranet. The kill switch never blocks them.")
        self.addr_entry = Adw.EntryRow(title="Add an address, network or domain", show_apply_button=True)
        self.addr_entry.connect("apply", self._add_address)
        self.addr_group.add(self.addr_entry)
        self.add(self.addr_group)
        self._addr_rows = []

    def update(self, st):
        self.state = st
        self.dns.sync(st)
        self.dns_group.set_description(self.DNS_TEXT + (
            self.DNS_CAVEAT if st.get("dns_caveat") else self.DNS_NSS if st.get("dns_nss") else ""))
        self._quiet = True
        self.enabled.set_active(st["enabled"])
        self.enabled.set_sensitive(st["supported"])
        self.mode.set_selected(1 if st.get("mode") == "include" else 0)
        self.mode.set_sensitive(st["supported"])
        self._quiet = False
        self.top_group.set_title("Apps That Use the VPN" if st.get("mode") == "include" else "Apps That Skip the VPN")
        self.top_group.set_description(
            "Only these programs - and anything they start - go through the VPN. Everything else on this computer "
            "uses your normal connection and is NOT protected." if st.get("mode") == "include" else
            "While the VPN is connected, these programs - and anything they start - keep using your normal "
            "internet connection. Everything else stays inside the tunnel.")
        if not st["supported"]:
            self.status.set_subtitle(GLib.markup_escape_text("Unavailable: " + st["reason"]))
        elif st["active"]:
            n = len(st.get("processes") or []) or st.get("moved", 0)
            self.status.set_subtitle("Active - %d process%s bypassing the VPN" % (n, "" if n == 1 else "es"))
        else:
            self.status.set_subtitle("Applies as soon as the VPN is connected")
        self._update_details(bypass_details(st) if st.get("active") else [])
        if st.get("routes", []) != self.routes:
            self._update_addresses(st.get("routes", []))
        apps_key = [(a["id"], a["name"], tuple(a["match"]), a.get("icon")) for a in st["apps"]]
        if apps_key == getattr(self, "_apps_key", None):
            return                                      # the list did not change: leave the rows alone
        self._apps_key = apps_key
        _clear(self.group, self._rows)
        if not st["apps"]:
            row = Adw.ActionRow(title="No apps yet", subtitle="Add Steam, Firefox or any other program.")
            row.add_css_class("dim-label")
            self.group.add(row)
            self._rows.append(row)
        for a in st["apps"]:
            row = Adw.ActionRow(title=GLib.markup_escape_text(a["name"]),
                                subtitle=GLib.markup_escape_text(", ".join(a["match"])))
            row.add_prefix(Gtk.Image(icon_name=icon_for(a.get("icon")), pixel_size=32))
            rm = Gtk.Button(icon_name="user-trash-symbolic", valign=Gtk.Align.CENTER, tooltip_text="Remove")
            rm.add_css_class("flat")
            rm.connect("clicked", lambda _b, x=a: self._save([y for y in self.state["apps"] if y["id"] != x["id"]]))
            row.add_suffix(rm)
            self.group.add(row)
            self._rows.append(row)

    def _update_details(self, details):
        if details == self._detail_key:
            return                                      # unchanged: keep the rows (and the reader's place) as they are
        self._detail_key = details
        for row in self._detail_rows:
            self.status.remove(row)
        self._detail_rows = []
        for title, text in details or [("Nothing to show", "The bypass runs while the VPN is connected")]:
            row = Adw.ActionRow(title=GLib.markup_escape_text(title), subtitle=GLib.markup_escape_text(text))
            row.add_css_class("property")
            row.set_subtitle_selectable(True)
            self.status.add_row(row)
            self._detail_rows.append(row)

    def _update_addresses(self, routes):
        self.routes = list(routes)
        _clear(self.addr_group, self._addr_rows)
        for r in self.routes:
            row = Adw.ActionRow(title=GLib.markup_escape_text(r))
            rm = Gtk.Button(icon_name="user-trash-symbolic", valign=Gtk.Align.CENTER, tooltip_text="Remove")
            rm.add_css_class("flat")
            rm.connect("clicked", lambda _b, x=r: self._save_routes([y for y in self.routes if y != x]))
            row.add_suffix(rm)
            self.addr_group.add(row)
            self._addr_rows.append(row)

    def _add_address(self, entry):
        text = entry.get_text().strip()
        if text:
            entry.set_text("")
            self._save_routes(self.routes + [x.strip() for x in text.replace(";", ",").split(",") if x.strip()])

    def _save_routes(self, routes):
        self.rpc("routes.set", lambda _res: (self.win.toast("Saved"), self.win.refresh(full=True)), self.win._fail,
                 entries=routes)

    def _on_enabled(self, row, _p):
        if not self._quiet:
            self.rpc("split.set", self.update, self.win._fail, enabled=row.get_active())

    def _on_mode(self, row, _p):
        if not self._quiet:
            self.rpc("split.set", self.update, self.win._fail, mode="include" if row.get_selected() == 1 else "exclude")

    def _pick(self, *_):
        AppPicker(self.win, [a["id"] for a in self.state["apps"]],
                  lambda picked: self._save(self.state["apps"] + picked)).present()

    def _save(self, apps):
        self.rpc("split.set", lambda st: (self.update(st), self.win.toast("App list saved")), self.win._fail, apps=apps)


# ----------------------------------------------------------------- traffic graph & history

def human(n):
    n = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or unit == "TiB":
            return ("%d %s" % (n, unit)) if unit == "B" else "%.1f %s" % (n, unit)
        n /= 1024


def graph_points(values, width, height, peak, pad=4):
    """Pixel points for a series (oldest first, right-aligned so new data scrolls in from the right)."""
    n = len(values)
    if n == 0:
        return []
    step = width / max(n - 1, 1) if n > 1 else 0
    peak = max(peak, 1.0)
    return [(width - (n - 1 - i) * step if n > 1 else width, height - pad - (v / peak) * (height - 2 * pad))
            for i, v in enumerate(values)]


class TrafficGraph(Gtk.Box):
    """Download / upload rate over the last two minutes."""
    RX = (0.21, 0.52, 0.89)
    TX = (0.15, 0.64, 0.41)

    def __init__(self, seconds=120):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self.rx, self.tx = collections.deque(maxlen=seconds), collections.deque(maxlen=seconds)
        self.area = Gtk.DrawingArea(content_height=96, hexpand=True)
        if HAVE_CAIRO:
            self.area.set_draw_func(self._draw)
        else:
            self.area.set_visible(False)
        self.legend = Gtk.Label(label="", xalign=0, css_classes=["dim-label", "caption"])
        self.append(self.area)
        self.append(self.legend)
        self._last = 0.0

    def push(self, rx_rate, tx_rate):
        now = time.monotonic()
        if now - self._last < 0.8:                       # status is refreshed more often than once a second
            return
        self._last = now
        self.rx.append(float(rx_rate))
        self.tx.append(float(tx_rate))
        self.legend.set_label("↓ %s/s    ↑ %s/s    peak %s/s (last 2 min)"
                              % (human(rx_rate), human(tx_rate), human(self.peak())))
        self.area.queue_draw()

    def reset(self):
        self.rx.clear()
        self.tx.clear()
        self.legend.set_label("")
        self.area.queue_draw()

    def peak(self):
        return max(list(self.rx) + list(self.tx) + [0.0])

    def _draw(self, area, cr, w, h):
        fg = area.get_color()
        cr.set_source_rgba(fg.red, fg.green, fg.blue, 0.12)
        for i in range(1, 4):                            # faint grid
            y = h * i / 4
            cr.move_to(0, y)
            cr.line_to(w, y)
        cr.set_line_width(1)
        cr.stroke()
        peak = self.peak()
        for series, (r, g, b) in ((self.rx, self.RX), (self.tx, self.TX)):
            pts = graph_points(list(series), w, h, peak)
            if len(pts) < 2:
                continue
            cr.move_to(pts[0][0], h)
            for x, y in pts:
                cr.line_to(x, y)
            cr.line_to(pts[-1][0], h)
            cr.close_path()
            cr.set_source_rgba(r, g, b, 0.18)
            cr.fill_preserve()
            cr.new_path()
            cr.move_to(*pts[0])
            for x, y in pts[1:]:
                cr.line_to(x, y)
            cr.set_source_rgba(r, g, b, 1)
            cr.set_line_width(2)
            cr.stroke()


class HistoryGroup(Adw.PreferencesGroup):
    def __init__(self, rpc, on_error):
        super().__init__(title="Recent Connections")
        self.rpc, self.on_error = rpc, on_error
        self._rows = []
        clear = Gtk.Button(label="Clear", valign=Gtk.Align.CENTER)
        clear.add_css_class("flat")
        clear.connect("clicked", lambda *_: self.rpc("history.clear", lambda *_: self.update([]), self.on_error))
        self.set_header_suffix(clear)
        self.set_visible(False)

    def update(self, rows):
        _clear(self, self._rows)
        self.set_visible(bool(rows))
        for r in rows[:8]:
            when = time.strftime("%b %d, %H:%M", time.localtime(r["start"]))
            d = r["duration"]
            dur = "%d:%02d:%02d" % (d // 3600, d % 3600 // 60, d % 60)
            row = Adw.ActionRow(title=GLib.markup_escape_text(r["profile"]),
                                subtitle=GLib.markup_escape_text("%s · %s · ↓ %s ↑ %s · %s" % (
                                    when, dur, human(r["rx"]), human(r["tx"]), r.get("reason", ""))))
            self.add(row)
            self._rows.append(row)

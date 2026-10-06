"""Schedule and App-bypass pages (plus their dialogs) for the main window."""

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib, GObject, Gtk  # noqa: E402

from .. import apps as appmod, schedule as sched  # noqa: E402

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


class BypassPage(Adw.PreferencesPage):
    def __init__(self, win, rpc):
        super().__init__()
        self.win, self.rpc = win, rpc
        self.state = {"apps": [], "enabled": True, "supported": True, "reason": "", "active": False}
        self._rows = []
        self._quiet = False
        self.banner = Adw.Banner(revealed=False)
        g = Adw.PreferencesGroup(
            title="Apps That Skip the VPN",
            description="While the VPN is connected, these programs - and anything they start - keep using your normal "
                        "internet connection. Everything else stays inside the tunnel.")
        self.enabled = Adw.SwitchRow(title="Exclude these apps from the VPN")
        self.enabled.connect("notify::active", self._on_enabled)
        g.add(self.enabled)
        self.status = Adw.ActionRow(title="Status")
        self.status.add_css_class("property")
        g.add(self.status)
        self.add(g)
        self.group = Adw.PreferencesGroup(title="Apps")
        add = Gtk.Button(label="Add Apps…", valign=Gtk.Align.CENTER)
        add.add_css_class("suggested-action")
        add.connect("clicked", self._pick)
        self.group.set_header_suffix(add)
        self.add(self.group)

    def update(self, st):
        self.state = st
        self._quiet = True
        self.enabled.set_active(st["enabled"])
        self.enabled.set_sensitive(st["supported"])
        self._quiet = False
        if not st["supported"]:
            self.status.set_subtitle(GLib.markup_escape_text("Unavailable: " + st["reason"]))
        elif st["active"]:
            self.status.set_subtitle("Active - %d process(es) bypassing the VPN" % st.get("moved", 0))
        else:
            self.status.set_subtitle("Applies as soon as the VPN is connected")
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

    def _on_enabled(self, row, _p):
        if not self._quiet:
            self.rpc("split.set", self.update, self.win._fail, enabled=row.get_active())

    def _pick(self, *_):
        AppPicker(self.win, [a["id"] for a in self.state["apps"]],
                  lambda picked: self._save(self.state["apps"] + picked)).present()

    def _save(self, apps):
        self.rpc("split.set", lambda st: (self.update(st), self.win.toast("App list saved")), self.win._fail, apps=apps)

"""The live connection table: on the Connection page, in a pop-out window, with a right-click menu (copy, close,
stop the program, block) and the window that manages the blocked connections."""

import os
import signal
import time

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, Gio, GLib, GObject, Gtk, Pango  # noqa: E402

from ..blocks import lifetime  # noqa: E402
from ..conntable import to_csv  # noqa: E402
from .files import save_file  # noqa: E402
from .keys import close_keys  # noqa: E402

WAY = {"in": "In", "out": "Out", "listen": "Listening"}
COLUMNS = (
    ("Way", 62, False, lambda r: WAY.get(r["dir"], r["dir"])),
    ("Application", 140, True, lambda r: ("%s (%d)" % (r["app"], r["pid"])) if r["pid"] else (r["app"] or "–")),
    ("Protocol", 66, False, lambda r: r["proto"].upper() + ("6" if r["v6"] else "")),
    ("Local", 175, True, lambda r: "%s:%d" % (r["local"], r["lport"])),
    ("Remote", 175, True, lambda r: ("%s:%d" % (r.get("rname") or r["remote"], r["rport"])) if r["rport"] else "–"),
    ("State", 110, False, lambda r: r["state"] or "–"),
)
KIND_LABELS = {"address": "Address", "endpoint": "Address and port", "port": "Port", "app": "Application"}
# how long a block lasts: (label, menu target suffix, rpc arguments)
DURATIONS = (("Until I unblock it", "0", {}), ("For 15 minutes", "15", {"minutes": 15}),
             ("For 1 hour", "60", {"minutes": 60}), ("For 1 day", "1440", {"minutes": 1440}),
             ("Until the computer restarts", "reboot", {"until_reboot": True}))


class ConnRow(GObject.Object):
    """One row of the connection table."""

    def __init__(self, data):
        super().__init__()
        self.data = data


def has_remote(r):
    return bool(r["rport"]) and r["remote"] not in ("", "*", "0.0.0.0", "::")


class ConnectionsTable(Gtk.Box):
    """Filterable table of connections.  ``host`` is the window that shows toasts (toast(text))."""

    def __init__(self, host, rpc, height=240, wide=False):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self.host, self.rpc = host, rpc
        self.store = Gio.ListStore(item_type=ConnRow)
        self._keys, self._note, self._row = None, "", None
        self.paused = False
        self.listening = Gtk.CheckButton(label="Listening")
        self.local = Gtk.CheckButton(label="Local")
        self.local.set_tooltip_text("Include connections that stay inside this computer")
        self.resolve = Gtk.CheckButton(label="Resolve names")
        self.resolve.set_tooltip_text("Show host names instead of addresses where reverse DNS knows them.\n"
                                      "This sends DNS queries for the remote addresses.")
        self.search = Gtk.SearchEntry(placeholder_text="Filter", width_chars=14)
        self.search.connect("search-changed", lambda *_: self.refilter())
        self.controls = Gtk.Box(spacing=8, valign=Gtk.Align.CENTER)
        export = Gio.Menu()
        export.append("Copy as CSV", "conn.export-copy")
        export.append("Save as CSV…", "conn.export-save")
        self.export = Gtk.MenuButton(label="Export", menu_model=export, tooltip_text="The rows shown, as CSV")
        for w in (self.search, self.listening, self.local, self.resolve, self.export):
            self.controls.append(w)
        self.filter = Gtk.CustomFilter.new(self._match)
        self.filtered = Gtk.FilterListModel(model=self.store, filter=self.filter)
        self.selection = Gtk.SingleSelection(model=self.filtered, autoselect=False, can_unselect=True)
        self.selection.set_selected(Gtk.INVALID_LIST_POSITION)
        self.view = Gtk.ColumnView(model=self.selection, show_row_separators=True, reorderable=False)
        self.view.add_css_class("data-table")
        for title, width, grow, fn in COLUMNS:
            factory = Gtk.SignalListItemFactory()
            factory.connect("setup", self._setup)
            factory.connect("bind", self._bind, fn)
            factory.connect("unbind", self._unbind)
            self.view.append_column(Gtk.ColumnViewColumn(title=title, factory=factory, resizable=True,
                                                         fixed_width=width, expand=grow and wide))
        self.scroll = Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.AUTOMATIC, vexpand=bool(wide))
        if not wide:
            self.scroll.set_min_content_height(height)
            self.scroll.set_max_content_height(height)
        else:
            self.scroll.set_min_content_height(height)
        self.scroll.set_child(self.view)
        frame = Gtk.Frame(vexpand=bool(wide))
        frame.set_child(self.scroll)
        self.append(frame)
        self.summary = Gtk.Label(xalign=0)
        self.summary.add_css_class("dim-label")
        self.append(self.summary)
        click = Gtk.GestureClick(button=Gdk.BUTTON_SECONDARY)
        click.connect("pressed", self._on_right_click)
        self.view.add_controller(click)
        self._build_actions()

    # ---- cells
    @staticmethod
    def _setup(_f, item):
        item.set_child(Gtk.Label(xalign=0, ellipsize=Pango.EllipsizeMode.END, margin_start=6, margin_end=6,
                                 margin_top=3, margin_bottom=3))

    @staticmethod
    def _bind(_f, item, fn):
        lbl = item.get_child()
        data = item.get_item().data
        lbl.set_label(fn(data))
        lbl.conn, lbl.pos = data, item.get_position()

    @staticmethod
    def _unbind(_f, item):
        lbl = item.get_child()
        lbl.conn = None

    # ---- data
    def _match(self, item):
        q = self.search.get_text().strip().lower()
        if not q:
            return True
        r = item.data
        return q in (" ".join(str(fn(r)) for _t, _w, _g, fn in COLUMNS) + " " + r["remote"]).lower()

    def refilter(self):
        self.filter.changed(Gtk.FilterChange.DIFFERENT)
        self._summary()

    def params(self):
        return {"listening": self.listening.get_active(), "local": self.local.get_active(),
                "resolve": self.resolve.get_active()}

    def update(self, res):
        if self.paused:
            return
        rows = res.get("rows", [])
        keys = [(r["dir"], r["proto"], r["v6"], r["local"], r["lport"], r["remote"], r["rport"], r["state"], r["pid"],
                 r.get("rname", "")) for r in rows]
        if keys != self._keys:                          # leave the table (and its scroll position) alone when nothing changed
            self._keys = keys
            adj = self.scroll.get_vadjustment()
            pos = adj.get_value()
            self.store.splice(0, self.store.get_n_items(), [ConnRow(r) for r in rows])
            GLib.idle_add(adj.set_value, pos)
        self._note = res.get("note", "") or ("(list truncated)" if res.get("truncated") else "")
        self._summary()

    def _summary(self):
        n, total = self.filtered.get_n_items(), self.store.get_n_items()
        text = "%d connection%s" % (n, "" if n == 1 else "s")
        if n != total:
            text += " (of %d)" % total
        if self.paused:
            text += " · paused"
        if self._note:
            text += " · " + self._note
        self.summary.set_label(text)

    def set_paused(self, flag):
        self.paused = bool(flag)
        self._summary()

    # ---- right-click menu
    def _row_at(self, x, y):
        w = self.view.pick(x, y, Gtk.PickFlags.DEFAULT)
        while w is not None and w is not self.view:
            if getattr(w, "conn", None) is not None:
                return w.conn, getattr(w, "pos", None)
            c = w.get_first_child()
            while c is not None:                          # the cell wraps our label
                if getattr(c, "conn", None) is not None:
                    return c.conn, getattr(c, "pos", None)
                c = c.get_next_sibling()
            w = w.get_parent()
        return None, None

    def _on_right_click(self, gesture, _n, x, y):
        row, pos = self._row_at(x, y)
        if row is None:
            return
        if pos is not None:
            self.selection.set_selected(pos)
        self.show_menu(row, x, y)

    def show_menu(self, row, x=0, y=0):
        self._row = row
        pop = Gtk.PopoverMenu.new_from_model(self.menu_for(row))
        pop.set_parent(self.view)
        pop.set_has_arrow(False)
        rect = Gdk.Rectangle()
        rect.x, rect.y, rect.width, rect.height = int(x), int(y), 1, 1
        pop.set_pointing_to(rect)
        pop.connect("closed", lambda p: GLib.idle_add(p.unparent))
        pop.popup()
        self._popover = pop

    @staticmethod
    def _item(section, label, action, target=None):
        mi = Gio.MenuItem.new(label, None)
        mi.set_action_and_target_value("conn." + action, GLib.Variant("s", target) if target is not None else None)
        section.append_item(mi)

    def menu_for(self, r):
        """The right-click menu of one connection (only what makes sense for it)."""
        menu = Gio.Menu()
        cp = Gio.Menu()
        if has_remote(r):
            self._item(cp, "Copy remote address (%s:%d)" % (r["remote"], r["rport"]), "copy", "remote")
            self._item(cp, "Copy remote IP", "copy", "remote_ip")
            if r.get("rname"):
                self._item(cp, "Copy remote host name (%s)" % r["rname"], "copy", "remote_host")
        self._item(cp, "Copy local address (%s:%d)" % (r["local"], r["lport"]), "copy", "local")
        if r["app"]:
            self._item(cp, "Copy application name", "copy", "app")
        self._item(cp, "Copy whole row", "copy", "row")
        menu.append_section(None, cp)
        stop = Gio.Menu()
        if r["dir"] != "listen" and has_remote(r):
            self._item(stop, "Force-close this connection", "close")
        if r["pid"]:
            self._item(stop, "Stop application “%s”…" % r["app"], "stop", "term")
            self._item(stop, "Force-kill application “%s”…" % r["app"], "stop", "kill")
        if stop.get_n_items():
            menu.append_section(None, stop)
        blk = Gio.Menu()
        proto = r["proto"].upper()
        if has_remote(r):
            self._item(blk, "Block remote address %s" % r["remote"], "block", "address")
            self._item(blk, "Block %s:%d (%s)" % (r["remote"], r["rport"], proto), "block", "endpoint")
            self._item(blk, "Block remote port %d (%s)" % (r["rport"], proto), "block", "remote_port")
        if r["dir"] in ("in", "listen"):
            self._item(blk, "Block local port %d (%s)" % (r["lport"], proto), "block", "local_port")
        if r["app"]:
            self._item(blk, "Block application “%s”" % r["app"], "block", "app")
        for i in range(blk.get_n_items()):            # every block offers how long it lasts
            label = blk.get_item_attribute_value(i, "label", None).get_string()
            what = blk.get_item_attribute_value(i, "target", None).get_string()
            sub = Gio.Menu()
            for text, suffix, _kw in DURATIONS:
                self._item(sub, text, "block", "%s|%s" % (what, suffix))
            blk.remove(i)
            blk.insert_submenu(i, label, sub)
        if blk.get_n_items():
            menu.append_section(None, blk)
        return menu

    def _build_actions(self):
        group = Gio.SimpleActionGroup()
        for name, ptype, cb in (("copy", "s", self._act_copy), ("close", None, self._act_close),
                                ("stop", "s", self._act_stop), ("block", "s", self._act_block),
                                ("export-copy", None, self._act_export_copy),
                                ("export-save", None, self._act_export_save)):
            act = Gio.SimpleAction.new(name, GLib.VariantType.new(ptype) if ptype else None)
            act.connect("activate", cb)
            group.add_action(act)
        self.insert_action_group("conn", group)
        # the Export button sits in the controls row, which is not inside this widget: it needs the actions too,
        # or its menu items are greyed out
        self.controls.insert_action_group("conn", group)

    # ---- actions
    @staticmethod
    def text_for(r, what):
        return {"remote": "%s:%d" % (r["remote"], r["rport"]), "remote_ip": r["remote"],
                "remote_host": r.get("rname") or r["remote"],
                "local": "%s:%d" % (r["local"], r["lport"]), "app": r["app"] or "",
                "row": "\t".join(str(fn(r)) for _t, _w, _g, fn in COLUMNS)}[what]

    def _act_copy(self, _a, param):
        r = self._row
        if r is None:
            return
        text = self.text_for(r, param.get_string())
        disp = Gdk.Display.get_default()
        if disp:
            disp.get_clipboard().set(text)
            self.host.toast("Copied %s" % (text if len(text) < 60 else text[:57] + "…"))

    def _act_close(self, _a, _p):
        r = self._row
        if r is None:
            return
        self.rpc("connections.close", lambda *_: self.host.toast("Connection closed"),
                 lambda msg, *_: self.host.toast("Could not close it: %s" % msg),
                 proto=r["proto"], local=r["local"], lport=r["lport"], remote=r["remote"], rport=r["rport"])

    def _act_stop(self, _a, param):
        r = self._row
        if r is None or not r["pid"]:
            return
        force = param.get_string() == "kill"
        d = Adw.MessageDialog(transient_for=self.host if isinstance(self.host, Gtk.Window) else self.get_root(),
                              heading="%s “%s”?" % ("Force-kill" if force else "Stop", r["app"]),
                              body="%s (process %d) will be %s. Unsaved work in it is lost. You can only stop your own programs."
                                   % (r["app"], r["pid"], "killed at once" if force else "asked to quit"))
        d.add_response("cancel", "Cancel")
        d.add_response("go", "Force-kill" if force else "Stop")
        d.set_response_appearance("go", Adw.ResponseAppearance.DESTRUCTIVE)
        d.connect("response", lambda _d, resp: resp == "go" and self.stop_process(r["pid"], r["app"], force))
        d.present()

    def stop_process(self, pid, name, force):
        """Signal one of the user's own programs (the daemon is not involved: it would act as root)."""
        if pid <= 1 or pid == os.getpid():
            self.host.toast("Not stopping that process")
            return False
        try:
            os.kill(pid, signal.SIGKILL if force else signal.SIGTERM)
        except ProcessLookupError:
            self.host.toast("%s has already ended" % name)
            return False
        except PermissionError:
            self.host.toast("%s belongs to another user - only your own programs can be stopped here" % name)
            return False
        if not force:
            def check():
                try:
                    os.kill(pid, 0)
                    self.host.toast("%s is still running - use Force-kill" % name)
                except OSError:
                    pass
                return False
            GLib.timeout_add_seconds(4, check)
        self.host.toast("%s %s" % (name, "killed" if force else "asked to quit"))
        return True

    def block_spec(self, r, what):
        """(kind, value, proto) the daemon needs for a block chosen in the menu."""
        proto = r["proto"]
        return {"address": ("address", r["remote"], "any"),
                "endpoint": ("endpoint", ("[%s]:%d" if ":" in r["remote"] else "%s:%d") % (r["remote"], r["rport"]), proto),
                "remote_port": ("port", str(r["rport"]), proto),
                "local_port": ("port", str(r["lport"]), proto),
                "app": ("app", r["app"], "any")}[what]

    def _act_block(self, _a, param):
        r = self._row
        if r is None:
            return
        what, _, dur = param.get_string().partition("|")
        kind, value, proto = self.block_spec(r, what)
        extra = next((kw for _t, suffix, kw in DURATIONS if suffix == dur), {})

        def done(e):
            n = e.get("closed", 0)
            how = lifetime(e)
            self.host.toast("Blocked %s%s%s" % (value, "" if how == "permanent" else " " + how,
                                                " – closed %d open connection%s" % (n, "" if n == 1 else "s") if n else ""))
            if hasattr(self.host, "blocks_changed"):
                self.host.blocks_changed()
        self.rpc("blocks.add", done, lambda msg, *_: self.host.toast("Could not block: %s" % msg),
                 kind=kind, value=value, proto=proto, **extra)

    # ---- export
    def shown_rows(self):
        return [self.filtered.get_item(i).data for i in range(self.filtered.get_n_items())]

    def _act_export_copy(self, *_):
        rows = self.shown_rows()
        disp = Gdk.Display.get_default()
        if disp:
            disp.get_clipboard().set(to_csv(rows))
            self.host.toast("Copied %d row%s as CSV" % (len(rows), "" if len(rows) == 1 else "s"))

    def _act_export_save(self, *_):
        rows = self.shown_rows()
        win = self.get_root() if isinstance(self.get_root(), Gtk.Window) else None

        def saved(path):
            if not path:
                return
            try:
                with open(path, "w", newline="") as fh:
                    fh.write(to_csv(rows))
                self.host.toast("Saved %d row%s to %s" % (len(rows), "" if len(rows) == 1 else "s", os.path.basename(path)))
            except OSError as e:
                self.host.toast("Could not save: %s" % e.strerror)
        save_file(win, "Save Connections", time.strftime("connections-%Y%m%d-%H%M%S.csv"), saved)


class ConnectionsGroup(Adw.PreferencesGroup):
    """The connection table on the Connection page, with Pop out and Blocked connections buttons."""

    def __init__(self, host, rpc):
        super().__init__(title="Connections", description="Applications using the network right now. Right-click a row.")
        self.host, self.rpc = host, rpc
        self.table = ConnectionsTable(host, rpc)
        # the table reports block changes to its host: this group is the one that knows the windows
        self.table.host = self
        self._real_host = host
        self.pop = Gtk.Button(label="Pop out", valign=Gtk.Align.CENTER, tooltip_text="Open the table in its own window")
        self.pop.connect("clicked", lambda *_: self.popout())
        # the title and description stay on top; the filter, switches and Pop out get a row of their own below them
        self.table.search.set_hexpand(True)
        bar = Gtk.Box(spacing=8, valign=Gtk.Align.CENTER, margin_bottom=6)
        bar.append(self.table.controls)
        bar.append(self.pop)
        self.table.controls.set_hexpand(True)
        self.add(bar)
        self.add(self.table)
        self.blocked_btn = Gtk.Button(label="Blocked connections…", halign=Gtk.Align.START, margin_top=6)
        self.blocked_btn.connect("clicked", lambda *_: self.open_blocked())
        self.add(self.blocked_btn)
        self._win = self._blocked = None
        self.blocked_count = 0

    # the table calls these on its host
    def toast(self, text):
        self._real_host.toast(text)

    def blocks_changed(self):
        self.refresh_blocked()
        if self._blocked is not None:
            self._blocked.reload()

    def update(self, res):
        self.table.update(res)

    def params(self):
        return self.table.params()

    def refresh_blocked(self):
        def got(st):
            self.blocked_count = len(st["entries"])
            self.blocked_btn.set_label("Blocked connections… (%d)" % self.blocked_count if self.blocked_count
                                       else "Blocked connections…")
        self.rpc("blocks.status", got, None)

    def popout(self):
        if self._win is not None:
            self._win.present()
            return self._win
        self._win = ConnectionsWindow(self._real_host, self.rpc, self)
        self._win.connect("close-request", lambda *_: setattr(self, "_win", None) or False)
        self._win.present()
        return self._win

    def open_blocked(self):
        if self._blocked is not None:
            self._blocked.present()
            return
        self._blocked = BlockedWindow(self._real_host, self.rpc, self)
        self._blocked.connect("close-request", lambda *_: (setattr(self, "_blocked", None), self.refresh_blocked(), False)[2])
        self._blocked.present()


class ConnectionsWindow(Adw.Window):
    """The table in a window of its own: bigger, with Pause, and polling by itself."""

    def __init__(self, host, rpc, group):
        super().__init__(application=host.get_application(), default_width=1080, default_height=640,
                         title="Connections")
        close_keys(self)
        self.rpc, self.group = rpc, group
        view = Adw.ToolbarView()
        header = Adw.HeaderBar()
        self.table = ConnectionsTable(self, rpc, height=300, wide=True)
        self.pause = Gtk.ToggleButton(label="Pause", tooltip_text="Freeze the table so you can read it")
        self.pause.connect("toggled", lambda b: self.table.set_paused(b.get_active()))
        header.pack_start(self.pause)
        header.pack_end(self.table.controls)
        view.add_top_bar(header)
        self.toasts = Adw.ToastOverlay()
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8, margin_top=8, margin_bottom=12, margin_start=12,
                      margin_end=12)
        box.append(self.table)
        btn = Gtk.Button(label="Blocked connections…", halign=Gtk.Align.START)
        btn.connect("clicked", lambda *_: group.open_blocked())
        box.append(btn)
        self.toasts.set_child(box)
        view.set_content(self.toasts)
        self.set_content(view)
        self._alive = True
        self.connect("close-request", self._on_close)
        self.rpc("connections", self.table.update, None, **self.table.params())      # first fill at once
        GLib.timeout_add_seconds(2, self._poll)

    def toast(self, text):
        self.toasts.add_toast(Adw.Toast(title=text, timeout=3))

    def blocks_changed(self):
        self.group.blocks_changed()

    def _on_close(self, *_):
        self._alive = False
        return False

    def _poll(self):
        if not self._alive:
            return False
        if self.is_visible() and not self.table.paused:
            self.rpc("connections", self.table.update, None, **self.table.params())
        return True


class BlockedWindow(Adw.Window):
    """Everything that is blocked: add, switch off, remove (several at once)."""

    def __init__(self, host, rpc, group):
        super().__init__(application=host.get_application(), default_width=620, default_height=700,
                         title="Blocked Connections")
        close_keys(self)
        self.rpc, self.group = rpc, group
        self.entries, self.status, self._rows, self._quiet = [], {}, {}, False
        view = Adw.ToolbarView()
        view.add_top_bar(Adw.HeaderBar())
        self.banner = Adw.Banner(revealed=False)
        view.add_top_bar(self.banner)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18, margin_top=12, margin_bottom=12,
                      margin_start=12, margin_end=12)

        g = Adw.PreferencesGroup(title="Enforcement")
        self.enforce = Adw.SwitchRow(title="Block these connections", subtitle="")
        self.enforce.connect("notify::active", self._on_enforce)
        g.add(self.enforce)
        box.append(g)

        add = Adw.PreferencesGroup(title="Block something",
                                   description="Blocking also closes the matching connections that are open now.")
        self.kinds = ["address", "endpoint", "port", "app"]
        self.kind = Adw.ComboRow(title="What", model=Gtk.StringList.new(
            ["Address or network", "Address and port", "Port", "Application"]))
        self.kind.connect("notify::selected", self._on_kind)
        self.value = Adw.EntryRow(title="")
        self.value.connect("entry-activated", lambda *_: self._add())
        self.proto = Adw.ComboRow(title="Protocol", model=Gtk.StringList.new(["Any", "TCP", "UDP"]))
        self.duration = Adw.ComboRow(title="How long", model=Gtk.StringList.new([d[0] for d in DURATIONS]))
        self.note = Adw.EntryRow(title="Note (optional)")
        for r in (self.kind, self.value, self.proto, self.duration, self.note):
            add.add(r)
        self.add_btn = Gtk.Button(label="Block", halign=Gtk.Align.END, margin_top=6)
        self.add_btn.add_css_class("suggested-action")
        self.add_btn.connect("clicked", lambda *_: self._add())
        add.add(self.add_btn)
        box.append(add)

        self.list_group = Adw.PreferencesGroup(title="Blocked")
        self.listbox = Gtk.ListBox(selection_mode=Gtk.SelectionMode.MULTIPLE, activate_on_single_click=False)
        self.listbox.add_css_class("boxed-list")
        self.listbox.connect("selected-rows-changed", self._on_selection_changed)
        keys = Gtk.EventControllerKey()
        keys.connect("key-pressed", self._on_key)
        self.listbox.add_controller(keys)
        self.empty = Gtk.Label(label="Nothing is blocked.", css_classes=["dim-label"], margin_top=6, margin_bottom=6)
        self.list_group.add(self.listbox)
        self.list_group.add(self.empty)
        box.append(self.list_group)

        scroll = Gtk.ScrolledWindow(vexpand=True, hscrollbar_policy=Gtk.PolicyType.NEVER)
        clamp = Adw.Clamp(maximum_size=640)
        clamp.set_child(box)
        scroll.set_child(clamp)
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        outer.append(scroll)
        self.sel_label = Gtk.Label(label="", hexpand=True, xalign=0, margin_start=6)
        sel_all = Gtk.Button(label="Select All")
        sel_all.connect("clicked", lambda *_: self.listbox.select_all())
        sel_none = Gtk.Button(label="Clear")
        sel_none.connect("clicked", lambda *_: self.listbox.unselect_all())
        self.sel_remove = Gtk.Button(label="Unblock")
        self.sel_remove.add_css_class("destructive-action")
        self.sel_remove.connect("clicked", lambda *_: self._remove_selected())
        bar = Gtk.ActionBar()
        bar.pack_start(self.sel_label)
        bar.pack_end(self.sel_remove)
        bar.pack_end(sel_none)
        bar.pack_end(sel_all)
        self.sel_bar = Gtk.Revealer(child=bar, reveal_child=False, transition_type=Gtk.RevealerTransitionType.SLIDE_UP)
        outer.append(self.sel_bar)
        self.toasts = Adw.ToastOverlay()
        self.toasts.set_child(outer)
        view.set_content(self.toasts)
        self.set_content(view)
        self._on_kind()
        self.reload()

    def toast(self, text):
        self.toasts.add_toast(Adw.Toast(title=text, timeout=3))

    # ---- data
    def reload(self, *_):
        self.rpc("blocks.status", self.fill, lambda msg, *_: self.toast(msg))

    def fill(self, st):
        self.status = st
        self.entries = st["entries"]
        self._quiet = True
        self.enforce.set_active(st["enabled"])
        if st["error"]:
            sub = st["error"]
        elif not st["supported"]:
            sub = st["reason"]
        elif st["active"]:
            sub = "Enforced with nftables"
        else:
            sub = "Nothing to enforce" if st["enabled"] else "Switched off"
        self.enforce.set_subtitle(GLib.markup_escape_text(sub))
        self.banner.set_title(st["reason"] if not st["supported"] else st["error"])
        self.banner.set_revealed(bool(st["error"] or not st["supported"]))
        self._quiet = False
        keep = {r.entry["id"] for r in self.listbox.get_selected_rows()}
        for r in self._rows.values():
            self.listbox.remove(r)
        self._rows = {}
        for e in self.entries:
            row = self._make_row(e)
            self._rows[e["id"]] = row
            self.listbox.append(row)
            if e["id"] in keep:
                self.listbox.select_row(row)
        self.empty.set_visible(not self.entries)
        self.listbox.set_visible(bool(self.entries))
        self.list_group.set_description("%d entr%s" % (len(self.entries), "y" if len(self.entries) == 1 else "ies")
                                        if self.entries else "")

    def _make_row(self, e):
        bits = [KIND_LABELS.get(e["kind"], e["kind"])]
        if e["kind"] in ("endpoint", "port") and e.get("proto", "any") != "any":
            bits.append(e["proto"].upper())
        if e.get("note"):
            bits.append(e["note"])
        bits.append("added %s" % time.strftime("%Y-%m-%d %H:%M", time.localtime(e.get("created", 0))))
        if lifetime(e) != "permanent":
            bits.append(lifetime(e))
        row = Adw.ActionRow(title=GLib.markup_escape_text(e["value"]), subtitle=GLib.markup_escape_text(" · ".join(bits)))
        row.entry = e
        row.set_activatable(False)
        sw = Gtk.Switch(valign=Gtk.Align.CENTER, active=e.get("enabled", True), tooltip_text="Enforce this entry")
        sw.connect("notify::active", lambda s, _p, ident=e["id"]: self._on_entry_switch(ident, s.get_active()))
        row.add_suffix(sw)
        rm = Gtk.Button(label="Unblock", valign=Gtk.Align.CENTER)
        rm.add_css_class("flat")
        rm.connect("clicked", lambda *_, ident=e["id"]: self.do_remove([ident]))
        row.add_suffix(rm)
        return row

    # ---- actions
    def _on_kind(self, *_):
        kind = self.kinds[self.kind.get_selected()] if self.kind.get_selected() >= 0 else "address"
        self.value.set_title({"address": "IP address or network (203.0.113.9 or 203.0.113.0/24)",
                              "endpoint": "Address and port (203.0.113.9:443)", "port": "Port number (6881)",
                              "app": "Program name (for example steam)"}[kind])
        self.proto.set_visible(kind in ("endpoint", "port"))

    def _on_enforce(self, row, _p):
        if not self._quiet and row.get_active() != self.status.get("enabled"):
            self.rpc("blocks.set", lambda *_: (self.reload(), self.group.refresh_blocked()),
                     lambda msg, *_: self.toast(msg), enabled=row.get_active())

    def _on_entry_switch(self, ident, active):
        if self._quiet:
            return
        e = next((x for x in self.entries if x["id"] == ident), None)
        if e is not None and e.get("enabled", True) != active:
            self.rpc("blocks.update", lambda *_: self.reload(), lambda msg, *_: self.toast(msg), ident=ident, enabled=active)

    def _add(self):
        kind = self.kinds[self.kind.get_selected()]
        value = self.value.get_text().strip()
        if not value:
            self.toast("Enter what to block")
            return
        proto = ["any", "tcp", "udp"][self.proto.get_selected()] if kind in ("endpoint", "port") else "any"

        def done(e):
            n = e.get("closed", 0)
            self.value.set_text("")
            self.note.set_text("")
            self.toast("Blocked %s%s" % (e["value"], " – closed %d connection%s" % (n, "" if n == 1 else "s") if n else ""))
            self.reload()
            self.group.refresh_blocked()
        self.rpc("blocks.add", done, lambda msg, *_: self.toast(msg), kind=kind, value=value, proto=proto,
                 note=self.note.get_text().strip(), **DURATIONS[max(0, self.duration.get_selected())][2])

    def selected_ids(self):
        return [r.entry["id"] for r in self.listbox.get_selected_rows()]

    def _on_selection_changed(self, *_):
        n = len(self.listbox.get_selected_rows())
        self.sel_label.set_label("%d selected" % n)
        self.sel_bar.set_reveal_child(n > 0)

    def _on_key(self, _c, keyval, _code, _state):
        if keyval == Gdk.KEY_Delete and self.selected_ids():
            self.do_remove(self.selected_ids())
            return True
        return False

    def _remove_selected(self):
        ids = self.selected_ids()
        if ids:
            self.do_remove(ids)

    def do_remove(self, ids):
        def done(res):
            n = len(res.get("removed", []))
            self.toast("Unblocked %d" % n)
            self.reload()
            self.group.refresh_blocked()
        self.rpc("blocks.remove", done, lambda msg, *_: self.toast(msg), ids=ids)

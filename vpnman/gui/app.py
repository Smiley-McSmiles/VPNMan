"""GTK4 / libadwaita front-end for vpnman (requires libadwaita >= 1.4)."""

import os
import sys
import threading
import time

try:
    import gi
    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Adw, Gdk, Gio, GLib, GObject, Gtk, Pango
except (ImportError, ValueError) as exc:  # pragma: no cover
    print("The GUI needs PyGObject, GTK 4 and libadwaita >= 1.4: %s" % exc, file=sys.stderr)
    raise SystemExit(1)

import json

from .. import APP_ID, APP_NAME, __version__, autostart, profiles as prof
from .tray import Tray
from ..settings import DNS_PRESETS, DEFAULTS
from ..ipc import Client, DaemonUnavailable, RpcError

ACTIVE = ("connected", "connecting", "reconnecting")


def human(n):
    n = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or unit == "TiB":
            return ("%d %s" if unit == "B" else "%.1f %s") % (n if unit == "B" else n, unit)
        n /= 1024


def hms(sec):
    sec = int(sec)
    return "%d:%02d:%02d" % (sec // 3600, sec % 3600 // 60, sec % 60)


def rpc(method, ok=None, fail=None, **params):
    """Run a daemon call off the UI thread; callbacks run on the main loop."""
    def work():
        try:
            res = Client(timeout=60).call(method, **params)
            if ok:
                GLib.idle_add(ok, res)
        except (DaemonUnavailable, RpcError) as e:
            GLib.idle_add(fail or (lambda *_: None), str(e), isinstance(e, DaemonUnavailable))
    threading.Thread(target=work, daemon=True).start()


def choose_files(parent, title, callback, multiple=True):
    if hasattr(Gtk, "FileDialog"):
        dlg = Gtk.FileDialog(title=title)

        def done(d, res):
            try:
                if multiple:
                    model = d.open_multiple_finish(res)
                    files = [model.get_item(i).get_path() for i in range(model.get_n_items())]
                else:
                    files = [d.open_finish(res).get_path()]
            except GLib.Error:
                return
            callback(files)
        (dlg.open_multiple if multiple else dlg.open)(parent, None, done)
    else:  # pragma: no cover - GTK < 4.10
        dlg = Gtk.FileChooserNative(title=title, transient_for=parent, action=Gtk.FileChooserAction.OPEN,
                                    select_multiple=multiple)
        dlg.connect("response", lambda d, r: callback([f.get_path() for f in d.get_files()]) if r == Gtk.ResponseType.ACCEPT else None)
        dlg.show()
        parent._native = dlg


class UserConfig:
    """Per-user GUI preferences (~/.config/vpnman/gui.json); the daemon's settings are system-wide."""
    DEFAULTS = {"run_in_background": True}

    def __init__(self):
        base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
        self.path = os.path.join(base, "vpnman", "gui.json")
        try:
            with open(self.path) as fh:
                self.data = dict(self.DEFAULTS, **json.load(fh))
        except (OSError, ValueError):
            self.data = dict(self.DEFAULTS)

    def get(self, key):
        return self.data.get(key, self.DEFAULTS.get(key))

    def set(self, key, value):
        self.data[key] = value
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            with open(self.path, "w") as fh:
                json.dump(self.data, fh)
        except OSError:
            pass


ICON_NAMES = [APP_ID] + ["%s-%s-symbolic" % (APP_ID, k) for k in ("connected", "connecting", "error", "disconnected")]


def private_icon_dir():
    """Cache-free copy of our icons shipped next to the program (installed or run from a checkout)."""
    here = os.path.dirname(os.path.abspath(__file__))
    for d in (os.path.join(os.environ.get("VPNMAN_DATA_DIR", "/nonexistent"), "icons"),
              os.path.normpath(os.path.join(here, "..", "..", "data", "icons")),
              "/usr/share/vpnman/icons", "/usr/local/share/vpnman/icons"):
        if os.path.isdir(os.path.join(d, "hicolor")):
            return d
    return ""


def ensure_icons():
    """GTK ignores icons added to a theme dir whose icon-theme.cache is stale (package installs do this).
    If any of ours is missing from the system theme, add the private copy to the search path."""
    display = Gdk.Display.get_default()
    if not display:
        return
    theme = Gtk.IconTheme.get_for_display(display)
    d = private_icon_dir()
    if d and not all(theme.has_icon(n) for n in ICON_NAMES):
        theme.add_search_path(d)
    Gtk.Window.set_default_icon_name(APP_ID)


TRAY_ICONS = {"connected": "connected", "connecting": "connecting", "reconnecting": "connecting",
              "error": "error", "disconnected": "disconnected"}


class Hero(Gtk.Box):
    """Big icon + title + description + child; StatusPage collapses inside a scrolled page."""

    def __init__(self, icon_name, title, description):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=24, margin_start=12,
                         margin_end=12, halign=Gtk.Align.CENTER)
        self.icon = Gtk.Image(icon_name=icon_name, pixel_size=96)
        self.icon.add_css_class("dim-label")
        self.title = Gtk.Label(label=title, css_classes=["title-1"], wrap=True, justify=Gtk.Justification.CENTER)
        self.desc = Gtk.Label(label=description, wrap=True, justify=Gtk.Justification.CENTER,
                              css_classes=["dim-label"])
        self.holder = Gtk.Box(halign=Gtk.Align.CENTER, margin_top=6)
        for w in (self.icon, self.title, self.desc, self.holder):
            self.append(w)

    def set_icon_name(self, n): self.icon.set_from_icon_name(n)
    def set_title(self, t): self.title.set_label(t)
    def set_description(self, d): self.desc.set_label(d or "")
    def set_child(self, w): self.holder.append(w)


# ------------------------------------------------------------------ dialogs

class ProfileDialog(Adw.Window):
    """Import a config file, add a profile by hand, or edit an existing one."""

    def __init__(self, parent, mode, protocols, profile=None, files=None, on_done=None):
        super().__init__(transient_for=parent, modal=True, default_width=480, default_height=640)
        self.mode, self.profile, self.on_done, self.parent_win = mode, profile, on_done, parent
        self.protocols = protocols
        self.files = files or []
        self.set_title({"import": "Import Profile", "add": "Add Profile", "edit": "Edit Profile"}[mode])
        view = Adw.ToolbarView()
        header = Adw.HeaderBar(show_end_title_buttons=False, show_start_title_buttons=False)
        cancel = Gtk.Button(label="Cancel")
        cancel.connect("clicked", lambda *_: self.close())
        self.save = Gtk.Button(label="Save" if mode == "edit" else "Add")
        self.save.add_css_class("suggested-action")
        self.save.connect("clicked", self._submit)
        header.pack_start(cancel)
        header.pack_end(self.save)
        view.add_top_bar(header)
        page = Adw.PreferencesPage()
        view.set_content(page)
        self.set_content(view)

        g = Adw.PreferencesGroup()
        page.add(g)
        if mode == "import":
            self.file_row = Adw.ActionRow(title="Config files", subtitle="None selected")
            btn = Gtk.Button(label="Choose…", valign=Gtk.Align.CENTER)
            btn.connect("clicked", self._pick)
            self.file_row.add_suffix(btn)
            g.add(self.file_row)
            if self.files:
                self._set_files(self.files)
        self.name = Adw.EntryRow(title="Name" + (" (optional)" if mode == "import" else ""))
        g.add(self.name)
        self.proto = None
        if mode != "edit":
            labels = (["Auto-detect"] if mode == "import" else []) + [
                "%s%s" % (p["label"], "" if p["available"] else " (not installed)") for p in protocols]
            self.proto = Adw.ComboRow(title="Protocol", model=Gtk.StringList.new(labels))
            g.add(self.proto)
        self.server = Adw.EntryRow(title="Server")
        self.port = Adw.EntryRow(title="Port")
        self.user = Adw.EntryRow(title="Username")
        self.password = Adw.PasswordEntryRow(title="Password" + (" (empty = keep)" if mode == "edit" else ""))
        self.opts = Adw.EntryRow(title="Options (key=value, comma separated)")
        self.dns = Adw.EntryRow(title="DNS servers (comma separated)")
        self.notes = Adw.EntryRow(title="Notes")
        g2 = Adw.PreferencesGroup(title="Details")
        page.add(g2)
        if mode != "import":
            for r in (self.server, self.port):
                g2.add(r)
        for r in (self.user, self.password):
            g2.add(r)
        if mode != "import":
            for r in (self.opts, self.dns, self.notes):
                g2.add(r)
        if profile:
            self.name.set_text(profile["name"])
            self.server.set_text(profile.get("server") or "")
            self.port.set_text(str(profile.get("port") or ""))
            self.user.set_text(profile.get("username") or "")
            self.dns.set_text(", ".join(profile.get("dns") or []))
            self.notes.set_text(profile.get("notes") or "")
            self.opts.set_text(", ".join("%s=%s" % kv for kv in profile.get("options", {}).items()
                                         if isinstance(kv[1], (str, int))))
        # ---- stunnel (TLS wrapper for OpenVPN)
        g3 = Adw.PreferencesGroup(title="SSL Tunnel (stunnel)",
                                  description="OpenVPN only. Wraps the connection in TLS so it looks like HTTPS.")
        page.add(g3)
        self.st_switch = Adw.SwitchRow(title="Tunnel over TLS with stunnel")
        self.st_host = Adw.EntryRow(title="stunnel server (host:port, default port 443)")
        self.st_sni = Adw.EntryRow(title="SNI hostname (optional)")
        self.st_ca = Adw.ActionRow(title="CA certificate (optional)", subtitle="None - server certificate is not verified")
        self.st_ca_path = None
        ca_btn = Gtk.Button(label="Choose…", valign=Gtk.Align.CENTER)
        ca_btn.connect("clicked", lambda *_: choose_files(self, "Choose CA certificate", self._set_ca, multiple=False))
        self.st_ca.add_suffix(ca_btn)
        for r in (self.st_switch, self.st_host, self.st_sni, self.st_ca):
            g3.add(r)
        st = (profile or {}).get("options", {}).get("stunnel")
        if st:
            self.st_switch.set_active(bool(st.get("enabled")))
            self.st_host.set_text("%s:%s" % (st.get("host", ""), st.get("port", 443)) if st.get("host") else "")
            self.st_sni.set_text(st.get("sni", ""))
            if st.get("ca"):
                self.st_ca.set_subtitle("Stored: %s" % st["ca"])
        self.err = Adw.Banner(revealed=False)
        view.add_top_bar(self.err)

    def _pick(self, *_):
        choose_files(self, "Choose VPN configuration files", self._set_files)

    def _set_files(self, files):
        self.files = files
        self.file_row.set_subtitle(", ".join(os.path.basename(f) for f in files))
        if len(files) == 1 and not self.name.get_text():
            self.name.set_text(os.path.splitext(os.path.basename(files[0]))[0])

    def _set_ca(self, files):
        self.st_ca_path = files[0]
        self.st_ca.set_subtitle(os.path.basename(files[0]))

    def _stunnel(self):
        """Return (options dict or None, {filename: b64} extra files); raises ValueError when invalid."""
        if not self.st_switch.get_active():
            if (self.profile or {}).get("options", {}).get("stunnel"):
                return {"stunnel": dict(self.profile["options"]["stunnel"], enabled=False)}, {}
            return {}, {}
        target = self.st_host.get_text().strip()
        if not target:
            raise ValueError("Enter the stunnel server (host:port)")
        host, _, port = target.rpartition(":") if ":" in target else (target, "", "")
        if not host:
            host = target
        st = {"enabled": True, "host": host, "port": int(port) if port.isdigit() else 443}
        if self.st_sni.get_text().strip():
            st["sni"] = self.st_sni.get_text().strip()
        files = {}
        old = (self.profile or {}).get("options", {}).get("stunnel", {})
        if self.st_ca_path:
            import base64
            with open(self.st_ca_path, "rb") as fh:
                files["stunnel-ca.pem"] = base64.b64encode(fh.read()).decode()
            st.update(ca="stunnel-ca.pem", verify="ca")
        elif old.get("ca"):
            st.update(ca=old["ca"], verify=old.get("verify", "ca"))
        return {"stunnel": st}, files

    def _selected_protocol(self):
        if self.proto is None:
            return None
        i = self.proto.get_selected() - (1 if self.mode == "import" else 0)
        return None if i < 0 else self.protocols[i]["id"]

    def _error(self, msg, *_):
        self.err.set_title(str(msg))
        self.err.set_revealed(True)
        self.save.set_sensitive(True)

    def _finish(self, *_):
        if self.on_done:
            self.on_done()
        self.close()

    def _submit(self, *_):
        self.save.set_sensitive(False)
        if self.mode == "import":
            if not self.files:
                return self._error("Choose at least one file")
            fields = {}
            if self.user.get_text():
                fields = {"username": self.user.get_text(), "password": self.password.get_text()}
            files, proto, name = list(self.files), self._selected_protocol(), self.name.get_text()
            try:
                st_opts, st_files = self._stunnel()
            except ValueError as e:
                return self._error(e)

            def work():
                err = None
                for f in files:
                    try:
                        text, extra = prof.collect_files(f)
                        extra.update(st_files)
                        Client().call("profiles.import", name=(name if len(files) == 1 and name else os.path.splitext(os.path.basename(f))[0]),
                                      text=text, files=extra, protocol=proto, filename=os.path.basename(f), fields=fields, options=st_opts)
                    except (RpcError, DaemonUnavailable, OSError) as e:
                        err = "%s: %s" % (os.path.basename(f), e)
                GLib.idle_add(self._error if err else self._finish, err)
            threading.Thread(target=work, daemon=True).start()
            return
        name = self.name.get_text().strip()
        if not name:
            return self._error("A name is required")
        opts = {}
        for kv in self.opts.get_text().split(","):
            if "=" in kv:
                k, _, v = kv.partition("=")
                opts[k.strip()] = v.strip()
        try:
            port = int(self.port.get_text() or 0)
        except ValueError:
            return self._error("Port must be a number")
        dns = [d.strip() for d in self.dns.get_text().split(",") if d.strip()]
        try:
            st_opts, st_files = self._stunnel()
        except ValueError as e:
            return self._error(e)
        opts.update(st_opts)
        if self.mode == "add":
            fields = {"server": self.server.get_text().strip(), "port": port, "username": self.user.get_text(),
                      "password": self.password.get_text(), "dns": dns, "notes": self.notes.get_text()}
            rpc("profiles.add", self._finish, self._error, name=name, protocol=self._selected_protocol(),
                fields=fields, options=opts, files=st_files)
        else:
            ch = {"name": name, "server": self.server.get_text().strip(), "port": port,
                  "username": self.user.get_text(), "dns": dns, "notes": self.notes.get_text(),
                  "options": dict(self.profile.get("options", {}), **opts)}
            if self.password.get_text():
                ch["password"] = self.password.get_text()
            pid = self.profile["id"]

            def apply_changes(*_):
                rpc("profiles.update", self._finish, self._error, ident=pid, changes=ch)
            if st_files:
                rpc("profiles.setfile", apply_changes, self._error, ident=pid, name="stunnel-ca.pem",
                    data=st_files["stunnel-ca.pem"])
            else:
                apply_changes()


# ------------------------------------------------------------------- window

class MainWindow(Adw.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app, title=APP_NAME, default_width=900, default_height=700)
        self.set_size_request(360, 480)
        self.status = None
        self.profiles = []
        self.protocols = []
        self.settings = {}
        self.latency = {}
        self.sel_id = None
        self._log_seq = 0
        self._quiet = False
        self._daemon_ok = True
        self._last_state = None
        self._rows = {}

        self.toasts = Adw.ToastOverlay()
        view = Adw.ToolbarView()
        self.set_content(view)

        # ---- header
        header = Adw.HeaderBar()
        self.switcher_title = Adw.ViewSwitcherTitle(title=APP_NAME)
        header.set_title_widget(self.switcher_title)
        add_menu = Gio.Menu()
        add_menu.append("Import from File…", "win.import")
        add_menu.append("Add Manually…", "win.add")
        add_btn = Gtk.MenuButton(icon_name="list-add-symbolic", menu_model=add_menu, tooltip_text="Add profile")
        header.pack_start(add_btn)
        main_menu = Gio.Menu()
        main_menu.append("Preferences", "app.preferences")
        main_menu.append("About VPNMan", "app.about")
        main_menu.append("Quit", "app.quit")
        header.pack_end(Gtk.MenuButton(icon_name="open-menu-symbolic", menu_model=main_menu,
                                       primary=True, tooltip_text="Main menu"))
        view.add_top_bar(header)
        self.banner = Adw.Banner(revealed=False, button_label="Start Service")
        self.banner.connect("button-clicked", self._start_service)
        view.add_top_bar(self.banner)

        # ---- pages
        self.stack = Adw.ViewStack(vexpand=True)
        self.stack.add_titled_with_icon(self._build_overview(), "overview", "Connection", "network-vpn-symbolic")
        self.stack.add_titled_with_icon(self._build_servers(), "servers", "Servers", "network-server-symbolic")
        self.stack.add_titled_with_icon(self._build_lock(), "lock", "Network Lock", "changes-prevent-symbolic")
        self.stack.add_titled_with_icon(self._build_log(), "log", "Log", "utilities-terminal-symbolic")
        self.switcher_title.set_stack(self.stack)
        bar = Adw.ViewSwitcherBar(stack=self.stack)
        self.switcher_title.bind_property("title-visible", bar, "reveal", GObject.BindingFlags.SYNC_CREATE)
        self.toasts.set_child(self.stack)
        view.set_content(self.toasts)
        view.add_bottom_bar(bar)

        for name, cb in (("import", self.on_import), ("add", self.on_add)):
            act = Gio.SimpleAction.new(name, None)
            act.connect("activate", cb)
            self.add_action(act)

        self.connect("close-request", self._on_close)
        self.refresh(full=True)
        GLib.timeout_add_seconds(1, self._tick)

    def _on_close(self, *_):
        """Hide to the tray instead of quitting - the VPN itself lives in the daemon either way."""
        if self.get_application().keep_in_tray():
            self.set_visible(False)
            return True
        return False

    def tray_menu(self):
        st = self.status or {}
        state = st.get("state", "disconnected")
        active = state in ACTIVE
        label = {"connected": "Connected to %s" % st.get("profile"), "connecting": "Connecting…",
                 "reconnecting": "Reconnecting…", "error": "Connection failed"}.get(state, "Not connected")
        locked = (st.get("netlock") or {}).get("engaged")
        return [
            {"label": label, "enabled": False},
            {"separator": True},
            {"label": "Disconnect" if active else "Connect", "enabled": self._daemon_ok,
             "callback": self.on_main_button},
            {"label": "Turn Network Lock %s" % ("Off" if locked else "On"), "enabled": self._daemon_ok,
             "callback": lambda: rpc("netlock.disable" if locked else "netlock.enable",
                                     lambda *_: self.refresh(), self._fail)},
            {"separator": True},
            {"label": "Show VPNMan", "callback": lambda: self.present()},
            {"label": "Quit", "callback": lambda: self.get_application().quit()},
        ]

    def _update_tray(self, st):
        app = self.get_application()
        tray = getattr(app, "tray", None)
        if not tray:
            return
        state = st["state"]
        key = (state, st["netlock"]["engaged"], st.get("profile"))
        tip = {"connected": "Connected to %s" % st.get("profile"), "disconnected": "Not connected",
               "connecting": "Connecting…", "reconnecting": "Reconnecting…",
               "error": "Connection failed"}.get(state, state)
        if st["netlock"]["engaged"]:
            tip += " · Network Lock on"
        tray.set_state("%s-%s-symbolic" % (APP_ID, TRAY_ICONS.get(state, "disconnected")), tip,
                       attention=(state == "error"))
        if key != getattr(self, "_tray_key", None):
            self._tray_key = key
            tray.update_menu()

    # ---- overview ----------------------------------------------------
    def _build_overview(self):
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24, margin_bottom=24)
        self.hero = Hero("network-vpn-disabled-symbolic", "Not Connected", "Choose a server and connect.")
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, halign=Gtk.Align.CENTER)
        self.server_row = Adw.ComboRow(title="Server", model=Gtk.StringList.new([]))
        self.server_row.connect("notify::selected", self._on_server_selected)
        # a ComboRow only reacts to clicks inside a GtkListBox (the list delivers the activation)
        pick = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        pick.add_css_class("boxed-list")
        pick.set_size_request(340, -1)
        pick.append(self.server_row)
        box.append(pick)
        self.main_btn = Gtk.Button(label="Connect", halign=Gtk.Align.CENTER)
        self.main_btn.add_css_class("pill")
        self.main_btn.add_css_class("suggested-action")
        self.main_btn.connect("clicked", self.on_main_button)
        box.append(self.main_btn)
        self.hero.set_child(box)
        page.append(self.hero)
        groups = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24)
        clamp = Adw.Clamp(maximum_size=600, margin_start=12, margin_end=12)
        clamp.set_child(groups)
        page.append(clamp)

        self.stats = Adw.PreferencesGroup(title="Connection Details")
        self.stat_rows = {}
        for key, title, icon in (("ip", "Public IP", "network-wired-symbolic"),
                                 ("iface", "Interface", "network-transmit-receive-symbolic"),
                                 ("uptime", "Duration", "preferences-system-time-symbolic"),
                                 ("down", "Downloaded", "go-down-symbolic"),
                                 ("up", "Uploaded", "go-up-symbolic")):
            row = Adw.ActionRow(title=title, subtitle="–", subtitle_selectable=True)
            row.add_prefix(Gtk.Image.new_from_icon_name(icon))
            row.add_css_class("property")
            self.stats.add(row)
            self.stat_rows[key] = row
        self.stats.set_visible(False)
        groups.append(self.stats)

        dns = Adw.PreferencesGroup(title="DNS", description="Name servers used while the VPN is active. "
                                   "Changes apply immediately, even when connected.")
        self.dns_labels = (["VPN provider's"] + [n for n, _ in DNS_PRESETS]
                           + ["Custom…", "Don't change DNS"])
        self.dns_row = Adw.ComboRow(title="DNS servers", model=Gtk.StringList.new(self.dns_labels))
        self.dns_row.add_prefix(Gtk.Image.new_from_icon_name("network-server-symbolic"))
        self.dns_row.connect("notify::selected", self._on_dns_choice)
        dns.add(self.dns_row)
        self.dns_custom = Adw.EntryRow(title="Custom DNS servers (comma separated)", show_apply_button=True,
                                       visible=False)
        self.dns_custom.connect("apply", lambda r: self._save_dns(True, self._parse_ips(r.get_text())))
        dns.add(self.dns_custom)
        groups.append(dns)

        start = Adw.PreferencesGroup(title="Startup", description="Handled by the background service, so it works "
                                     "right after boot, before anyone logs in. It waits for the network and keeps trying.")
        self.auto_switch = Adw.SwitchRow(title="Connect when the computer starts")
        self.auto_switch.add_prefix(Gtk.Image.new_from_icon_name("system-run-symbolic"))
        self.auto_switch.connect("notify::active", self._on_auto_toggle)
        self.auto_row = Adw.ComboRow(title="Connect to", model=Gtk.StringList.new(["Last used server"]))
        self.auto_row.connect("notify::selected", self._on_auto_target)
        self.auto_values = ["last"]
        start.add(self.auto_switch)
        start.add(self.auto_row)
        groups.append(start)

        quick = Adw.PreferencesGroup()
        self.lock_switch = Adw.SwitchRow(title="Network Lock", subtitle="Block all traffic outside the VPN (kill switch)")
        self.lock_switch.add_prefix(Gtk.Image.new_from_icon_name("changes-prevent-symbolic"))
        self.lock_switch.connect("notify::active", self._on_lock_toggled)
        quick.add(self.lock_switch)
        groups.append(quick)
        scroll = Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.NEVER, vexpand=True)
        scroll.set_child(page)
        return scroll

    # ---- startup (boot-time auto-connect) -----------------------------
    def _auto_value(self):
        i = self.auto_row.get_selected()
        return self.auto_values[i] if 0 <= i < len(self.auto_values) else "last"

    def _on_auto_toggle(self, row, _p):
        self.auto_row.set_sensitive(row.get_active())
        if not self._quiet:
            rpc("settings.set", lambda *_: self.toast("Saved"), self._fail, key="connection.autoconnect",
                value=self._auto_value() if row.get_active() else "off")

    def _on_auto_target(self, row, _p):
        if not self._quiet and self.auto_switch.get_active():
            rpc("settings.set", lambda *_: self.toast("Saved"), self._fail, key="connection.autoconnect",
                value=self._auto_value())

    def _sync_auto(self):
        if not self.settings:
            return
        cur = self.settings["connection"]["autoconnect"]
        self.auto_values = ["last", "fastest"] + [p["id"] for p in self.profiles]
        labels = ["Last used server", "Fastest server"] + [p["name"] for p in self.profiles]
        self._quiet = True
        self.auto_row.set_model(Gtk.StringList.new(labels))
        on = cur not in ("off", "")
        self.auto_switch.set_active(on)
        self.auto_row.set_sensitive(on)
        if on:
            for i, v in enumerate(self.auto_values):
                if v == cur or (i >= 2 and self.profiles[i - 2]["name"] == cur):
                    self.auto_row.set_selected(i)
        self._quiet = False

    @staticmethod
    def _parse_ips(text):
        return [x.strip() for x in text.replace(";", ",").replace(" ", ",").split(",") if x.strip()]

    def _save_dns(self, force, servers):
        rpc("settings.update", lambda *_: (self.toast("DNS updated"), self.refresh(full=True)), self._fail,
            tree={"dns": {"force": force, "servers": servers}})

    def _on_dns_choice(self, row, _p):
        i = row.get_selected()
        n = len(DNS_PRESETS)
        self.dns_custom.set_visible(i == n + 1)
        if self._quiet:
            return
        if i == 0:
            self._save_dns(True, [])
        elif 1 <= i <= n:
            self._save_dns(True, DNS_PRESETS[i - 1][1])
        elif i == n + 2:
            self._save_dns(False, [])
        elif self.dns_custom.get_text():
            self._save_dns(True, self._parse_ips(self.dns_custom.get_text()))

    def _sync_dns(self, dns):
        n = len(DNS_PRESETS)
        servers = dns.get("servers", [])
        if not dns.get("force", True):
            idx = n + 2
        elif not servers:
            idx = 0
        else:
            idx = n + 1
            for k, (_name, ips) in enumerate(DNS_PRESETS, 1):
                if ips == servers:
                    idx = k
        self.dns_row.set_selected(idx)
        self.dns_custom.set_visible(idx == n + 1)
        if idx == n + 1:
            self.dns_custom.set_text(", ".join(servers))

    # ---- servers -----------------------------------------------------
    def _build_servers(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.search = Gtk.SearchEntry(placeholder_text="Search servers")
        self.search.connect("search-changed", lambda *_: self.listbox.invalidate_filter())
        top = Gtk.Box(spacing=6)
        self.search.set_hexpand(True)
        top.append(self.search)
        self.ping_btn = Gtk.Button(label="Test Latency")
        self.ping_btn.connect("clicked", self.on_ping)
        top.append(self.ping_btn)
        self.listbox = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        self.listbox.add_css_class("boxed-list")
        self.listbox.set_filter_func(self._filter)
        self.listbox.set_sort_func(self._sort)
        inner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        inner.append(top)
        inner.append(self.listbox)
        clamp = Adw.Clamp(maximum_size=720, margin_top=12, margin_bottom=12, margin_start=12, margin_end=12,
                          valign=Gtk.Align.START)
        clamp.set_child(inner)
        scroll = Gtk.ScrolledWindow(vexpand=True, hscrollbar_policy=Gtk.PolicyType.NEVER)
        scroll.set_child(clamp)
        self.empty = Adw.StatusPage(icon_name="network-server-symbolic", title="No Profiles",
                                    description="Import an OpenVPN or WireGuard file, or add a server by hand.",
                                    vexpand=True)
        b = Gtk.Button(label="Import…", halign=Gtk.Align.CENTER)
        b.add_css_class("pill")
        b.add_css_class("suggested-action")
        b.connect("clicked", self.on_import)
        self.empty.set_child(b)
        self.srv_stack = Gtk.Stack()
        self.srv_stack.add_named(scroll, "list")
        self.srv_stack.add_named(self.empty, "empty")
        box.append(self.srv_stack)
        return box

    def _filter(self, row):
        q = self.search.get_text().lower()
        return not q or q in row.profile["name"].lower() or q in row.profile["protocol"] or \
            q in (row.profile.get("server") or "").lower()

    def _sort(self, a, b):
        ka = (not a.profile["favorite"], a.profile["name"].lower())
        kb = (not b.profile["favorite"], b.profile["name"].lower())
        return (ka > kb) - (ka < kb)

    def _make_row(self, p):
        row = Adw.ActionRow(title=GLib.markup_escape_text(p["name"]),
                            subtitle=GLib.markup_escape_text("%s%s" % (p["protocol"], "  ·  %s:%s" % (p["server"], p["port"]) if p["server"] else "")))
        row.profile = p
        row.set_activatable(False)
        if p["blacklisted"]:
            row.add_css_class("dim-label")
        lat = Gtk.Label(label="", css_classes=["dim-label", "numeric"])
        row.lat = lat
        row.add_suffix(lat)
        fav = Gtk.ToggleButton(icon_name="starred-symbolic" if p["favorite"] else "non-starred-symbolic",
                               active=p["favorite"], valign=Gtk.Align.CENTER, tooltip_text="Favourite")
        fav.add_css_class("flat")
        fav.connect("toggled", lambda b, p=p: rpc("profiles.update", lambda *_: self.refresh(full=True),
                                                   ident=p["id"], changes={"favorite": b.get_active()}))
        row.add_suffix(fav)
        menu = Gtk.MenuButton(icon_name="view-more-symbolic", valign=Gtk.Align.CENTER, tooltip_text="More")
        menu.add_css_class("flat")
        pop = Gtk.Popover()
        pb = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        for label, cb in (("Edit…", lambda *_: self._edit(p)),
                          ("Unblock" if p["blacklisted"] else "Blacklist", lambda *_: self._toggle_block(p)),
                          ("Remove…", lambda *_: self._remove(p))):
            b = Gtk.Button(label=label)
            b.add_css_class("flat")
            b.connect("clicked", lambda w, cb=cb: (pop.popdown(), cb()))
            pb.append(b)
        pop.set_child(pb)
        menu.set_popover(pop)
        row.add_suffix(menu)
        go = Gtk.Button(label="Connect", valign=Gtk.Align.CENTER)
        go.add_css_class("suggested-action")
        go.connect("clicked", lambda *_: self.connect_to(p["id"]))
        row.add_suffix(go)
        return row

    def _edit(self, p):
        ProfileDialog(self, "edit", self.protocols, profile=p, on_done=lambda: self.refresh(full=True)).present()

    def _toggle_block(self, p):
        rpc("profiles.update", lambda *_: self.refresh(full=True), ident=p["id"],
            changes={"blacklisted": not p["blacklisted"]})

    def _remove(self, p):
        d = Adw.MessageDialog(transient_for=self, heading="Remove %s?" % p["name"],
                              body="The profile and its stored credentials will be deleted.")
        d.add_response("cancel", "Cancel")
        d.add_response("remove", "Remove")
        d.set_response_appearance("remove", Adw.ResponseAppearance.DESTRUCTIVE)
        d.connect("response", lambda d, r: r == "remove" and rpc("profiles.remove", lambda *_: self.refresh(full=True), ident=p["id"]))
        d.present()

    # ---- network lock page -------------------------------------------
    def _build_lock(self):
        page = Adw.PreferencesPage()
        g = Adw.PreferencesGroup(title="Kill Switch",
                                 description="While engaged, only the VPN tunnel, its server and the exceptions below can "
                                             "send or receive traffic. If the VPN drops, nothing leaks.")
        self.lock_now = Adw.SwitchRow(title="Engage now")
        self.lock_now.connect("notify::active", self._on_lock_toggled)
        g.add(self.lock_now)
        page.add(g)
        self.lock_bindings = {}
        g = Adw.PreferencesGroup(title="Behaviour")
        for key, title, sub in (("netlock.enabled", "Lock when connecting", "Engage automatically before connecting and release on disconnect"),
                                ("netlock.persist", "Stay locked", "Keep the lock after disconnecting and across restarts/boots")):
            g.add(self._setting_switch(key, title, sub))
        page.add(g)
        g = Adw.PreferencesGroup(title="Allowed Outside the Tunnel")
        for key, title, sub in (("netlock.allow_lan", "Local network", "Private, link-local and multicast ranges"),
                                ("netlock.allow_dhcp", "DHCP", "Needed to renew your network lease"),
                                ("netlock.allow_ping", "Ping", "Answer and send ICMP echo requests"),
                                ("netlock.block_ipv6", "Block IPv6", "Drop all IPv6, even inside the tunnel (prevents v6 leaks)")):
            g.add(self._setting_switch(key, title, sub))
        page.add(g)
        g = Adw.PreferencesGroup(title="Whitelist", description="Comma-separated IPs or CIDR ranges")
        g.add(self._setting_entry("netlock.whitelist_out", "Reachable outside the VPN"))
        g.add(self._setting_entry("netlock.whitelist_in", "Allowed to reach this computer"))
        page.add(g)
        return page

    def _setting_switch(self, key, title, subtitle=""):
        row = Adw.SwitchRow(title=title, subtitle=subtitle)
        row.key = key
        row.connect("notify::active", self._on_setting_switch)
        self.lock_bindings[key] = row
        return row

    def _setting_entry(self, key, title):
        row = Adw.EntryRow(title=title, show_apply_button=True)
        row.key = key
        row.connect("apply", lambda r: rpc("settings.set", lambda *_: self.toast("Saved"), self._fail,
                                           key=r.key, value=r.get_text()))
        self.lock_bindings[key] = row
        return row

    def _on_setting_switch(self, row, _p):
        if not self._quiet:
            rpc("settings.set", None, self._fail, key=row.key, value=row.get_active())

    # ---- log ---------------------------------------------------------
    def _build_log(self):
        self.logbuf = Gtk.TextBuffer()
        tags = {"error": "#e01b24", "warn": "#e5a50a", "info": "#26a269", "tool": None, "debug": "#9a9996"}
        for k, col in tags.items():
            if col:
                self.logbuf.create_tag(k, foreground=col)
        self.logbuf.create_tag("time", foreground="#9a9996")
        view = Gtk.TextView(buffer=self.logbuf, editable=False, cursor_visible=False, monospace=True,
                            wrap_mode=Gtk.WrapMode.WORD_CHAR, left_margin=12, right_margin=12, top_margin=8, bottom_margin=8)
        self.logview = view
        scroll = Gtk.ScrolledWindow(vexpand=True)
        scroll.set_child(view)
        self.log_scroll = scroll
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        bar = Gtk.Box(spacing=6, margin_top=6, margin_bottom=6, margin_start=12, margin_end=12)
        clear = Gtk.Button(label="Clear")
        clear.connect("clicked", lambda *_: self.logbuf.set_text(""))
        bar.append(clear)
        box.append(bar)
        box.append(scroll)
        return box

    def _append_log(self, entries):
        for e in entries:
            end = self.logbuf.get_end_iter()
            self.logbuf.insert_with_tags_by_name(end, time.strftime("%H:%M:%S ", time.localtime(e["time"])), "time")
            end = self.logbuf.get_end_iter()
            if e["level"] in ("error", "warn", "info", "debug"):
                self.logbuf.insert_with_tags_by_name(end, e["msg"] + "\n", e["level"])
            else:
                self.logbuf.insert(end, e["msg"] + "\n")
        if entries:
            adj = self.log_scroll.get_vadjustment()
            GLib.idle_add(lambda: adj.set_value(adj.get_upper() - adj.get_page_size()))

    # ---- actions -----------------------------------------------------
    def toast(self, text):
        self.toasts.add_toast(Adw.Toast(title=text, timeout=3))

    def _fail(self, msg, daemon_down=False):
        if daemon_down:
            self._set_daemon(False, msg)
        else:
            self.toast(msg)

    def _set_daemon(self, ok, msg=""):
        self._daemon_ok = ok
        self.banner.set_title("The VPNMan background service is not running" if not ok else "")
        self.banner.set_revealed(not ok)
        for w in (self.main_btn, self.lock_switch, self.lock_now):
            w.set_sensitive(ok)

    def _start_service(self, *_):
        """Enable + start vpnmand, asking for the admin password through polkit."""
        import shutil
        import subprocess
        exe = shutil.which("vpnman") or "/usr/bin/vpnman"
        cmd = [exe, "service", "enable"]
        if os.geteuid() != 0:
            if not shutil.which("pkexec"):
                return self.toast("Run:  sudo vpnman service enable")
            cmd = ["pkexec"] + cmd
        self.banner.set_button_label("Starting…")

        def work():
            try:
                rc = subprocess.run(cmd, capture_output=True, text=True, timeout=120).returncode
            except (OSError, subprocess.SubprocessError):
                rc = 1
            GLib.timeout_add_seconds(2, lambda: (self.banner.set_button_label("Start Service"),
                                                 self.refresh(full=True), False)[2])
            if rc:
                GLib.idle_add(self.toast, "Could not start the service (cancelled or failed)")
        threading.Thread(target=work, daemon=True).start()

    def on_import(self, *_):
        ProfileDialog(self, "import", self.protocols, on_done=lambda: self.refresh(full=True)).present()

    def on_add(self, *_):
        ProfileDialog(self, "add", self.protocols, on_done=lambda: self.refresh(full=True)).present()

    def on_ping(self, *_):
        self.ping_btn.set_sensitive(False)
        self.ping_btn.set_label("Testing…")

        def done(res):
            self.latency = res
            self.ping_btn.set_sensitive(True)
            self.ping_btn.set_label("Test Latency")
            self._update_latency()
        rpc("latency", done, self._fail)

    def _update_latency(self):
        for pid, row in self._rows.items():
            ms = self.latency.get(pid)
            row.lat.set_label("%.0f ms" % ms if ms else ("timeout" if pid in self.latency else ""))

    def connect_to(self, pid):
        self.sel_id = pid
        self.stack.set_visible_child_name("overview")
        rpc("connect", lambda *_: self.refresh(), self._fail, ident=pid)

    def on_main_button(self, *_):
        st = self.status or {}
        if st.get("state") in ACTIVE:
            rpc("disconnect", lambda *_: self.refresh(), self._fail)
        elif not self.profiles:
            self.stack.set_visible_child_name("servers")
            self.toast("Import a profile first")
        else:
            self.connect_to(self.sel_id or self.profiles[0]["id"])

    def _on_server_selected(self, row, _p):
        i = row.get_selected()
        if not self._quiet and 0 <= i < len(self.profiles):
            self.sel_id = self.profiles[i]["id"]

    def _on_lock_toggled(self, row, _p):
        if self._quiet:
            return
        rpc("netlock.enable" if row.get_active() else "netlock.disable", lambda *_: self.refresh(), self._fail)

    # ---- data refresh --------------------------------------------------
    def _tick(self):
        self.refresh()
        return True

    def refresh(self, full=False):
        rpc("status", self._on_status, self._fail)
        rpc("logs", self._on_logs, None, since=self._log_seq)
        if full:
            rpc("profiles.list", self._on_profiles, None)
            rpc("settings.get", self._on_settings, None)
            if not self.protocols:
                rpc("protocols", lambda r: setattr(self, "protocols", r), None)

    def _on_logs(self, res):
        self._log_seq = res["last"]
        self._append_log(res["entries"])

    def _on_profiles(self, profiles):
        self.profiles = profiles
        self._quiet = True
        names = [p["name"] for p in profiles]
        self.server_row.set_model(Gtk.StringList.new(names))
        ids = [p["id"] for p in profiles]
        if self.sel_id not in ids:
            self.sel_id = ids[0] if ids else None
        if self.sel_id:
            self.server_row.set_selected(ids.index(self.sel_id))
        self._quiet = False
        child = self.listbox.get_first_child()
        while child:
            nxt = child.get_next_sibling()
            self.listbox.remove(child)
            child = nxt
        self._rows = {}
        for p in profiles:
            row = self._make_row(p)
            self._rows[p["id"]] = row
            self.listbox.append(row)
        self._update_latency()
        self.srv_stack.set_visible_child_name("list" if profiles else "empty")
        self._sync_auto()

    def _on_settings(self, settings):
        self.settings = settings
        self._quiet = True
        self._sync_dns(settings["dns"])
        self._sync_auto()
        for key, row in self.lock_bindings.items():
            sec, name = key.split(".")
            val = settings[sec][name]
            if isinstance(row, Adw.SwitchRow):
                row.set_active(bool(val))
            else:
                row.set_text(", ".join(val))
        self._quiet = False

    def _on_status(self, st):
        self._set_daemon(True)
        old = self.status
        self.status = st
        state = st["state"]
        active = state in ACTIVE
        self._quiet = True
        self.lock_switch.set_active(st["netlock"]["engaged"])
        self.lock_now.set_active(st["netlock"]["engaged"])
        self._quiet = False
        self.server_row.set_sensitive(not active)
        pid = st.get("profile_id")
        if active and pid and pid != self.sel_id:
            self.sel_id = pid             # opened mid-connection: show the server actually in use
            ids = [p["id"] for p in self.profiles]
            if pid in ids:
                self._quiet = True
                self.server_row.set_selected(ids.index(pid))
                self._quiet = False
        if state == "connected":
            self.hero.set_icon_name("network-vpn-symbolic")
            self.hero.set_title("Connected")
            self.hero.set_description("%s · %s" % (st["profile"], st["protocol"]))
        elif state in ("connecting", "reconnecting"):
            self.hero.set_icon_name("network-vpn-acquiring-symbolic")
            self.hero.set_title("Connecting…" if state == "connecting" else "Reconnecting…")
            self.hero.set_description(st.get("message") or st["profile"] or "")
        elif state == "error":
            self.hero.set_icon_name("network-vpn-error-symbolic")
            self.hero.set_title("Connection Failed")
            self.hero.set_description(st.get("message") or "")
        else:
            self.hero.set_icon_name("network-vpn-disabled-symbolic")
            self.hero.set_title("Not Connected")
            self.hero.set_description("Your traffic is not protected." if not st["netlock"]["engaged"]
                                      else "Network lock is engaged - traffic is blocked.")
        self.main_btn.set_label("Disconnect" if active else "Connect")
        for cls, on in (("suggested-action", not active), ("destructive-action", active)):
            (self.main_btn.add_css_class if on else self.main_btn.remove_css_class)(cls)
        self.stats.set_visible(state == "connected")
        if state == "connected":
            r = self.stat_rows
            r["ip"].set_subtitle(st.get("public_ip") or "checking…")
            r["iface"].set_subtitle(st.get("iface") or "–")
            r["uptime"].set_subtitle(hms(st.get("uptime", 0)))
            r["down"].set_subtitle("%s  (%s/s)" % (human(st["rx"]), human(st["rx_rate"])))
            r["up"].set_subtitle("%s  (%s/s)" % (human(st["tx"]), human(st["tx_rate"])))
        self._update_tray(st)
        if state != self._last_state:
            if self._last_state is not None:
                self._notify(state, st)
            self._last_state = state

    def _notify(self, state, st):
        if not self.settings.get("ui", {}).get("notifications", True):
            return
        msg = {"connected": "Connected to %s" % st.get("profile"), "disconnected": "Disconnected",
               "error": "Connection failed: %s" % st.get("message"),
               "reconnecting": "Connection lost - reconnecting"}.get(state)
        if msg and not self.is_active():
            n = Gio.Notification.new(APP_NAME)
            n.set_body(msg)
            self.get_application().send_notification("state", n)


# ------------------------------------------------------------- preferences

class PreferencesWindow(Adw.PreferencesWindow):
    def __init__(self, parent, settings):
        super().__init__(transient_for=parent, modal=True, search_enabled=False)
        self.s = settings
        self.set_title("Preferences")

        page = Adw.PreferencesPage(title="Connection", icon_name="network-vpn-symbolic")
        g = Adw.PreferencesGroup(title="Reliability")
        g.add(self._switch("connection.reconnect", "Reconnect automatically"))
        g.add(self._spin("connection.retry_max", "Retries before giving up", 0, 20))
        g.add(self._spin("connection.retry_delay", "Seconds between retries", 1, 120))
        g.add(self._switch("connection.failover", "Fail over to next favourite"))
        g.add(self._spin("connection.timeout", "Connection timeout (s)", 10, 300))
        page.add(g)
        g = Adw.PreferencesGroup(title="OpenVPN")
        g.add(self._entry("connection.openvpn_args", "Extra arguments", "comma separated"))
        page.add(g)
        self.add(page)

        page = Adw.PreferencesPage(title="DNS & Routes", icon_name="network-wired-symbolic")
        g = Adw.PreferencesGroup(title="DNS")
        g.add(self._switch("dns.force", "Change DNS while connected", "Prevents DNS leaks; pick servers on the Connection page"))
        g.add(self._entry("dns.servers", "Custom DNS servers", "comma separated, overrides pushed servers"))
        page.add(g)
        g = Adw.PreferencesGroup(title="Checks")
        g.add(self._switch("checks.tunnel", "Look up public IP after connecting"))
        g.add(self._entry("checks.url", "Lookup URL"))
        page.add(g)
        g = Adw.PreferencesGroup(title="Routes", description="Networks that bypass the VPN (IPv4, comma separated)")
        row = Adw.EntryRow(title="Bypass networks", show_apply_button=True)
        row.set_text(", ".join(r["ip"] for r in settings["routes"] if r.get("action") == "out"))
        row.connect("apply", lambda r: self._set("routes", [{"ip": x.strip(), "action": "out"}
                                                           for x in r.get_text().split(",") if x.strip()]))
        g.add(row)
        page.add(g)
        self.add(page)

        page = Adw.PreferencesPage(title="Tray & Login", icon_name="preferences-desktop-symbolic")
        app = parent.get_application()
        tray_ok = bool(app.tray and app.tray.available)
        g = Adw.PreferencesGroup(title="System Tray")
        row = Adw.ActionRow(title="Tray icon", subtitle="Available" if tray_ok else
                            "Not available on this desktop")
        row.add_prefix(Gtk.Image.new_from_icon_name("emblem-ok-symbolic" if tray_ok else "dialog-warning-symbolic"))
        g.add(row)
        bg = Adw.SwitchRow(title="Keep running in the tray when the window is closed",
                           subtitle="The VPN stays connected either way - it is handled by the background service",
                           active=app.userconfig.get("run_in_background"), sensitive=tray_ok)
        bg.connect("notify::active", lambda r, _p: (app.userconfig.set("run_in_background", r.get_active()),
                                                    app.set_background_hold(app.keep_in_tray())))
        g.add(bg)
        if not tray_ok:
            g.set_description("GNOME has no tray by default. Install and enable the 'AppIndicator and "
                              "KStatusNotifierItem Support' extension (Ubuntu ships it; Fedora: "
                              "gnome-shell-extension-appindicator; Arch: gnome-shell-extension-appindicator). "
                              "KDE, XFCE, Cinnamon, MATE, LXQt and Budgie work out of the box. Without a tray, closing "
                              "the window simply closes the app.")
        page.add(g)
        g = Adw.PreferencesGroup(title="Login")
        login = Adw.SwitchRow(title="Start VPNMan when I log in",
                              subtitle="Starts in the tray (or as a window if there is no tray)",
                              active=autostart.is_enabled())
        login.connect("notify::active", lambda r, _p: autostart.enable() if r.get_active() else autostart.disable())
        g.add(login)
        page.add(g)
        self.add(page)

        page = Adw.PreferencesPage(title="Events", icon_name="system-run-symbolic")
        g = Adw.PreferencesGroup(title="Hooks", description="Shell commands run as root. Environment: VPNMAN_EVENT, "
                                 "VPNMAN_PROFILE, VPNMAN_PROTOCOL, VPNMAN_IFACE")
        for k, t in (("pre_connect", "Before connecting"), ("connected", "After connecting"),
                     ("disconnected", "After disconnecting")):
            g.add(self._entry("events." + k, t))
        page.add(g)
        g = Adw.PreferencesGroup(title="Interface")
        g.add(self._switch("ui.notifications", "Desktop notifications"))
        page.add(g)
        self.add(page)

    def _val(self, key):
        node = self.s
        for p in key.split("."):
            node = node[p]
        return node

    def _set(self, key, value):
        rpc("settings.set", None, lambda m, *_: self.add_toast(Adw.Toast(title=m)), key=key, value=value)

    def _switch(self, key, title, sub=""):
        row = Adw.SwitchRow(title=title, subtitle=sub, active=bool(self._val(key)))
        row.connect("notify::active", lambda r, _p: self._set(key, r.get_active()))
        return row

    def _spin(self, key, title, lo, hi):
        row = Adw.SpinRow.new_with_range(lo, hi, 1)
        row.set_title(title)
        row.set_value(self._val(key))
        row.connect("notify::value", lambda r, _p: self._set(key, int(r.get_value())))
        return row

    def _entry(self, key, title, sub=""):
        v = self._val(key)
        row = Adw.EntryRow(title=title + (" - " + sub if sub else ""), show_apply_button=True)
        row.set_text(", ".join(v) if isinstance(v, list) else str(v))
        row.connect("apply", lambda r: self._set(key, r.get_text()))
        return row


# ----------------------------------------------------------------------- app

class Application(Adw.Application):
    def __init__(self):
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.DEFAULT_FLAGS)
        self.win = None
        self.tray = None
        self.background = False
        self.userconfig = UserConfig()
        self._held = False
        self._bg_pending = False
        self.add_main_option("background", 0, GLib.OptionFlags.NONE, GLib.OptionArg.NONE,
                             "Start minimised to the system tray", None)

    def do_handle_local_options(self, options):
        if options.contains("background"):
            self.background = True
        return -1

    def do_startup(self):
        Adw.Application.do_startup(self)
        ensure_icons()
        for name, cb, accel in (("preferences", self.on_prefs, "<primary>comma"), ("about", self.on_about, None),
                                ("quit", lambda *_: self.quit(), "<primary>q")):
            act = Gio.SimpleAction.new(name, None)
            act.connect("activate", cb)
            self.add_action(act)
            if accel:
                self.set_accels_for_action("app." + name, [accel])

    def do_activate(self):
        if self.win is None:
            self.win = MainWindow(self)
            self._setup_tray()
            if self.background:
                # start hidden if a tray host shows up; otherwise the user would have no way back in
                self._bg_pending = True
                self.hold()
                GLib.timeout_add_seconds(5, self._background_timeout)
                return
        self.win.present()

    # ---- tray ----------------------------------------------------------
    def _setup_tray(self):
        # IconThemePath lets the tray host find our icons even when the system icon cache is stale
        self.tray = Tray(APP_ID, APP_NAME, lambda: self.win.present(), self.win.tray_menu,
                         self._on_tray_availability, private_icon_dir())
        self.tray.set_state("%s-disconnected-symbolic" % APP_ID, "VPNMan")
        self.tray.start()

    def keep_in_tray(self):
        return bool(self.tray and self.tray.available and self.userconfig.get("run_in_background"))

    def set_background_hold(self, on):
        if on and not self._held:
            self.hold()
            self._held = True
        elif not on and self._held:
            self.release()
            self._held = False

    def _on_tray_availability(self, available):
        self.set_background_hold(self.keep_in_tray())
        if self._bg_pending and available:
            self._bg_pending = False
            self.release()                    # the persistent hold above takes over
        elif not available and self.win and not self.win.get_visible():
            self.win.present()                # tray vanished (e.g. GNOME extension disabled)

    def _background_timeout(self):
        if self._bg_pending:
            self._bg_pending = False
            self.release()
            if not (self.tray and self.tray.available):
                self.win.present()
        return False

    def on_prefs(self, *_):
        def show(settings):
            self.win.settings = settings
            PreferencesWindow(self.win, settings).present()

        def fail(msg, down=False):
            self.win.toast("Preferences need the background service: " + msg if down else msg)
            self.win._set_daemon(False, msg) if down else None
        rpc("settings.get", show, fail)

    def on_about(self, *_):
        kw = dict(application_name=APP_NAME, application_icon=APP_ID, version=__version__,
                  developer_name="VPNMan contributors", license_type=Gtk.License.MIT_X11,
                  website="https://github.com/Smiley-McSmiles/VPNMan", comments="Multi-protocol VPN manager with a kill switch.")
        if hasattr(Adw, "AboutDialog"):
            Adw.AboutDialog(**kw).present(self.win)
        else:
            Adw.AboutWindow(transient_for=self.win, **kw).present()


def run(argv=None):
    return Application().run(argv if argv is not None else sys.argv)


if __name__ == "__main__":
    sys.exit(run())
